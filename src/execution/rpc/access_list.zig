//! `eth_createAccessList(call, block?, stateOverrides?)` as reth serves it
//! (`create_access_list_with`, revm-inspectors 0.44 `AccessListInspector`):
//!
//!   1. The call runs as eth_call would (its own `accessList` charged and pre-warmed) under
//!      an `Inspector` seeded with that list. When the top frame starts, the inspector
//!      excludes the sender, the recipient (or the created address) and the active
//!      precompiles and native contracts, and drops seeded entries of those. Before each
//!      instruction it lists SLOAD/SSTORE slots under the executing account (excluded or
//!      not), the address operand of BALANCE, EXTCODESIZE, EXTCODECOPY, EXTCODEHASH and
//!      SELFDESTRUCT, and the callee of CALL, CALLCODE, DELEGATECALL and STATICCALL unless
//!      excluded. Reverted frames count. The list is sorted by address, then slot.
//!   2. A failed first run returns that list with its gas and error. Otherwise the call
//!      runs again with the list as its access list, for the gas used and error.
//!
//! The coinbase is not excluded. EIP-7702 authorities are not either: call requests carry
//! no authorization list here. Buffers are carved from the API scratch after the call
//! data, the request's access list and the override space (and before a historical
//! call's proof tail).

const std = @import("std");
const assert = std.debug.assert;
const rpc = @import("../../utilities/rpc/root.zig");
const json = @import("../../utilities/json/root.zig");
const evm = @import("../evm/root.zig");
const node = @import("../node/root.zig");
const eth = @import("eth.zig");
const call_error = @import("call_error.zig");

const Api = eth.Api;
const Call = rpc.Call;
const HandlerError = rpc.HandlerError;
const Item = evm.transaction.AccessListItem;
const Key = evm.primitives.B256;
const Address = [20]u8;
const op = evm.opcode;

pub const methods = [_]rpc.Method(*Api){
    .{ .name = "eth_createAccessList", .handler = create_access_list },
};

/// Upper bound on entries (accounts plus slots) of one list.
pub const entries_max = 4096;
/// Fewer entries than this is not a useful list: the scratch is misconfigured.
const entries_min = 64;

/// One account (`slot` null) or one of its storage slots. Sorted by address, the account
/// first, then its slots ascending: alloy's `AccessList::sort` order.
pub const Entry = struct {
    address: Address,
    slot: ?u256,

    fn order(a: Entry, b: Entry) std.math.Order {
        const by_address = std.mem.order(u8, &a.address, &b.address);
        if (by_address != .eq) return by_address;
        const a_slot = a.slot orelse return if (b.slot == null) .eq else .lt;
        const b_slot = b.slot orelse return .gt;
        return std.math.order(a_slot, b_slot);
    }
};

/// revm-inspectors' `AccessListInspector` over the evm's step hooks: a sorted set of
/// entries, where every listed slot has its account entry.
pub const Inspector = struct {
    entries: []Entry,
    len: u32 = 0,
    /// More entries than `entries` holds; the list is incomplete.
    overflow: bool = false,
    machine: *const evm.evm.Evm,
    /// Set when the top frame starts.
    excluded: ?Excluded = null,

    const Excluded = struct {
        from: Address,
        /// The callee, or the address a creation deploys to.
        to: Address,
        /// The precompiles and native contracts (the coinbase cleared).
        warm: evm.state.StaticWarm,

        fn contains(excluded: *const Excluded, address: Address) bool {
            if (std.mem.eql(u8, &address, &excluded.from)) return true;
            if (std.mem.eql(u8, &address, &excluded.to)) return true;
            return excluded.warm.contains(address);
        }
    };

    pub fn slice(inspector: *const Inspector) []const Entry {
        return inspector.entries[0..inspector.len];
    }

    /// Lists the request's own access list (revm-inspectors `AccessListInspector::new`).
    pub fn seed(inspector: *Inspector, list: []const Item) void {
        for (list) |item| {
            inspector.insert(.{ .address = item.address, .slot = null });
            for (item.storage_keys) |key| {
                const slot = evm.primitives.b256_to_u256(key);
                inspector.insert(.{ .address = item.address, .slot = slot });
            }
        }
    }

    pub fn tracer(inspector: *Inspector) evm.evm.Tracer {
        return .{
            .context = inspector,
            .enter = on_enter,
            .exit = on_exit,
            .log = on_log,
            .step = on_step,
            .step_end = on_step_end,
        };
    }

    fn of(context: *anyopaque) *Inspector {
        return @ptrCast(@alignCast(context));
    }

    /// Where the entry is, or where it would be inserted.
    fn search(inspector: *const Inspector, entry: Entry) struct { index: u32, found: bool } {
        var low: u32 = 0;
        var high: u32 = inspector.len;
        while (low < high) {
            const middle = low + (high - low) / 2;
            switch (Entry.order(inspector.entries[middle], entry)) {
                .lt => low = middle + 1,
                .gt => high = middle,
                .eq => return .{ .index = middle, .found = true },
            }
        }
        return .{ .index = low, .found = false };
    }

    /// Adds `entry` (and its account entry, for a slot) unless listed.
    fn insert(inspector: *Inspector, entry: Entry) void {
        if (entry.slot != null) inspector.insert_one(.{ .address = entry.address, .slot = null });
        inspector.insert_one(entry);
        assert(inspector.overflow or inspector.search(entry).found);
    }

    fn insert_one(inspector: *Inspector, entry: Entry) void {
        const place = inspector.search(entry);
        if (place.found) return;
        if (inspector.len == inspector.entries.len) {
            inspector.overflow = true;
            return;
        }
        const tail = inspector.entries[place.index .. inspector.len + 1];
        std.mem.copyBackwards(Entry, tail[1..], tail[0 .. tail.len - 1]);
        tail[0] = entry;
        inspector.len += 1;
    }

    fn insert_unless_excluded(inspector: *Inspector, word: u256) void {
        const bytes = evm.primitives.u256_to_b256(word);
        const address: Address = bytes[12..32].*;
        const excluded = &inspector.excluded.?; // Set when the top frame started.
        if (excluded.contains(address)) return;
        inspector.insert(.{ .address = address, .slot = null });
    }

    /// revm-inspectors `collect_excluded_addresses`: at the top frame, before it runs.
    fn on_enter(context: *anyopaque, frame: evm.evm.TraceFrame) void {
        const inspector = of(context);
        if (frame.depth != 0) return;
        assert(inspector.excluded == null);
        var warm = inspector.machine.state.static_warm;
        warm.coinbase = null;
        inspector.excluded = .{ .from = frame.from, .to = frame.to, .warm = warm };
        const excluded = &inspector.excluded.?;
        var kept: u32 = 0;
        for (inspector.entries[0..inspector.len]) |entry| {
            if (excluded.contains(entry.address)) continue;
            inspector.entries[kept] = entry;
            kept += 1;
        }
        inspector.len = kept;
    }

    fn on_exit(_: *anyopaque, _: evm.evm.Outcome) void {}

    fn on_log(_: *anyopaque, _: Address, _: []const [32]u8, _: []const u8) void {}

    fn on_step(context: *anyopaque, frame: *const evm.evm.Frame, _: *const evm.evm.Evm) void {
        const inspector = of(context);
        const stack = frame.stack.items[0..frame.stack.len];
        switch (frame.analyzed.code[frame.pc]) {
            op.SLOAD, op.SSTORE => if (stack.len >= 1) inspector.insert(.{
                .address = frame.address,
                .slot = stack[stack.len - 1],
            }),
            op.EXTCODECOPY,
            op.EXTCODEHASH,
            op.EXTCODESIZE,
            op.BALANCE,
            op.SELFDESTRUCT,
            => if (stack.len >= 1) inspector.insert_unless_excluded(stack[stack.len - 1]),
            op.CALL,
            op.CALLCODE,
            op.DELEGATECALL,
            op.STATICCALL,
            => if (stack.len >= 2) inspector.insert_unless_excluded(stack[stack.len - 2]),
            else => {},
        }
    }

    fn on_step_end(
        _: *anyopaque,
        _: *const evm.evm.Frame,
        _: *const evm.evm.Evm,
        _: evm.evm.StepEnd,
    ) void {}
};

const Buffers = struct {
    entries: []Entry,
    items: []Item,
    keys: []Key,
};

const Executed = @FieldType(node.executor.Executor.Simulated, "executed");

fn create_access_list(api: *Api, call: *Call) HandlerError!void {
    try eth.refuse_deposit(call);
    var request = try eth.parse_call_request(api, call);
    // reth's third parameter: state overrides (no block overrides).
    const state_overrides = try call.params.optional_raw();
    try call.params.finish();
    try eth.set_overrides(api, call, &request, state_overrides, null);
    const buffers = carve_buffers(api, request) orelse
        return call.fail(rpc.code.internal_error, "scratch too small");
    const executor = api.chain.executor;
    var inspector: Inspector = .{ .entries = buffers.entries, .machine = executor.machine };
    inspector.seed(request.message.access_list);
    const tracer = inspector.tracer();
    executor.machine.tracer = &tracer;
    const inspected = eth.simulate(api, call, request);
    executor.machine.tracer = null;
    const first = switch (try inspected) {
        .invalid => |reason| return eth.fail_invalid(call, reason),
        .executed => |executed| executed,
    };
    if (inspector.overflow) return call.fail(rpc.code.server_error, "access list too large");
    const list = inspector.slice();
    // The item and key buffers are free until the second run: the error text goes there.
    const text_buffer = std.mem.sliceAsBytes(buffers.keys);
    if (!first.success) {
        return write_result(call.writer, list, first.gas_used, failure_text(text_buffer, first));
    }
    request.message.access_list = to_items(list, buffers.items, buffers.keys) catch
        unreachable; // Proof: items and keys hold as many as the entry buffer.
    const second = switch (try eth.simulate(api, call, request)) {
        .invalid => |reason| return eth.fail_invalid(call, reason),
        .executed => |executed| executed,
    };
    // The second run is done with the items and keys.
    const failure = if (second.success) null else failure_text(text_buffer, second);
    try write_result(call.writer, list, second.gas_used, failure);
}

/// reth's error text for a reverted or halted call (`ensure_success`).
fn failure_text(buffer: []u8, executed: Executed) []const u8 {
    assert(!executed.success);
    if (executed.exit.status() == .revert) {
        return call_error.revert_message(buffer, executed.output);
    }
    return call_error.halt(buffer, executed.exit, executed.gas_used).message;
}

/// The list buffers, after the parsed call data, access list and override space and
/// before a historical call's proofs.
fn carve_buffers(api: *Api, request: eth.CallRequest) ?Buffers {
    const scratch = api.scratch;
    const start = eth.scratch_used(api, &request);
    const end = switch (request.view) {
        .head => scratch.len,
        .historical => eth.proof_tail_offset(api).?, // Checked when parsed.
    };
    // Room for the alignment of each of the three arrays.
    const slack = 3 * 16;
    if (start + slack >= end) return null;
    const per_entry = @sizeOf(Entry) + @sizeOf(Item) + @sizeOf(Key);
    const count = @min(entries_max, (end - start - slack) / per_entry);
    if (count < entries_min) return null;
    var offset = start;
    const entries = carve(Entry, scratch[0..end], &offset, count) orelse return null;
    const items = carve(Item, scratch[0..end], &offset, count) orelse return null;
    const keys = carve(Key, scratch[0..end], &offset, count) orelse return null;
    assert(offset <= end);
    return .{ .entries = entries, .items = items, .keys = keys };
}

fn carve(comptime T: type, scratch: []u8, offset: *usize, count: usize) ?[]T {
    const base = @intFromPtr(scratch.ptr);
    const start = std.mem.alignForward(usize, base + offset.*, @alignOf(T)) - base;
    const end = start + count * @sizeOf(T);
    if (end > scratch.len) return null;
    offset.* = end;
    const typed: [*]T = @ptrCast(@alignCast(scratch[start..end].ptr));
    return typed[0..count];
}

/// Converts sorted, deduplicated `entries` into evm access list items; `items` and
/// `keys` must hold one per account and slot entry. Returns the items used.
pub fn to_items(
    entries: []const Entry,
    items: []Item,
    keys: []Key,
) error{AccessListFull}![]const Item {
    var item_count: usize = 0;
    var key_count: usize = 0;
    for (entries) |entry| {
        if (entry.slot) |slot| {
            assert(item_count > 0); // The account entry sorts first.
            if (key_count == keys.len) return error.AccessListFull;
            keys[key_count] = evm.primitives.u256_to_b256(slot);
            key_count += 1;
            const item = &items[item_count - 1];
            assert(std.mem.eql(u8, &item.address, &entry.address));
            item.storage_keys = keys[key_count - 1 - item.storage_keys.len .. key_count];
        } else {
            if (item_count == items.len) return error.AccessListFull;
            items[item_count] = .{ .address = entry.address, .storage_keys = &.{} };
            item_count += 1;
        }
    }
    return items[0..item_count];
}

fn write_result(
    w: *json.Writer,
    entries: []const Entry,
    gas_used: u64,
    failure: ?[]const u8,
) HandlerError!void {
    try w.begin_object();
    try w.key("accessList");
    try w.begin_array();
    var open = false;
    for (entries) |entry| {
        if (entry.slot) |slot| {
            assert(open);
            try w.data(&evm.primitives.u256_to_b256(slot));
            continue;
        }
        if (open) {
            try w.end_array();
            try w.end_object();
        }
        try w.begin_object();
        try w.key("address");
        try w.data(&entry.address);
        try w.key("storageKeys");
        try w.begin_array();
        open = true;
    }
    if (open) {
        try w.end_array();
        try w.end_object();
    }
    try w.end_array();
    try w.key("gasUsed");
    try w.quantity(gas_used);
    if (failure) |text| {
        try w.key("error");
        try w.string(text);
    }
    try w.end_object();
}

const testing = std.testing;
const Prng = @import("../../testing/prng.zig").Prng;

fn check_inspector(seed: u64) !void {
    var prng = Prng.init(seed);
    var buffer: [64]Entry = undefined;
    var inspector: Inspector = .{ .entries = &buffer, .machine = undefined };
    for (0..prng.range(0, 24)) |_| {
        var address: Address = @splat(0);
        address[19] = @intCast(prng.below(4));
        const slot: ?u256 = if (prng.chance(1, 2)) prng.below(4) else null;
        inspector.insert(.{ .address = address, .slot = slot });
    }
    try testing.expect(!inspector.overflow);
    const entries = inspector.slice();
    for (entries, 0..) |entry, index| {
        if (index > 0) try testing.expect(Entry.order(entries[index - 1], entry) == .lt);
        const account: Entry = .{ .address = entry.address, .slot = null };
        try testing.expect(inspector.search(account).found);
    }
    var items: [64]Item = undefined;
    var keys: [64]Key = undefined;
    const list = try to_items(entries, &items, &keys);
    var total: usize = 0;
    for (list) |item| total += 1 + item.storage_keys.len;
    try testing.expectEqual(entries.len, total);
}

test "access_list: seeded fuzz of the inspector's sorted set" {
    for (0..128) |seed| try check_inspector(seed + 0xacc);
}

fn fuzz_inspector(_: void, smith: *testing.Smith) anyerror!void {
    try check_inspector(smith.value(u64));
}

test "access_list: fuzz" {
    try testing.fuzz({}, fuzz_inspector, .{});
}
