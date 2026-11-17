//! `eth_createAccessList(call, block?, stateOverrides?)` (geth): runs the call, collects
//! the accounts and slots it warms beyond the pre-warmed set (`node.access_list`), and
//! repeats with that list until it stops changing (at most `rounds_max` runs; geth has no
//! bound). Returns `{accessList, gasUsed, error?}` where `gasUsed` is the last run's gas
//! with the list applied and `error` reth's text for its revert or halt (`call_error`). A
//! request's own `accessList` is not used as the starting point (the result converges to
//! the same list). Buffers are carved from the API scratch after the call data and
//! override space (and before a historical call's proof tail).

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
const Entry = node.access_list.Entry;
const Item = evm.transaction.AccessListItem;
const Key = evm.primitives.B256;

pub const methods = [_]rpc.Method(*Api){
    .{ .name = "eth_createAccessList", .handler = create_access_list },
};

pub const rounds_max = 8;
/// Upper bound on entries (accounts plus slots) of one list.
pub const entries_max = 4096;
/// Fewer entries than this is not a useful list: the scratch is misconfigured.
const entries_min = 64;

const Buffers = struct {
    current: []Entry,
    previous: []Entry,
    items: []Item,
    keys: []Key,
};

fn create_access_list(api: *Api, call: *Call) HandlerError!void {
    var request = try eth.parse_call_request(api, call);
    // reth's third parameter: state overrides (no block overrides).
    const state_overrides = try call.params.optional_raw();
    try call.params.finish();
    try eth.set_overrides(api, call, &request, state_overrides, null);
    const buffers = carve_buffers(api, request) orelse
        return call.fail(rpc.code.internal_error, "scratch too small");
    var collector: node.access_list.Collector = .{ .entries = buffers.current };
    var previous_len: usize = 0;
    var last: Executed = undefined;
    for (0..rounds_max) |round| {
        const previous = buffers.previous[0..previous_len];
        request.message.access_list = node.access_list.to_items(
            previous,
            buffers.items,
            buffers.keys,
        ) catch unreachable; // Proof: items and keys hold as many as the entry buffers.
        request.message.collect = &collector;
        last = switch (try eth.simulate(api, call, request)) {
            .invalid => |reason| return eth.fail_invalid(call, reason),
            .executed => |executed| executed,
        };
        if (collector.overflow) return call.fail(rpc.code.server_error, "access list too large");
        if (collector.eql(previous) or round + 1 == rounds_max) break;
        @memcpy(buffers.previous[0..collector.len], collector.slice());
        previous_len = collector.len;
    }
    // The item and key buffers are done with: the error text goes there.
    const text_buffer = std.mem.sliceAsBytes(buffers.keys);
    const failure: ?[]const u8 = if (last.success)
        null
    else if (last.exit.status() == .revert)
        call_error.revert_message(text_buffer, last.output)
    else
        call_error.halt(text_buffer, last.exit, last.gas_used).message;
    try write_result(call.writer, buffers.previous[0..previous_len], last.gas_used, failure);
}

const Executed = @FieldType(node.executor.Executor.Simulated, "executed");

/// The list buffers, after the parsed call data and override space and before a
/// historical call's proofs.
fn carve_buffers(api: *Api, request: eth.CallRequest) ?Buffers {
    const scratch = api.scratch;
    // After the call data and the override code space.
    const start = eth.scratch_used(api, &request);
    const end = switch (request.view) {
        .head => scratch.len,
        .historical => eth.proof_tail_offset(api).?, // Checked when parsed.
    };
    // Room for the alignment of each of the four arrays.
    const slack = 4 * 16;
    if (start + slack >= end) return null;
    const per_entry = 2 * @sizeOf(Entry) + @sizeOf(Item) + @sizeOf(Key);
    const count = @min(entries_max, (end - start - slack) / per_entry);
    if (count < entries_min) return null;
    var offset = start;
    const current = carve(Entry, scratch[0..end], &offset, count) orelse return null;
    const previous = carve(Entry, scratch[0..end], &offset, count) orelse return null;
    const items = carve(Item, scratch[0..end], &offset, count) orelse return null;
    const keys = carve(Key, scratch[0..end], &offset, count) orelse return null;
    assert(offset <= end);
    return .{ .current = current, .previous = previous, .items = items, .keys = keys };
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
