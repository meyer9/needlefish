//! `eth_simulateV1(options, block?)` (execution-apis): runs `blockStateCalls`, a list of
//! simulated blocks each with optional `blockOverrides`, `stateOverrides` and `calls`, on
//! top of a base block, carrying state across calls and blocks. Nothing is committed.
//!
//! Supported: the block overrides of `apply_block_overrides` (all of alloy's but `blockHash`;
//! overridden numbers and times must increase; defaults are parent + 1 and parent time + 12,
//! saturating; the base fee is zero unless overridden);
//! state overrides `balance`, `nonce`, `code`, `state` (replaces all storage) and
//! `stateDiff`. Calls run fee-free (gas price and base fee zero, as without
//! `validation`), with the block's remaining gas by default. Each block reports
//! `number`, `timestamp`, `gasLimit`, `gasUsed`, `baseFeePerGas`, `miner` and `calls`
//! (`returnData`, `logs`, `gasUsed`, `status`, `error` for a revert (code 3, reth's
//! "execution reverted: <reason>", with data) or a halt (-32015, reth's halt text)). Not
//! supported: `validation: true`, `traceTransfers`, `movePrecompileToAddress`; no block
//! hashes or roots.

const std = @import("std");
const assert = std.debug.assert;
const rpc = @import("../../utilities/rpc/root.zig");
const json = @import("../../utilities/json/root.zig");
const evm = @import("../evm/root.zig");
const node = @import("../node/root.zig");
const eth = @import("eth.zig");
const eth_proof = @import("eth_proof.zig");
const state_view = @import("state_view.zig");
const call_error = @import("call_error.zig");
const call_fees = @import("call_fees.zig");
const chainspec = @import("../chainspec/root.zig");
const schedule_module = @import("simulate_schedule.zig");

const Api = eth.Api;
const Call = rpc.Call;
const HandlerError = rpc.HandlerError;
const Executor = node.executor.Executor;
const BlockEnv = node.executor.BlockEnv;

pub const methods = [_]rpc.Method(*Api){
    .{ .name = "eth_simulateV1", .handler = simulate_v1 },
};

pub const blocks_max = schedule_module.blocks_max;
pub const calls_max = 256;
pub const overrides_max = 64;
pub const slots_max = 256;
/// execution-apis error codes (reth `EthSimulateError::error_code`, `SIMULATE_*_CODE`).
const code_vm_error = -32015;
const code_nonce_too_low = -38010;
const code_nonce_too_high = -38011;
const code_base_fee_too_low = -38012;
const code_intrinsic_gas = -38013;
const code_insufficient_funds = -38014;
const code_block_gas = -38015;
const code_initcode_size = -38025;

/// Iterates the elements of a JSON array as raw value slices.
const Elements = struct {
    scanner: json.Scanner,
    count: u32 = 0,

    fn init(raw: []const u8) HandlerError!Elements {
        var elements: Elements = .{ .scanner = json.Scanner.init(raw) };
        const first = elements.scanner.next() catch return error.InvalidParams;
        if (first.tag != .array_begin) return error.InvalidParams;
        return elements;
    }

    fn next(elements: *Elements, max: u32) HandlerError!?[]const u8 {
        const before = elements.scanner.offset();
        const token = elements.scanner.next() catch return error.InvalidParams;
        if (token.tag == .array_end) return null;
        if (elements.count == max) return error.InvalidParams;
        elements.count += 1;
        elements.scanner.skip(token) catch return error.InvalidParams;
        const text = elements.scanner.input[before..elements.scanner.offset()];
        return std.mem.trimStart(u8, text, " \t\r\n,");
    }
};

/// Iterates the members of a JSON object as (key, raw value) pairs.
const Members = struct {
    scanner: json.Scanner,
    count: u32 = 0,

    const Member = struct { key: []const u8, value: []const u8 };

    fn init(raw: []const u8) HandlerError!Members {
        var members: Members = .{ .scanner = json.Scanner.init(raw) };
        const first = members.scanner.next() catch return error.InvalidParams;
        if (first.tag != .object_begin) return error.InvalidParams;
        return members;
    }

    fn next(members: *Members, max: u32) HandlerError!?Member {
        const key = members.scanner.next() catch return error.InvalidParams;
        if (key.tag == .object_end) return null;
        if (members.count == max or key.escaped) return error.InvalidParams;
        members.count += 1;
        const before = members.scanner.offset();
        const token = members.scanner.next() catch return error.InvalidParams;
        members.scanner.skip(token) catch return error.InvalidParams;
        const text = members.scanner.input[before..members.scanner.offset()];
        return .{ .key = key.bytes, .value = std.mem.trim(u8, text, " \t\r\n:") };
    }
};

fn string_of(raw: []const u8) HandlerError![]const u8 {
    if (raw.len < 2 or raw[0] != '"' or raw[raw.len - 1] != '"') return error.InvalidParams;
    return raw[1 .. raw.len - 1];
}

fn quantity_of(comptime T: type, raw: []const u8) HandlerError!T {
    return json.parse_quantity(T, try string_of(raw)) catch error.InvalidParams;
}

/// One eth_simulateV1 request: what every block and call of it shares.
const Simulation = struct {
    api: *Api,
    call: *Call,
    /// Call data and override code of the call running; error texts once it ran.
    space: []u8,
    /// `validation: true`: fees, balances and nonces are checked and fees charged.
    validation: bool,
    /// The base block's extra data (its EIP-1559 parameters, for validated base fees).
    extra_data: []const u8,
    history: ?*node.HistoryDatabase,
    /// What is left of the RPC gas cap, shared by every call of the request (reth
    /// `remaining_call_gas_limit`).
    gas_cap_remaining: u64 = eth.rpc_gas_cap,
};

/// reth `EthSimulateError::GasLimitReached` (-38026, as `TooManyBlocks`).
const code_gas_limit_reached = schedule_module.code_too_many_blocks;
const gas_limit_reached = "Client adjustable limit reached";

/// The simulated block a block builds on.
const Parent = struct {
    env: BlockEnv,
    gas_used: u64,
    blob_gas_used: u64,
};

fn simulate_v1(api: *Api, call: *Call) HandlerError!void {
    const options = try call.params.raw();
    const view = try state_view.resolve(api, call, try call.params.optional_raw());
    try call.params.finish();
    const blocks = (json.find_path(options, &.{"blockStateCalls"}) catch null) orelse
        return error.InvalidParams;
    const count = try count_blocks(blocks);
    if (count > blocks_max) {
        return call.fail(schedule_module.code_too_many_blocks, "too many blocks");
    }
    if (count == 0) return call.fail(rpc.code.invalid_params, "calls are empty.");
    const space = switch (view) {
        .head => api.scratch,
        .historical => api.scratch[0 .. eth.proof_tail_offset(api) orelse {
            return call.fail(rpc.code.internal_error, "proof scratch too small");
        }],
    };
    const header = eth.view_header(api, view);
    const denim = api.spec.upgrades[@backingInt(chainspec.Upgrade.denim)];
    const chain = api.chain;
    var schedule = schedule_module.Schedule.init(
        chain.genesis_number,
        chain.genesis_timestamp,
        denim,
        header.number,
        header.timestamp,
    );
    // base/base orders and bounds every block before running any.
    try plan_blocks(call, space, schedule, blocks);
    var history: node.HistoryDatabase = undefined;
    var simulation: Simulation = .{
        .api = api,
        .call = call,
        .space = space,
        .validation = try json_true(options, "validation"),
        .extra_data = header.extra_data,
        .history = null,
    };
    const database: ?evm.state.Database = switch (view) {
        .head => blk: {
            chain.ensure_head_state() catch {
                return call.fail(rpc.code.internal_error, "head state unavailable");
            };
            break :blk null;
        },
        .historical => |block| blk: {
            const offset = eth.proof_tail_offset(api).?; // Checked above.
            const proofs: *eth_proof.Scratch = @ptrCast(@alignCast(api.scratch[offset..].ptr));
            history = .{
                .chain = chain,
                .hash = block.hash,
                .number = block.number,
                .account_proof = &proofs.account,
                .storage_proof = &proofs.storage,
            };
            simulation.history = &history;
            break :blk history.database();
        },
    };
    const session = chain.executor.session_begin(database);
    defer chain.executor.session_end(session);
    var parent: Parent = .{
        .env = node.chain.env_of(&header),
        .gas_used = header.gas_used,
        .blob_gas_used = header.blob_gas_used orelse 0,
    };
    parent.env.parent_beacon_block_root = parent.env.parent_beacon_block_root orelse @splat(0);
    try run_blocks(&simulation, &schedule, &parent, blocks);
}

fn count_blocks(blocks: []const u8) HandlerError!u64 {
    var list = try Elements.init(blocks);
    var count: u64 = 0;
    while (try list.next(4 * blocks_max)) |_| count += 1;
    return count;
}

/// Checks the numbers and timestamps of every block (`sanitize_base_chain`) on a copy of
/// the schedule.
fn plan_blocks(
    call: *Call,
    buffer: []u8,
    schedule_in: schedule_module.Schedule,
    blocks: []const u8,
) HandlerError!void {
    var schedule = schedule_in;
    var list = try Elements.init(blocks);
    while (try list.next(blocks_max)) |block_raw| {
        _ = try schedule.next(call, buffer, try block_overrides(block_raw));
    }
}

fn block_overrides(block_raw: []const u8) HandlerError!?[]const u8 {
    const raw = json.find_path(block_raw, &.{"blockOverrides"}) catch return error.InvalidParams;
    const text = raw orelse return null;
    return if (std.mem.eql(u8, text, "null")) null else text;
}

/// Runs and writes every block, each preceded by the empty fillers of its number gap.
fn run_blocks(
    simulation: *Simulation,
    schedule: *schedule_module.Schedule,
    parent: *Parent,
    blocks: []const u8,
) HandlerError!void {
    const w = simulation.call.writer;
    try w.begin_array();
    var list = try Elements.init(blocks);
    while (try list.next(blocks_max)) |block_raw| {
        var filler = schedule.*;
        const overrides = try block_overrides(block_raw);
        const planned = try schedule.next(simulation.call, simulation.space, overrides);
        var number = filler.prev_number + 1;
        while (number < planned.number) : (number += 1) {
            const prev = filler.prev_timestamp;
            // Proof: `plan_blocks` ran the same schedule without an error.
            filler.prev_timestamp = filler.next_timestamp(number, prev).?;
            const empty: schedule_module.Schedule.Planned = .{
                .number = number,
                .timestamp = filler.prev_timestamp,
            };
            parent.* = try run_block_checked(simulation, parent, "{}", empty);
        }
        parent.* = try run_block_checked(simulation, parent, block_raw, planned);
    }
    try w.end_array();
}

/// `simulate_block`, reporting a historical state read failure as such.
fn run_block_checked(
    simulation: *Simulation,
    parent: *const Parent,
    raw: []const u8,
    planned: schedule_module.Schedule.Planned,
) HandlerError!Parent {
    return simulate_block(simulation, parent, raw, planned) catch |err| {
        if (simulation.history) |history| if (history.failure) |failure| {
            return eth_proof.fail_history(simulation.call, failure);
        };
        return err;
    };
}

fn json_true(raw: []const u8, name: []const u8) HandlerError!bool {
    const value = (json.find_path(raw, &.{name}) catch return error.InvalidParams) orelse
        return false;
    return std.mem.eql(u8, value, "true");
}

/// The environment of a simulated block on `parent`: unvalidated blocks run with a zero
/// base fee, validated ones with the chain's next base fee; prevRandao is zero; then the
/// block overrides apply.
fn block_env(
    simulation: *Simulation,
    parent: *const Parent,
    overrides: ?[]const u8,
    planned: schedule_module.Schedule.Planned,
) HandlerError!BlockEnv {
    var env = parent.env;
    env.number = planned.number;
    env.timestamp = planned.timestamp;
    env.prev_randao = @splat(0);
    env.blob_base_fee = null;
    env.base_fee = 0;
    if (simulation.validation) {
        const spec = simulation.api.spec;
        env.base_fee = spec.next_base_fee(.{
            .timestamp = parent.env.timestamp,
            .gas_used = parent.gas_used,
            .gas_limit = parent.env.gas_limit,
            .base_fee = parent.env.base_fee,
            .blob_gas_used = parent.blob_gas_used,
            .extra_data = simulation.extra_data,
        }, planned.timestamp) catch parent.env.base_fee;
    }
    if (overrides) |raw| {
        // base/base refuses a gas limit above both the block's and the RPC gas cap.
        const gas_limit = json.find_path(raw, &.{"gasLimit"}) catch return error.InvalidParams;
        if (gas_limit) |text| if (!std.mem.eql(u8, text, "null")) {
            const limit = try quantity_of(u64, text);
            if (limit > env.gas_limit and limit > eth.rpc_gas_cap) {
                return simulation.call.fail(code_gas_limit_reached, gas_limit_reached);
            }
        };
        try apply_block_overrides(simulation.call, &env, raw);
    }
    assert(env.number == planned.number and env.timestamp == planned.timestamp);
    return env;
}

/// Runs one simulated block on top of `parent` and writes it.
fn simulate_block(
    simulation: *Simulation,
    parent: *const Parent,
    raw: []const u8,
    planned: schedule_module.Schedule.Planned,
) HandlerError!Parent {
    const call = simulation.call;
    const space = simulation.space;
    const env = try block_env(simulation, parent, try block_overrides(raw), planned);
    const executor = simulation.api.chain.executor;
    if (json.find_path(raw, &.{"stateOverrides"}) catch return error.InvalidParams) |o| {
        if (try both_state_and_diff(o)) |address| {
            return call.fail(rpc.code.invalid_params, both_state_message(space, address));
        }
        apply_state_overrides(executor.state, space, o) catch |err| switch (err) {
            error.InvalidParams => return error.InvalidParams,
            else => return call.fail(rpc.code.internal_error, @errorName(err)),
        };
    }
    const w = call.writer;
    try w.begin_object();
    try w.key("number");
    try w.quantity(env.number);
    try w.key("timestamp");
    try w.quantity(env.timestamp);
    try w.key("gasLimit");
    try w.quantity(env.gas_limit);
    try w.key("baseFeePerGas");
    try w.quantity(env.base_fee);
    try w.key("miner");
    try w.data(&env.beneficiary);
    try w.key("calls");
    try w.begin_array();
    var gas_used: u64 = 0;
    var log_index: u64 = 0;
    if (json.find_path(raw, &.{"calls"}) catch return error.InvalidParams) |calls| {
        var list = try Elements.init(calls);
        var index: u64 = 0;
        while (try list.next(calls_max)) |call_raw| : (index += 1) {
            const position: Position = .{ .block = env.number, .index = index };
            gas_used += try run_call(simulation, &env, gas_used, call_raw, position, &log_index);
            assert(gas_used <= env.gas_limit);
        }
    }
    try w.end_array();
    try w.key("gasUsed");
    try w.quantity(gas_used);
    try w.end_object();
    return .{ .env = env, .gas_used = gas_used, .blob_gas_used = 0 };
}

/// Whether the block overrides `raw` set the field `names` (a name and its aliases; a null
/// member sets nothing).
fn overridden(raw: []const u8, names: []const []const u8) HandlerError!bool {
    for (names) |name| {
        const value = json.find_path(raw, &.{name}) catch return error.InvalidParams;
        if (value != null and !std.mem.eql(u8, value.?, "null")) return true;
    }
    return false;
}

const Position = struct { block: u64, index: u64 };

/// alloy-evm 0.39 `apply_block_overrides` over alloy's `BlockOverrides` fields and serde
/// aliases. Unknown members are ignored, as serde ignores them. `difficulty` is read and
/// dropped (post-merge DIFFICULTY reads prevRandao); `beaconRoot` reaches only a simulated
/// block's system call; `blockHash` is not supported.
pub fn apply_block_overrides(call: *Call, env: *BlockEnv, raw: []const u8) HandlerError!void {
    var members = try Members.init(raw);
    while (try members.next(32)) |member| {
        if (std.mem.eql(u8, member.value, "null")) continue;
        const key = member.key;
        if (is(key, "number") or is(key, "blockNumber")) {
            env.number = saturate(u64, try quantity_of(u256, member.value));
        } else if (is(key, "difficulty")) {
            _ = try quantity_of(u256, member.value);
        } else if (is(key, "time") or is(key, "timestamp")) {
            env.timestamp = try quantity_of(u64, member.value);
        } else if (is(key, "gasLimit")) {
            env.gas_limit = try quantity_of(u64, member.value);
        } else if (is(key, "coinbase") or is(key, "feeRecipient")) {
            env.beneficiary = try fixed_of(20, member.value);
        } else if (is(key, "random") or is(key, "prevRandao")) {
            env.prev_randao = try fixed_of(32, member.value);
        } else if (is(key, "baseFee") or is(key, "baseFeePerGas")) {
            env.base_fee = saturate(u64, try quantity_of(u256, member.value));
        } else if (is(key, "blobBaseFee")) {
            env.blob_base_fee = saturate(u128, try quantity_of(u256, member.value));
        } else if (is(key, "beaconRoot") or is(key, "parentBeaconBlockRoot")) {
            env.parent_beacon_block_root = try fixed_of(32, member.value);
        } else if (is(key, "blockHash")) {
            return call.fail(rpc.code.invalid_params, "unsupported block override");
        }
    }
}

fn is(key: []const u8, name: []const u8) bool {
    return std.mem.eql(u8, key, name);
}

fn saturate(comptime T: type, value: u256) T {
    return @intCast(@min(value, std.math.maxInt(T)));
}

fn fixed_of(comptime size: usize, raw: []const u8) HandlerError![size]u8 {
    return json.parse_fixed(size, try string_of(raw)) catch error.InvalidParams;
}

/// The first account of the state overrides `raw` that sets both `state` and `stateDiff`
/// (alloy-evm `StateOverrideError::BothStateAndStateDiff`), if any.
pub fn both_state_and_diff(raw: []const u8) HandlerError!?[20]u8 {
    var accounts = try Members.init(raw);
    while (try accounts.next(overrides_max)) |entry| {
        const state = try overridden(entry.value, &.{"state"});
        if (state and try overridden(entry.value, &.{"stateDiff"})) {
            return json.parse_fixed(20, entry.key) catch error.InvalidParams;
        }
    }
    return null;
}

/// reth's `EthApiError::BothStateAndStateDiffInOverride` text (the address `{:?}`-printed:
/// lowercase hex), written into `buffer`.
pub fn both_state_message(buffer: []u8, address: [20]u8) []const u8 {
    assert(buffer.len >= 96);
    const hex = std.fmt.bytesToHex(address, .lower);
    const format = "account 0x{s} has both 'state' and 'stateDiff'";
    return std.fmt.bufPrint(buffer, format, .{&hex}) catch unreachable; // Proof: 96 bytes.
}

pub const OverrideError = HandlerError || evm.state.Error;

pub fn apply_state_overrides(state: *evm.State, space: []u8, raw: []const u8) OverrideError!void {
    var accounts = try Members.init(raw);
    while (try accounts.next(overrides_max)) |entry| {
        const text = entry.key;
        if (text.len != 42) return error.InvalidParams;
        const address = json.parse_fixed(20, text) catch return error.InvalidParams;
        const account = try state.load(address);
        var fields = try Members.init(entry.value);
        while (try fields.next(8)) |field| {
            if (std.mem.eql(u8, field.value, "null")) continue;
            try apply_account_field(state, account, space, field);
        }
    }
}

fn apply_account_field(
    state: *evm.State,
    account: *evm.state.Account,
    space: []u8,
    field: Members.Member,
) OverrideError!void {
    if (std.mem.eql(u8, field.key, "balance")) {
        try state.set_balance(account, try quantity_of(u256, field.value));
    } else if (std.mem.eql(u8, field.key, "nonce")) {
        try state.set_nonce(account, try quantity_of(u64, field.value));
    } else if (std.mem.eql(u8, field.key, "code")) {
        const code = json.parse_data(try string_of(field.value), space) catch
            return error.InvalidParams;
        try state.replace_code(account, code);
    } else if (std.mem.eql(u8, field.key, "state")) {
        // Fresh storage incarnation: database slots read as zero (never committed).
        account.storage_epoch += 1;
        try write_slots(state, account, field.value);
    } else if (std.mem.eql(u8, field.key, "stateDiff")) {
        try write_slots(state, account, field.value);
    } else return error.InvalidParams;
}

fn write_slots(state: *evm.State, account: *evm.state.Account, raw: []const u8) OverrideError!void {
    var slots = try Members.init(raw);
    while (try slots.next(slots_max)) |slot| {
        const key = json.parse_fixed(32, slot.key) catch return error.InvalidParams;
        const value = json.parse_fixed(32, try string_of(slot.value)) catch
            return error.InvalidParams;
        const access = try state.storage_access(account, std.mem.readInt(u256, &key, .big));
        try state.storage_write(account, access.slot, std.mem.readInt(u256, &value, .big));
    }
}

/// Runs and writes one call; returns its gas used. A call the EVM rejects fails the whole
/// request (reth's `execute_transactions`); a revert or halt is the call's `error`.
fn run_call(
    simulation: *Simulation,
    env: *const BlockEnv,
    gas_used: u64,
    raw: []const u8,
    position: Position,
    log_index: *u64,
) HandlerError!u64 {
    const call = simulation.call;
    const space = simulation.space;
    var message = try eth.parse_call(space, raw);
    try set_fees(simulation, &message, raw);
    const remaining = env.gas_limit - gas_used;
    if ((message.gas orelse 0) > remaining) {
        return call.fail(code_block_gas, "Block gas limit exceeded by the block's transactions");
    }
    // The RPC gas cap bounds a given gas silently and the default.
    const cap = simulation.gas_cap_remaining;
    message.gas = if (message.gas) |gas| @min(gas, cap) else @min(remaining, cap);
    const executor = simulation.api.chain.executor;
    const caller = executor.state.load(message.from) catch |err| {
        return call.fail(rpc.code.internal_error, @errorName(err));
    };
    const sender: Sender = .{ .nonce = caller.info.nonce, .balance = caller.info.balance };
    const result = executor.session_call(env, message) catch |err| {
        return call.fail(rpc.code.internal_error, @errorName(err));
    };
    const executed = switch (result) {
        .invalid => |reason| return fail_invalid(simulation, reason, &message, sender),
        .executed => |executed| executed,
    };
    if (executed.gas_used > cap) {
        return call.fail(code_gas_limit_reached, gas_limit_reached);
    }
    simulation.gas_cap_remaining = cap - executed.gas_used;
    const w = call.writer;
    try w.begin_object();
    try w.key("returnData");
    // base/base reports no return data for a failed call (the revert output is `data`).
    try w.data(if (executed.status == .success) executed.output else &.{});
    try w.key("logs");
    try w.begin_array();
    for (executed.logs) |item| {
        try write_log(w, item, position, log_index.*);
        log_index.* += 1;
    }
    try w.end_array();
    try w.key("gasUsed");
    try w.quantity(executed.gas_used);
    try w.key("status");
    try w.quantity(@as(u64, @intFromBool(executed.status == .success)));
    // The call data in `space` is done with: the error text goes there.
    switch (executed.status) {
        .success => {},
        .revert => {
            const text = call_error.revert_message(space, executed.output);
            try write_error(w, call_error.code_execution_error, text, executed.output);
        },
        .halt => {
            const failure = call_error.halt(space, executed.exit, message.gas.?);
            try write_error(w, code_vm_error, failure.message, &.{});
        },
    }
    try w.end_object();
    return executed.gas_used;
}

const Sender = struct { nonce: u64, balance: u256 };

/// The call's prices and nonce as reth's `resolve_transaction` fills them: missing fee
/// fields are zero; the request's nonce counts only with validation.
fn set_fees(
    simulation: *const Simulation,
    message: *node.executor.Executor.Call,
    raw: []const u8,
) HandlerError!void {
    const fees = try call_fees.parse(raw);
    const eip1559 = fees.max_fee != null or fees.max_priority_fee != null;
    const price = if (eip1559) fees.max_fee orelse 0 else fees.gas_price orelse 0;
    message.gas_price = @min(price, std.math.maxInt(u128));
    message.priority_fee = if (eip1559)
        @min(fees.max_priority_fee orelse 0, std.math.maxInt(u128))
    else
        null;
    message.validate = simulation.validation;
    if (!simulation.validation) return;
    const nonce = json.find_path(raw, &.{"nonce"}) catch return error.InvalidParams;
    if (nonce) |text| if (!std.mem.eql(u8, text, "null")) {
        message.nonce = try quantity_of(u64, text);
    };
}

/// reth's top-level error for a call the EVM rejects (`as_simulate_error`, else the
/// eth_call error).
fn fail_invalid(
    simulation: *const Simulation,
    reason: evm.transaction.Invalid,
    message: *const node.executor.Executor.Call,
    sender: Sender,
) HandlerError {
    const call = simulation.call;
    const buffer = simulation.space;
    switch (reason) {
        .nonce_too_low => {
            const text = std.fmt.bufPrint(buffer, "nonce too low: next nonce {d}, tx nonce {d}", .{
                sender.nonce, message.nonce orelse sender.nonce,
            }) catch "nonce too low";
            return call.fail(code_nonce_too_low, text);
        },
        .nonce_too_high => return call.fail(code_nonce_too_high, "nonce too high"),
        .nonce_overflow => return call.fail(rpc.code.internal_error, "nonce has max value"),
        .fee_below_base_fee => {
            return call.fail(code_base_fee_too_low, "max fee per gas less than block base fee");
        },
        .intrinsic_gas_too_low, .floor_gas_too_low => {
            return call.fail(code_intrinsic_gas, "intrinsic gas too low");
        },
        .insufficient_funds => {
            const cost = @as(u512, message.gas.?) * message.gas_price + message.value;
            const text = std.fmt.bufPrint(
                buffer,
                "insufficient funds for gas * price + value: have {d} want {d}",
                .{ sender.balance, cost },
            ) catch "insufficient funds for gas * price + value";
            return call.fail(code_insufficient_funds, text);
        },
        .initcode_too_large => return call.fail(code_initcode_size, "max initcode size exceeded"),
        else => return eth.fail_invalid(call, reason),
    }
}

fn write_error(
    w: *json.Writer,
    code: i32,
    message: []const u8,
    data: []const u8,
) HandlerError!void {
    try w.key("error");
    try w.begin_object();
    try w.key("code");
    try w.integer(code);
    try w.key("message");
    try w.string(message);
    if (data.len > 0) {
        try w.key("data");
        try w.data(data);
    }
    try w.end_object();
}

fn write_log(
    w: *json.Writer,
    item: evm.state.Log,
    position: Position,
    index: u64,
) HandlerError!void {
    try w.begin_object();
    try w.key("address");
    try w.data(&item.address);
    try w.key("topics");
    try w.begin_array();
    for (item.topic_slice()) |topic| try w.data(&topic);
    try w.end_array();
    try w.key("data");
    try w.data(item.data);
    try w.key("blockNumber");
    try w.quantity(position.block);
    try w.key("transactionIndex");
    try w.quantity(position.index);
    try w.key("logIndex");
    try w.quantity(index);
    try w.key("removed");
    try w.boolean(false);
    try w.end_object();
}
