//! Opt-in execution coverage for the differential fuzz adapter (`-Ddiff-coverage`).
//!
//! Two kinds of features, reported per request by `base diff-adapter` when the environment
//! sets `BASE_DIFF_COVERAGE`:
//!   - semantic features: opcode x fork x call-depth bucket, opcode x frame outcome,
//!     precompile x input-length bucket x result, native precompile x selector x result,
//!     transaction type x outcome (recorded by the adapter),
//!   - edges: the compiler's inline 8-bit counters (`-ffuzz` instrumentation of the `base`
//!     module), of which the adapter reports those inside the EVM and crypto code.
//!
//! Builds without `-Ddiff-coverage` compile every hook away, and with it a hook costs one
//! branch until `active` is set. Recording never changes execution. Single-threaded: the
//! adapter runs one request at a time.

const std = @import("std");
const assert = std.debug.assert;
const Fork = @import("fork.zig").Fork;
const Exit = @import("evm.zig").Exit;
const opcode_info = @import("opcode.zig");

pub const enabled: bool = @import("build_options").diff_coverage;

/// Set once at startup when the environment asks for coverage.
pub var active: bool = false;

const fork_count = @typeInfo(Fork).@"enum".field_names.len;
const exit_count = @typeInfo(Exit).@"enum".field_names.len;
/// Call depth buckets: 0, 1, 2-3, 4-15, 16-63, 64 and deeper.
const depth_bucket_count = 6;
const depth_bucket_names = [depth_bucket_count][]const u8{
    "0", "1", "2-3", "4-15", "16-63", "64+",
};

var opcodes: [256][fork_count][depth_bucket_count]u32 = @splat(@splat(@splat(0)));
var halts: [256][exit_count]u32 = @splat(@splat(0));

/// Sparse features (precompile, native, transaction): a fixed open-addressing table.
const Kind = enum(u8) { precompile, native, transaction };
pub const key_bytes = 32;
const Key = [key_bytes]u8;
const slot_count = 1 << 12;
const Slot = struct { key: Key, count: u32 };
var slots: [slot_count]Slot = undefined;
var slot_used: [slot_count]bool = @splat(false);
/// Indices of used slots, for O(used) reset and emission.
var used: [slot_count]u16 = undefined;
var used_count: u32 = 0;
/// Features dropped because the table was full (reported as `nf:dropped`).
var dropped: u32 = 0;

pub fn reset() void {
    if (comptime !enabled) return;
    opcodes = @splat(@splat(@splat(0)));
    halts = @splat(@splat(0));
    for (used[0..used_count]) |index| slot_used[index] = false;
    used_count = 0;
    dropped = 0;
}

fn depth_bucket(depth: u16) usize {
    if (depth <= 1) return depth;
    if (depth <= 3) return 2;
    if (depth <= 15) return 3;
    if (depth <= 63) return 4;
    return 5;
}

/// Every executed instruction (each part of a fused one).
pub inline fn step(comptime fork: Fork, comptime opcode: u8, depth: u16) void {
    if (comptime !enabled) return;
    if (!active) return;
    const cell = &opcodes[opcode][@backingInt(fork)][depth_bucket(depth)];
    cell.* +|= 1;
}

/// An instruction that ended its frame's run: a halt, STOP/RETURN/REVERT, or a CALL/CREATE
/// suspending the frame.
pub inline fn halt(comptime opcode: u8, exit: Exit) void {
    if (comptime !enabled) return;
    if (!active) return;
    halts[opcode][@backingInt(exit)] +|= 1;
}

fn bucket_of_length(length: usize) u8 {
    if (length == 0) return 0;
    return @intCast(std.math.log2_int(usize, length) + 1);
}

/// A precompile call: its address, input length and result.
pub fn precompile(address: *const [20]u8, input_length: usize, status: []const u8) void {
    if (comptime !enabled) return;
    if (!active) return;
    var key: Key = @splat(0);
    key[0] = @backingInt(Kind.precompile);
    key[1..3].* = address[18..20].*;
    key[3] = bucket_of_length(input_length);
    key[4] = @intFromBool(input_length % 32 == 0);
    put_text(&key, 5, status);
    record(&key);
}

/// A native precompile call: its contract (B-20 tokens by variant), selector and result
/// (`revert` with the revert selector).
pub fn native(
    address: *const [20]u8,
    input: []const u8,
    status: []const u8,
    output: []const u8,
) void {
    if (comptime !enabled) return;
    if (!active) return;
    var key: Key = @splat(0);
    key[0] = @backingInt(Kind.native);
    const token = address[0] == 0xb2 and std.mem.allEqual(u8, address[1..10], 0);
    // A B-20 token address is derived per token: keep its variant byte only.
    key[1..21].* = if (token) [_]u8{0xb2} ++ @as([19]u8, @splat(0)) else address.*;
    if (token) key[20] = address[19];
    key[21] = @intFromBool(input.len >= 4);
    if (input.len >= 4) key[22..26].* = input[0..4].*;
    key[26] = @intFromBool(output.len >= 4);
    if (output.len >= 4) key[27..31].* = output[0..4].*;
    key[31] = if (std.mem.eql(u8, status, "success"))
        0
    else if (std.mem.eql(u8, status, "revert"))
        1
    else
        2;
    record(&key);
}

/// A transaction's outcome in the block: `ok`, `revert`, `halt`, or a rejection's error.
pub fn transaction(tx_type: u8, outcome: []const u8) void {
    if (comptime !enabled) return;
    if (!active) return;
    var key: Key = @splat(0);
    key[0] = @backingInt(Kind.transaction);
    key[1] = tx_type;
    put_text(&key, 2, outcome);
    record(&key);
}

fn put_text(key: *Key, start: usize, text: []const u8) void {
    assert(start < key_bytes);
    const length = @min(text.len, key_bytes - start);
    @memcpy(key[start..][0..length], text[0..length]);
}

fn record(key: *const Key) void {
    var index: usize = @intCast(std.hash.Wyhash.hash(0, key) % slot_count);
    var probes: usize = 0;
    while (probes < slot_count) : (probes += 1) {
        if (!slot_used[index]) {
            if (used_count == slot_count / 2) {
                dropped +|= 1;
                return;
            }
            slot_used[index] = true;
            slots[index] = .{ .key = key.*, .count = 1 };
            used[used_count] = @intCast(index);
            used_count += 1;
            return;
        }
        if (std.mem.eql(u8, &slots[index].key, key)) {
            slots[index].count +|= 1;
            return;
        }
        index = (index + 1) % slot_count;
    }
    unreachable; // The table is at most half full.
}

/// Writes the semantic features as `"nf:...":count` JSON members, each preceded by `,`
/// unless `first`; returns whether nothing was written yet.
pub fn write_members(out: *std.Io.Writer, first_member: bool) std.Io.Writer.Error!bool {
    var first = first_member;
    for (opcodes, 0..) |per_fork, opcode| {
        for (per_fork, 0..) |per_depth, fork| {
            for (per_depth, 0..) |count, depth| {
                if (count == 0) continue;
                try separator(out, &first);
                try out.print("\"nf:op:{s}:{t}:d{s}\":{d}", .{
                    opcode_info.table[opcode].name,
                    @as(Fork, @fromBackingInt(@intCast(fork))),
                    depth_bucket_names[depth],
                    count,
                });
            }
        }
    }
    for (halts, 0..) |per_exit, opcode| {
        for (per_exit, 0..) |count, exit| {
            if (count == 0) continue;
            try separator(out, &first);
            try out.print("\"nf:exit:{s}:{t}\":{d}", .{
                opcode_info.table[opcode].name,
                @as(Exit, @fromBackingInt(@intCast(exit))),
                count,
            });
        }
    }
    for (used[0..used_count]) |index| {
        const slot = &slots[index];
        try separator(out, &first);
        try write_key(out, &slot.key);
        try out.print(":{d}", .{slot.count});
    }
    if (dropped > 0) {
        try separator(out, &first);
        try out.print("\"nf:dropped\":{d}", .{dropped});
    }
    return first;
}

pub fn separator(out: *std.Io.Writer, first: *bool) std.Io.Writer.Error!void {
    if (!first.*) try out.writeAll(",");
    first.* = false;
}

fn text_of(bytes: []const u8) []const u8 {
    const end = std.mem.indexOfScalar(u8, bytes, 0) orelse bytes.len;
    return bytes[0..end];
}

fn write_key(out: *std.Io.Writer, key: *const Key) std.Io.Writer.Error!void {
    switch (@as(Kind, @fromBackingInt(@intCast(key[0])))) {
        .precompile => {
            const address = std.mem.readInt(u16, key[1..3], .big);
            // Length bucket `l<k>`: 0 for empty, else 2^(k-1) <= length < 2^k.
            try out.print("\"nf:pre:0x{x}:l{d}{s}:{s}\"", .{
                address,
                key[3],
                if (key[4] == 1) "w" else "",
                text_of(key[5..]),
            });
        },
        .native => {
            try out.print("\"nf:native:0x{x}:", .{key[1..21]});
            if (key[21] == 1) try out.print("{x}", .{key[22..26]}) else try out.writeAll("short");
            const statuses = [_][]const u8{ "success", "revert", "halt" };
            try out.print(":{s}", .{statuses[key[31]]});
            if (key[31] == 1 and key[26] == 1) try out.print(":{x}", .{key[27..31]});
            if (key[31] == 1 and key[26] == 0) try out.writeAll(":short");
            try out.writeAll("\"");
        },
        .transaction => {
            try out.print("\"nf:tx:0x{x}:{s}\"", .{ key[1], text_of(key[2..]) });
        },
    }
}

/// The compiler's inline 8-bit edge counters and their PCs (`-ffuzz`), or empty slices in
/// builds without the instrumentation.
pub fn edge_counters() []u8 {
    if (comptime !enabled) return &.{};
    const start = @extern([*]u8, .{ .name = "__start___sancov_cntrs", .linkage = .weak }) orelse
        return &.{};
    const stop = @extern([*]u8, .{ .name = "__stop___sancov_cntrs", .linkage = .weak }) orelse
        return &.{};
    return start[0 .. stop - start];
}

pub fn edge_pcs() []const usize {
    if (comptime !enabled) return &.{};
    const start = @extern([*]usize, .{ .name = "__start___sancov_pcs1", .linkage = .weak }) orelse
        return &.{};
    const stop = @extern([*]usize, .{ .name = "__stop___sancov_pcs1", .linkage = .weak }) orelse
        return &.{};
    return start[0 .. stop - start];
}
