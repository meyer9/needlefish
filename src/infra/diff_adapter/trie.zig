//! Differential protocol `trie` mode (base/base `TRIE_PROTOCOL.md`): applies a request's
//! blocks of hashed-key writes, from the empty state, and reports after every block the
//! state root, the storage roots of the keys the block names, and the requested proofs.
//!
//! `blocks` (the primary) is the node's commit path over its own on-disk database in
//! `trie.dir` (`trie_node.zig`, disk mode): each block's writes, as post-block values in
//! hashed key space (`trie_model.zig`), go through `StateDb.commit_hashed` (a hashed
//! changeset applied into the flat trees by `DiskState`) and `Database.commit_applied`;
//! roots come from the database head and its account records, proofs from
//! `Database.proof_hashed` (eth_getProof's disk walk). Unwinds are native (`set_head`);
//! one the database cannot make (deeper than its reorg bound) applies the revert and the
//! ops as one block.
//!
//! `variants` (`trie_variants.zig`): `sparse`, `state-trie`, `hash-builder` (the model's
//! whole state through `HashBuilder`), and on requests whose every key carries its
//! preimages, `node-address`: the durable node's in-memory state keyed by address
//! (`Overlay`, `execute_and_commit`, `proof_at`) in a second database in `trie.dir`. A
//! variant that fails reports the error on that block and every later one.

const std = @import("std");
const assert = std.debug.assert;

const db = @import("../../execution/db/root.zig");
const trie_request = @import("trie_request.zig");
const trie_model = @import("trie_model.zig");
const trie_node = @import("trie_node.zig");
const trie_variants = @import("trie_variants.zig");
const response = @import("response.zig");
const Coverage = @import("coverage.zig").Coverage;

const Hash = [32]u8;
const Writer = std.Io.Writer;
const Case = trie_request.Case;
const Block = trie_request.Block;
const Op = trie_request.Op;
const Node = trie_node.Node;
const Model = trie_model.Model;
const Touched = trie_model.Touched;
const AccountState = db.history.AccountState;

pub const StorageRoot = struct { key: Hash, root: Hash };
pub const SlotProof = struct { slot: Hash, value: u256, proof: []const []const u8 };
pub const ProofResult = struct {
    key: Hash,
    account: ?AccountState,
    account_proof: []const []const u8,
    storage: []SlotProof,
};

/// One block's result; a variant fills what it computes, or `error_text`.
pub const BlockResult = struct {
    number: u64,
    error_text: ?[]const u8 = null,
    state_root: ?Hash = null,
    storage_roots: ?[]const StorageRoot = null,
    proofs: ?[]const ProofResult = null,
};

pub const Variant = struct { name: []const u8, blocks: []BlockResult };

pub const Outcome = struct { blocks: []const BlockResult, variants: []const Variant };

const variant_names = [_][]const u8{ "sparse", "state-trie", "hash-builder", "node-address" };
const VariantId = enum(u8) { sparse, state_trie, hash_builder, node_address };

/// One request's run: the databases, the variants and the model.
const Run = struct {
    arena: std.mem.Allocator,
    allocator: std.mem.Allocator,
    case: *const Case,
    model: Model,
    primary: *Node,
    /// Request height -> the primary's height holding that state (a non-native unwind
    /// appends a block instead of moving back).
    primary_heights: [trie_node.blocks_max + 1]u64 = undefined,
    address_node: ?*Node = null,
    address_heights: [trie_node.blocks_max + 1]u64 = undefined,
    sparse: ?*trie_variants.Sparse = null,
    state_trie: ?trie_variants.StateTrieVariant = null,
    /// The first error of each variant (later blocks repeat it).
    failed: [variant_names.len]?[]const u8 = @splat(null),
    variants: [variant_names.len][]BlockResult = undefined,
    height: u64 = 0,
};

/// Runs `case` in `case.dir` (created, and deleted with everything in it before returning).
pub fn run(
    arena: std.mem.Allocator,
    allocator: std.mem.Allocator,
    io: std.Io,
    case: *const Case,
) !Outcome {
    const cwd = std.Io.Dir.cwd();
    cwd.createDirPath(io, case.dir) catch return error.DirectoryFailed;
    defer remove_dir(io, case.dir);
    const primary_path = try std.fs.path.join(arena, &.{ case.dir, "primary.db" });
    const address_path = try std.fs.path.join(arena, &.{ case.dir, "node-address.db" });
    var state: Run = .{
        .arena = arena,
        .allocator = allocator,
        .case = case,
        .model = .{ .arena = arena },
        .primary = try Node.create(allocator, .disk, primary_path),
    };
    defer state.primary.destroy();
    state.primary_heights[0] = 0;
    state.address_heights[0] = 0;
    for (&state.variants) |*blocks| blocks.* = try arena.alloc(BlockResult, case.blocks.len);
    start_variants(&state, address_path);
    defer stop_variants(&state);
    const blocks = try arena.alloc(BlockResult, case.blocks.len);
    for (case.blocks, blocks, 0..) |*block, *result, index| {
        result.* = try run_block(&state, block, index);
    }
    var variants: std.ArrayList(Variant) = .empty;
    for (variant_names, state.variants, 0..) |name, results, index| {
        const id: VariantId = @fromBackingInt(@intCast(index));
        if (id == .node_address and !case.preimages) continue;
        try variants.append(arena, .{ .name = name, .blocks = results });
    }
    return .{ .blocks = blocks, .variants = variants.items };
}

fn start_variants(state: *Run, address_path: []const u8) void {
    const allocator = state.allocator;
    state.sparse = trie_variants.Sparse.create(allocator) catch |err| blk: {
        state.failed[@backingInt(VariantId.sparse)] = @errorName(err);
        break :blk null;
    };
    state.state_trie = trie_variants.StateTrieVariant.init(allocator) catch |err| blk: {
        state.failed[@backingInt(VariantId.state_trie)] = @errorName(err);
        break :blk null;
    };
    if (!state.case.preimages) return;
    state.address_node = Node.create(allocator, .memory, address_path) catch |err| blk: {
        state.failed[@backingInt(VariantId.node_address)] = @errorName(err);
        break :blk null;
    };
}

fn stop_variants(state: *Run) void {
    if (state.address_node) |node| node.destroy();
    if (state.state_trie) |*variant| variant.deinit(state.allocator);
    if (state.sparse) |sparse| sparse.destroy(state.allocator);
}

/// Deletes the request's database files and its directory (best effort: the directory
/// was empty or absent before the request).
fn remove_dir(io: std.Io, dir: []const u8) void {
    const cwd = std.Io.Dir.cwd();
    var names_buffer: [2][std.fs.max_path_bytes]u8 = undefined;
    for ([_][]const u8{ "primary.db", "node-address.db" }, &names_buffer) |name, *buffer| {
        const path = std.fmt.bufPrint(buffer, "{s}/{s}", .{ dir, name }) catch continue;
        cwd.deleteFile(io, path) catch {};
    }
    cwd.deleteDir(io, dir) catch |err| {
        std.log.warn("diff adapter: trie dir {s} not removed: {t}", .{ dir, err });
    };
}

fn run_block(state: *Run, block: *const Block, index: usize) !BlockResult {
    if (block.unwind > state.height) return error.InvalidField;
    const parent = state.height - block.unwind;
    if (block.number != parent + 1) return error.InvalidField;
    // The model: the revert (the state after the parent), then the ops.
    // The primary's block is the ops alone after a native unwind, else revert and ops.
    var touched_all: Touched = .{};
    var touched_ops: Touched = .{};
    try state.model.apply(block.revert, &touched_all);
    try state.model.apply(block.ops, &touched_ops);
    for (touched_ops.accounts.keys()) |key| try touched_all.accounts.put(state.arena, key, {});
    for (touched_ops.slots.keys()) |ref| try touched_all.slots.put(state.arena, ref, {});
    const writes_native = try state.model.writes(&touched_ops);
    const writes_all = try state.model.writes(&touched_all);
    const named = try named_keys(state.arena, block);
    var result: BlockResult = .{ .number = block.number };
    // The primary.
    const node = state.primary;
    const native = try node.unwind_to(state.primary_heights[@intCast(parent)]);
    try node.commit_hashed(if (native) writes_native else writes_all);
    state.primary_heights[@intCast(parent + 1)] = node.height;
    result.state_root = node.state_root();
    result.storage_roots = try primary_storage_roots(state, named);
    result.proofs = try primary_proofs(state, block);
    state.height = parent + 1;
    run_variants(state, block, index, parent, named, writes_native);
    return result;
}

/// Every key an op of the block (its revert too) names, once, ascending.
fn named_keys(arena: std.mem.Allocator, block: *const Block) ![]const Hash {
    var keys: std.AutoArrayHashMapUnmanaged(Hash, void) = .empty;
    for ([2][]const Op{ block.revert, block.ops }) |ops| {
        for (ops) |*op| try keys.put(arena, op.key, {});
    }
    const sorted = keys.keys();
    std.mem.sort(Hash, sorted, {}, hash_less_than);
    return sorted;
}

fn hash_less_than(_: void, a: Hash, b: Hash) bool {
    return std.mem.order(u8, &a, &b) == .lt;
}

fn primary_storage_roots(state: *Run, named: []const Hash) ![]const StorageRoot {
    var roots: std.ArrayList(StorageRoot) = .empty;
    for (named) |*key| {
        const record = state.primary.db.state.account_hashed(key) orelse continue;
        try roots.append(state.arena, .{ .key = key.*, .root = record.storage_root });
    }
    return roots.items;
}

fn primary_proofs(state: *Run, block: *const Block) ![]const ProofResult {
    const proofs = try state.arena.alloc(ProofResult, block.proofs.len);
    const account_proof = try state.allocator.create(trie_node.AccountProof);
    defer state.allocator.destroy(account_proof);
    const storage_proofs = try state.allocator.alloc(
        trie_node.StorageProof,
        trie_request.proof_slots_max,
    );
    defer state.allocator.free(storage_proofs);
    var values: [trie_request.proof_slots_max]u256 = undefined;
    for (block.proofs, proofs) |*target, *out| {
        const count = target.slots.len;
        const account = try state.primary.db.proof_hashed(
            &target.key,
            target.slots,
            account_proof,
            storage_proofs[0..count],
            values[0..count],
        );
        out.* = try proof_result(state.arena, target, account, account_proof, storage_proofs);
        for (out.storage, values[0..count]) |*slot, value| slot.value = value;
    }
    return proofs;
}

/// Copies a proof out of the trie's proof buffers (values are filled by the caller).
fn proof_result(
    arena: std.mem.Allocator,
    target: *const trie_request.Proof,
    account: ?AccountState,
    account_proof: anytype,
    storage_proofs: anytype,
) error{OutOfMemory}!ProofResult {
    const storage = try arena.alloc(SlotProof, target.slots.len);
    for (storage, target.slots, 0..) |*slot, slot_key, index| {
        const proof = try nodes_of(arena, &storage_proofs[index]);
        slot.* = .{ .slot = slot_key, .value = 0, .proof = proof };
    }
    return .{
        .key = target.key,
        .account = account,
        .account_proof = try nodes_of(arena, account_proof),
        .storage = storage,
    };
}

fn nodes_of(arena: std.mem.Allocator, proof: anytype) error{OutOfMemory}![]const []const u8 {
    const nodes = try arena.alloc([]const u8, proof.count);
    for (nodes, 0..) |*item, index| {
        const start = if (index == 0) 0 else proof.ends[index - 1];
        item.* = try arena.dupe(u8, proof.buffer[start..proof.ends[index]]);
    }
    return nodes;
}

fn run_variants(
    state: *Run,
    block: *const Block,
    index: usize,
    parent: u64,
    named: []const Hash,
    writes_native: db.overlay.HashedWrites,
) void {
    for (&state.variants, 0..) |results, id_index| {
        const id: VariantId = @fromBackingInt(@intCast(id_index));
        results[index] = .{ .number = block.number };
        if (state.failed[id_index]) |text| {
            results[index].error_text = text;
            continue;
        }
        const outcome = switch (id) {
            .sparse => sparse_block(state, parent, named, writes_native),
            .state_trie => state_trie_block(state, block, named),
            .hash_builder => hash_builder_block(state, named),
            .node_address => address_block(state, block, parent, named),
        };
        results[index] = outcome catch |err| {
            const text = @errorName(err);
            state.failed[id_index] = text;
            results[index].error_text = text;
            continue;
        };
        results[index].number = block.number;
    }
}

fn sparse_block(
    state: *Run,
    parent: u64,
    named: []const Hash,
    writes: db.overlay.HashedWrites,
) anyerror!BlockResult {
    const sparse = state.sparse orelse return error.Unavailable;
    var result: BlockResult = .{ .number = 0 };
    result.state_root = try sparse.block(parent, writes);
    var roots: std.ArrayList(StorageRoot) = .empty;
    for (named) |*key| {
        const root = try sparse.storage_root(key) orelse continue;
        try roots.append(state.arena, .{ .key = key.*, .root = root });
    }
    result.storage_roots = roots.items;
    return result;
}

fn state_trie_block(state: *Run, block: *const Block, named: []const Hash) anyerror!BlockResult {
    const variant = if (state.state_trie) |*variant| variant else return error.Unavailable;
    try variant.apply(block.revert);
    try variant.apply(block.ops);
    var result: BlockResult = .{ .number = 0 };
    result.state_root = try variant.root();
    var roots: std.ArrayList(StorageRoot) = .empty;
    for (named) |*key| {
        const account = variant.account(key) orelse continue;
        try roots.append(state.arena, .{ .key = key.*, .root = account.storage_root });
    }
    result.storage_roots = roots.items;
    result.proofs = try state_trie_proofs(state, variant, block);
    return result;
}

fn state_trie_proofs(
    state: *Run,
    variant: *trie_variants.StateTrieVariant,
    block: *const Block,
) anyerror![]const ProofResult {
    const proofs = try state.arena.alloc(ProofResult, block.proofs.len);
    const account_proof = try state.allocator.create(trie_node.AccountProof);
    defer state.allocator.destroy(account_proof);
    const storage_proofs = try state.allocator.alloc(
        trie_node.StorageProof,
        trie_request.proof_slots_max,
    );
    defer state.allocator.free(storage_proofs);
    const state_trie = &variant.state_trie;
    for (block.proofs, proofs) |*target, *out| {
        try state_trie.prove_account(target.key, account_proof);
        for (target.slots, storage_proofs[0..target.slots.len]) |slot, *proof| {
            state_trie.prove_storage(target.key, slot, proof);
        }
        const account = variant.account(&target.key);
        out.* = try proof_result(state.arena, target, account, account_proof, storage_proofs);
        for (out.storage) |*slot| slot.value = state_trie.get_storage(target.key, slot.slot);
    }
    return proofs;
}

fn hash_builder_block(state: *Run, named: []const Hash) anyerror!BlockResult {
    var result: BlockResult = .{ .number = 0 };
    result.state_root = try state.model.state_root();
    var roots: std.ArrayList(StorageRoot) = .empty;
    for (named) |*key| {
        if (state.model.find(key) == null) continue;
        try roots.append(state.arena, .{ .key = key.*, .root = try state.model.storage_root(key) });
    }
    result.storage_roots = roots.items;
    return result;
}

/// `node-address`: the block by address through an `Overlay` into the in-memory node
/// state; a native unwind, else the revert and the ops as one block.
fn address_block(
    state: *Run,
    block: *const Block,
    parent: u64,
    named: []const Hash,
) anyerror!BlockResult {
    const node = state.address_node orelse return error.Unavailable;
    const native = try node.unwind_to(state.address_heights[@intCast(parent)]);
    if (!native) try overlay_ops(node, block.revert);
    try overlay_ops(node, block.ops);
    try node.commit_overlay();
    state.address_heights[@intCast(parent + 1)] = node.height;
    var result: BlockResult = .{ .number = 0, .state_root = node.state_root() };
    var roots: std.ArrayList(StorageRoot) = .empty;
    for (named) |*key| {
        const address = address_of(block, key).?;
        if (node.db.state.basic(address) == null) continue;
        const root = node.db.state.storage_root(address);
        try roots.append(state.arena, .{ .key = key.*, .root = root });
    }
    result.storage_roots = roots.items;
    result.proofs = try address_proofs(state, node, block);
    return result;
}

fn overlay_ops(node: *Node, ops: []const Op) anyerror!void {
    const overlay = &node.overlay;
    for (ops) |*op| {
        const address = op.address.?;
        switch (op.kind) {
            .account => try overlay.set_account(address, op.info),
            .storage => {
                const slot = std.mem.readInt(u256, &op.slot_key.?, .big);
                try overlay.set_storage(address, slot, op.value);
            },
            .wipe => if (overlay.basic(address) != null) try overlay.wipe_storage(address),
            .delete => if (overlay.basic(address) != null) try overlay.set_account(address, null),
        }
    }
}

/// The preimage of a key the block names (every op carries one on these requests).
fn address_of(block: *const Block, key: *const Hash) ?[20]u8 {
    for ([2][]const Op{ block.revert, block.ops }) |ops| {
        for (ops) |*op| if (std.mem.eql(u8, &op.key, key)) return op.address;
    }
    return null;
}

fn address_proofs(state: *Run, node: *Node, block: *const Block) anyerror![]const ProofResult {
    const proofs = try state.arena.alloc(ProofResult, block.proofs.len);
    const account_proof = try state.allocator.create(trie_node.AccountProof);
    defer state.allocator.destroy(account_proof);
    const storage_proofs = try state.allocator.alloc(
        trie_node.StorageProof,
        trie_request.proof_slots_max,
    );
    defer state.allocator.free(storage_proofs);
    var slots: [trie_request.proof_slots_max]u256 = undefined;
    var values: [trie_request.proof_slots_max]u256 = undefined;
    for (block.proofs, proofs) |*target, *out| {
        const count = target.slots.len;
        for (target.slot_keys.?, slots[0..count]) |*key, *slot| {
            slot.* = std.mem.readInt(u256, key, .big);
        }
        const account = try node.db.proof_at(
            node.db.head_info.number,
            target.address.?,
            slots[0..count],
            account_proof,
            storage_proofs[0..count],
            values[0..count],
        );
        out.* = try proof_result(state.arena, target, account, account_proof, storage_proofs);
        for (out.storage, values[0..count]) |*slot, value| slot.value = value;
    }
    return proofs;
}

// The response.

pub fn write(
    out: *Writer,
    id: ?[]const u8,
    outcome: *const Outcome,
    coverage: ?*const Coverage,
) Writer.Error!void {
    try out.writeAll("{\"id\":");
    try response.write_string_or_null(out, id);
    try out.writeAll(",\"ok\":true,\"blocks\":[");
    for (outcome.blocks, 0..) |*result, index| {
        if (index > 0) try out.writeAll(",");
        try write_block(out, result);
    }
    try out.writeAll("],\"variants\":{");
    for (outcome.variants, 0..) |*variant, index| {
        if (index > 0) try out.writeAll(",");
        try std.json.Stringify.encodeJsonString(variant.name, .{}, out);
        try out.writeAll(":[");
        for (variant.blocks, 0..) |*result, block_index| {
            if (block_index > 0) try out.writeAll(",");
            try write_block(out, result);
        }
        try out.writeAll("]");
    }
    try out.writeAll("}");
    if (coverage) |features| try features.write_trie(out);
    try out.writeAll("}");
}

fn write_block(out: *Writer, result: *const BlockResult) Writer.Error!void {
    try out.writeAll("{\"number\":");
    try response.quantity(out, result.number);
    if (result.error_text) |text| {
        try out.writeAll(",\"error\":");
        try std.json.Stringify.encodeJsonString(text, .{}, out);
        return out.writeAll("}");
    }
    if (result.state_root) |root| {
        try out.writeAll(",\"stateRoot\":");
        try response.data(out, &root);
    }
    if (result.storage_roots) |roots| {
        try out.writeAll(",\"storageRoots\":{");
        for (roots, 0..) |*entry, index| {
            if (index > 0) try out.writeAll(",");
            try response.data(out, &entry.key);
            try out.writeAll(":");
            try response.data(out, &entry.root);
        }
        try out.writeAll("}");
    }
    if (result.proofs) |proofs| {
        try out.writeAll(",\"proofs\":[");
        for (proofs, 0..) |*proof, index| {
            if (index > 0) try out.writeAll(",");
            try write_proof(out, proof);
        }
        try out.writeAll("]");
    }
    try out.writeAll("}");
}

fn write_proof(out: *Writer, proof: *const ProofResult) Writer.Error!void {
    try out.writeAll("{\"key\":");
    try response.data(out, &proof.key);
    try out.writeAll(",\"account\":");
    if (proof.account) |account| {
        try out.writeAll("{\"nonce\":");
        try response.quantity(out, account.nonce);
        try out.writeAll(",\"balance\":");
        try response.quantity(out, account.balance);
        try out.writeAll(",\"codeHash\":");
        try response.data(out, &account.code_hash);
        try out.writeAll(",\"storageRoot\":");
        try response.data(out, &account.storage_root);
        try out.writeAll("}");
    } else try out.writeAll("null");
    try out.writeAll(",\"accountProof\":");
    try write_nodes(out, proof.account_proof);
    try out.writeAll(",\"storage\":[");
    for (proof.storage, 0..) |*slot, index| {
        if (index > 0) try out.writeAll(",");
        var value: Hash = undefined;
        std.mem.writeInt(u256, &value, slot.value, .big);
        try out.writeAll("{\"slot\":");
        try response.data(out, &slot.slot);
        try out.writeAll(",\"value\":");
        try response.data(out, &value);
        try out.writeAll(",\"proof\":");
        try write_nodes(out, slot.proof);
        try out.writeAll("}");
    }
    try out.writeAll("]}");
}

fn write_nodes(out: *Writer, nodes: []const []const u8) Writer.Error!void {
    try out.writeAll("[");
    for (nodes, 0..) |item, index| {
        if (index > 0) try out.writeAll(",");
        try response.data(out, item);
    }
    try out.writeAll("]");
}
