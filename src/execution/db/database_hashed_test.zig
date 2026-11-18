//! Hashed changesets in disk mode (`Changeset.hashed`, `overlay.build_hashed_changeset`):
//! the same random blocks go to two disk-mode databases on `SimStorage`, one through the
//! node's address-keyed path (`Overlay`, `execute_and_commit`), the other as writes in
//! hashed key space (a hashed changeset built from trie-key reads, `State.apply` into the
//! trees, `commit_applied`), the way `StateDb.commit_hashed` commits. After every block,
//! native unwind (`set_head`) and reopen (journal replay of the hashed changesets) both
//! have the same state root and read the same account records and slots by trie key.

const std = @import("std");
const assert = std.debug.assert;
const testing = std.testing;

const database = @import("database.zig");
const disk_test = @import("database_disk_test.zig");
const SimStorage = @import("storage/sim_storage.zig").SimStorage;
const overlay_module = @import("overlay.zig");
const changeset_module = @import("changeset.zig");
const state_module = @import("state.zig");
const Prng = @import("../../testing/prng.zig").Prng;
const keccak256 = @import("../trie/node.zig").keccak256;

const Hash = database.Hash;
const Node = disk_test.Node;
const Address = state_module.Address;
const AccountInfo = state_module.AccountInfo;
const State = state_module.State;

const addresses_max = 8;
const slots_max = 4;
const blocks_max = 48;

/// Trie-key reads of a disk-mode state, for `build_hashed_changeset`.
const Reader = struct {
    state: *const State,

    pub const Error = error{};

    pub fn account(reader: Reader, key: *const Hash) Reader.Error!?AccountInfo {
        const record = reader.state.account_hashed(key) orelse return null;
        return record.info;
    }

    pub fn storage(reader: Reader, key: *const Hash, slot: *const Hash) Reader.Error!u256 {
        return reader.state.storage_hashed(key, slot);
    }
};

fn slot_hash(slot: u64) Hash {
    var bytes: Hash = @splat(0);
    std.mem.writeInt(u64, bytes[24..32], slot, .big);
    return keccak256(&bytes);
}

const Pair = struct {
    address: Node,
    hashed: Node,
    changeset: changeset_module.Changeset,
    buffer: []u8,
    /// Block ids of the canonical chain by height.
    heights: [blocks_max + 1]u32 = undefined,
    height: u32 = 0,
    next_id: u32 = 1,
    header: [8]u8 = undefined,

    fn input(pair: *Pair, id: u32, parent: u32, number: u64) database.BlockInput {
        std.mem.writeInt(u64, &pair.header, id, .big);
        return .{
            .hash = disk_test.hash_of(id),
            .parent_hash = if (number == 0) @splat(0) else disk_test.hash_of(parent),
            .number = number,
            .timestamp = number,
            .header = &pair.header,
            .body = "",
            .receipts = "",
            .transaction_hashes = &.{},
            .changeset = "",
        };
    }

    /// Random ops into the address side's overlay; the touched addresses and slots.
    fn random_ops(pair: *Pair, prng: *Prng, touched: *[addresses_max]u8) !void {
        const overlay = &pair.address.overlay;
        for (0..prng.range(1, 8)) |_| {
            const index = prng.below(addresses_max);
            const address = disk_test.address_of(index);
            const exists = overlay.basic(address) != null;
            const choice = prng.below(8);
            if (choice < 4 and exists) {
                const slot = prng.below(slots_max);
                const value: u256 = if (prng.chance(1, 3)) 0 else prng.range(1, 1 << 30);
                try overlay.set_storage(address, slot, value);
                touched[index] |= @as(u8, 1) << @intCast(slot);
                touched[index] |= 0x80;
            } else if (choice == 7 and exists) {
                // Disk mode refuses to destroy an account with committed storage.
                if (pair.address.db.state.has_storage(address)) continue;
                try overlay.set_account(address, null);
                touched[index] |= 0x80;
            } else {
                const info: AccountInfo = .{ .nonce = prng.range(1, 4), .balance = prng.below(9) };
                try overlay.set_account(address, info);
                touched[index] |= 0x80;
            }
        }
    }

    /// The address side's post-state of what `touched` names, as hashed writes.
    fn writes(
        pair: *Pair,
        touched: *const [addresses_max]u8,
        accounts: []overlay_module.HashedAccountWrite,
        slots: []overlay_module.HashedSlotWrite,
    ) overlay_module.HashedWrites {
        var accounts_len: usize = 0;
        var slots_len: usize = 0;
        const state = &pair.address.db.state;
        for (touched, 0..) |mask, index| {
            if (mask == 0) continue;
            const address = disk_test.address_of(index);
            const key = keccak256(&address);
            accounts[accounts_len] = .{ .key = key, .info = state.basic(address) };
            accounts_len += 1;
            for (0..slots_max) |slot| {
                if (mask & (@as(u8, 1) << @intCast(slot)) == 0) continue;
                const value = state.storage(address, slot);
                slots[slots_len] = .{ .key = key, .slot = slot_hash(slot), .value = value };
                slots_len += 1;
            }
        }
        sort_writes(accounts[0..accounts_len], slots[0..slots_len]);
        return .{ .accounts = accounts[0..accounts_len], .slots = slots[0..slots_len] };
    }

    fn block(pair: *Pair, prng: *Prng) !void {
        var touched: [addresses_max]u8 = @splat(0);
        try pair.random_ops(prng, &touched);
        const id = pair.next_id;
        pair.next_id += 1;
        const parent = pair.heights[pair.height];
        var block_input = pair.input(id, parent, pair.height + 1);
        _ = try pair.address.commit_retry(&block_input);
        var accounts: [addresses_max]overlay_module.HashedAccountWrite = undefined;
        var slots: [addresses_max * slots_max]overlay_module.HashedSlotWrite = undefined;
        const hashed_writes = pair.writes(&touched, &accounts, &slots);
        try pair.commit_hashed(hashed_writes, &block_input);
        pair.height += 1;
        pair.heights[pair.height] = id;
        try pair.expect_same();
    }

    /// `StateDb.commit_hashed` then `commit_applied`, retried while the trees are busy.
    fn commit_hashed(
        pair: *Pair,
        hashed_writes: overlay_module.HashedWrites,
        block_input: *database.BlockInput,
    ) !void {
        const db = &pair.hashed.db;
        var ticks: u32 = 0;
        while (ticks < 100_000) : (ticks += 1) {
            const reader: Reader = .{ .state = &db.state };
            try overlay_module.build_hashed_changeset(reader, hashed_writes, &pair.changeset);
            try testing.expect(pair.changeset.hashed);
            db.state.apply(&pair.changeset) catch |err| switch (err) {
                error.Busy => {
                    pair.hashed.sim.tick();
                    continue;
                },
                else => return err,
            };
            block_input.changeset = pair.changeset.encode(pair.buffer);
            _ = db.commit_applied(block_input) catch |err| switch (err) {
                error.Busy => {
                    try db.state.unwind(&pair.changeset);
                    pair.hashed.sim.tick();
                    continue;
                },
                else => return err,
            };
            return;
        }
        return error.Timeout;
    }

    fn expect_same(pair: *Pair) !void {
        const a = &pair.address.db;
        const b = &pair.hashed.db;
        try testing.expectEqualSlices(u8, &a.head_info.state_root, &b.head_info.state_root);
        for (0..addresses_max) |index| {
            const address = disk_test.address_of(index);
            const key = keccak256(&address);
            const info = a.state.basic(address);
            const record = b.state.account_hashed(&key);
            try testing.expectEqual(info == null, record == null);
            if (info) |want| try testing.expect(want.eql(record.?.info));
            for (0..slots_max) |slot| {
                const want = a.state.storage(address, slot);
                try testing.expectEqual(want, b.state.storage_hashed(&key, &slot_hash(slot)));
            }
        }
    }
};

const AccountWrite = overlay_module.HashedAccountWrite;
const SlotWrite = overlay_module.HashedSlotWrite;

fn account_less_than(_: void, x: AccountWrite, y: AccountWrite) bool {
    return std.mem.order(u8, &x.key, &y.key) == .lt;
}

fn slot_less_than(_: void, x: SlotWrite, y: SlotWrite) bool {
    const order = std.mem.order(u8, &x.key, &y.key);
    if (order != .eq) return order == .lt;
    return std.mem.order(u8, &x.slot, &y.slot) == .lt;
}

fn sort_writes(accounts: []AccountWrite, slots: []SlotWrite) void {
    std.mem.sort(AccountWrite, accounts, {}, account_less_than);
    std.mem.sort(SlotWrite, slots, {}, slot_less_than);
}

/// Ticks until every entry is durable and nothing is in flight (a clean stop: reopening
/// then replays the journal written since the last checkpoint).
fn settle(node: *Node) !void {
    var ticks: u32 = 0;
    while (node.db.durable_sequence < node.db.submitted_sequence or !node.db.idle()) {
        if (ticks >= 100_000) return error.Timeout;
        node.sim.tick();
        ticks += 1;
    }
    assert(node.db.durable_sequence == node.db.submitted_sequence);
}

fn run_seed(seed: u64) !void {
    var prng = Prng.init(0x4a5e_d000 + seed);
    const size = disk_test.config_disk.engine.size_bytes();
    var sim_a = try SimStorage.init(testing.allocator, .{ .size_bytes = size, .seed = seed });
    defer sim_a.deinit(testing.allocator);
    var sim_b = try SimStorage.init(testing.allocator, .{ .size_bytes = size, .seed = seed + 7 });
    defer sim_b.deinit(testing.allocator);
    const pair = try testing.allocator.create(Pair);
    defer testing.allocator.destroy(pair);
    const config = disk_test.config_disk.changeset;
    pair.* = .{
        .address = undefined,
        .hashed = undefined,
        .changeset = try changeset_module.Changeset.init(testing.allocator, config),
        .buffer = try testing.allocator.alloc(u8, disk_test.config_disk.engine.entry_body_size_max),
    };
    defer testing.allocator.free(pair.buffer);
    defer pair.changeset.deinit(testing.allocator);
    try pair.address.init(&sim_a, disk_test.config_disk);
    defer pair.address.deinit();
    try pair.hashed.init(&sim_b, disk_test.config_disk);
    defer pair.hashed.deinit();
    try pair.address.format(0x4a5e + seed);
    try pair.hashed.format(0x4a5f + seed);
    var genesis = pair.input(0, 0, 0);
    _ = try pair.address.commit_retry(&genesis);
    _ = try pair.hashed.commit_retry(&genesis);
    pair.heights[0] = 0;
    while (pair.height < blocks_max) {
        try pair.block(&prng);
        if (prng.chance(1, 6) and pair.height > 1) {
            // A native unwind on both: `set_head` unwinds the stored changesets.
            const depth = prng.range(1, @min(pair.height, 3));
            pair.height -= @intCast(depth);
            const hash = disk_test.hash_of(pair.heights[pair.height]);
            try pair.address.set_head_retry(hash);
            try pair.hashed.set_head_retry(hash);
            try pair.expect_same();
        }
        if (prng.chance(1, 10)) {
            // A restart: the journal's hashed changesets replay through the same paths.
            if (prng.chance(1, 2)) try pair.hashed.checkpoint();
            try settle(&pair.hashed);
            try pair.hashed.reopen();
            try pair.expect_same();
        }
    }
}

test "database hashed changesets: disk mode commits, unwinds and replays them like addresses" {
    for (0..4) |seed| {
        run_seed(seed) catch |err| {
            std.debug.print("database hashed changesets: failing seed={d}\n", .{seed});
            return err;
        };
    }
}
