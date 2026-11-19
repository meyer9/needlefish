//! The trie mode's on-disk databases: needlefish's `db.database` over a file in the
//! request's `trie.dir`, through the storage engine (`IoStorageType` over `file_io.zig`).
//!
//! - `.disk` (the primary): disk mode (`Config.disk_state`), the state in `DiskState` over
//!   the four flat trees, as `base el-run` runs it (`import/run.zig`). A block is committed
//!   as the runner commits an executed one: the writes go through `StateDb` (here
//!   `commit_hashed`, which builds a hashed changeset and `State.apply`s it into the trees)
//!   and the block is journaled with `commit_applied`; a refused (busy) block is rolled
//!   back and retried after the storage quiets down. Proofs are `Database.proof_hashed`
//!   (eth_getProof's disk walk). Unwinds are native: `set_head` to the ancestor, which
//!   unwinds the stored changesets.
//! - `.disk_small` (`disk-small`): the same, over `config_disk_small` (the smallest sizes the
//!   node's code allows), so a request of tens of blocks reaches flushes, merges, checkpoints
//!   and cache evictions; `reopen` restarts it from its file (cleanly or as a crash).
//! - `.disk_deep` (`disk-deep`): the same over `config_disk_deep` (entries of 8 + 8 writes, a
//!   three-block chain); `commit_split` commits a block's writes as that many blocks.
//! - `.memory` (`node-address`): the durable node's in-memory state (`State` tables and
//!   `StateTrie`), keyed by address; blocks go through an `Overlay` and
//!   `execute_and_commit`; proofs through `proof_at` at the head (eth_getProof's live path).
//!
//! Every operation is driven until it is durable before the next one, so the storage
//! engine's work is a function of the request alone.

const std = @import("std");
const assert = std.debug.assert;

const db = @import("../../execution/db/root.zig");
const trie = @import("../../execution/trie/root.zig");
const state_db_module = @import("../../execution/node/state_db.zig");
const room_module = @import("../../execution/import/room.zig");
const to_disk = @import("../../execution/import/to_disk.zig");
const io_storage = @import("../../execution/db/storage/io_storage.zig");
const branch_record = @import("../../execution/db/branch_record.zig");
const sector_size = @import("../../execution/db/storage/storage.zig").sector_size;
const table_module = @import("../../execution/db/storage/table.zig");
const record_cache = @import("../../execution/db/record_cache.zig");
const FileIo = @import("file_io.zig").FileIo;
const OpenMode = @import("../../utilities/io/common.zig").OpenMode;

const database = db.database;
const Hash = [32]u8;
const Address = [20]u8;
const StateDb = state_db_module.StateDb;
const HashedWrites = db.overlay.HashedWrites;
const HashedSlotWrite = db.overlay.HashedSlotWrite;

pub const Storage = io_storage.IoStorageType(FileIo);
pub const Database = database.DatabaseType(Storage);
const Room = room_module.RoomType(Database);
pub const AccountProof = trie.StateTrie.AccountProof;
pub const StorageProof = trie.StateTrie.StorageProof;
pub const AccountState = db.history.AccountState;

pub const Mode = enum { disk, disk_small, disk_deep, memory };

/// Blocks a request may hold (the chain index by height).
pub const blocks_max = 256;
/// Unwinds deeper than this (or below the retained blocks) are not native.
pub const reorg_depth_max = 8;
/// Ticks one wait may take.
const ticks_max = 1 << 20;
/// Busy retries of one block.
const attempts_max = 16;

const block_size: u32 = 4 * sector_size;
const record_writes_max: u32 = 4096;

pub const changeset_config: db.changeset.Config = .{
    .accounts_max = 2048,
    .storage_max = 8192,
    .codes_max = 1,
    .code_bytes_max = 1024,
};

const engine_config: @import("../../execution/db/storage/engine.zig").Config = .{
    .journal_size_bytes = 32 << 20,
    .checkpoint_zone_size_bytes = 1024 * block_size,
    .entry_body_size_max = 2 << 20,
    .checkpoint_block_size = block_size,
    .grid_block_count = 1 << 14,
};

const chain_config: db.chain.Config = .{
    .blocks_max = blocks_max,
    .bytes_max = 64 << 20,
    .transactions_max = 1,
    .canonical_max = 1024,
    .reorg_depth_max = reorg_depth_max,
};

pub const config_disk: database.Config = .{
    .engine = engine_config,
    // Disk mode keeps only codes and block hashes in RAM.
    .state = .{
        .accounts_max = 4,
        .storage_slots_max = 4,
        .codes_max = 4,
        .code_bytes_max = 4096,
        .account_nodes_max = 64,
        .storage_nodes_max = 64,
    },
    .chain = chain_config,
    .changeset = changeset_config,
    .queue_entries_max = 4,
    .checkpoint_staging_bytes = 16 << 20,
    .flat_trees = true,
    .flat_flush_entries_min = 4096,
    .flat_cache_blocks = 256,
    .flat_accounts_max = 1 << 16,
    .flat_slots_max = 1 << 18,
    .flat_account_branches_max = 1 << 16,
    .flat_storage_branches_max = 1 << 18,
    .flat_branch_flush_entries_min = 1024,
    .disk_state = .{
        .trie_nodes_max = 1 << 17,
        .storage_tries_max = 4096,
        .memo_entries_max = 1 << 17,
        .memo_bytes_max = 32 << 20,
        .record_writes_max = record_writes_max,
        .record_write_bytes_max = record_writes_max * branch_record.value_bytes_max,
        // The smallest the config allows: one largest move.
        .replay_record_writes_max = record_writes_max * (2 * reorg_depth_max + 1),
        .record_cache_entries = 1024,
    },
};

/// `disk-small`: `config_disk` at the smallest sizes the node's code allows, so a request
/// of tens of blocks reaches what the primary's sizes put off past it: memtable flushes into
/// tables (a flush minimum of one), merges, checkpoints (a journal of two largest entries:
/// `Room` finds it short before every block and checkpoints), and cache evictions. The
/// per-block bounds (changeset, `DiskState` work, record writes) and the key bounds that
/// size the levels stay `config_disk`'s, so it takes every block the primary does.
const small_block_size: u32 = sector_size;
/// One largest block entry: a header, and a changeset at `changeset_config`'s limits.
const small_entry_body_bytes: u32 = blk: {
    const body = database.block_entry_fixed_size + 16 +
        db.changeset.encoded_length_max(changeset_config);
    break :blk @intCast(std.mem.alignForward(u64, body, sector_size));
};
/// A checkpoint at most: every retained block (`Database.chain_bytes_capacity`) and 16 MiB.
const small_checkpoint_bytes: u64 =
    @as(u64, chain_config.bytes_max) + 3 * @as(u64, small_entry_body_bytes) + (16 << 20);

pub const config_disk_small: database.Config = blk: {
    var config = config_disk;
    config.engine = .{
        // The journal's smallest (`journal.zig` init): two largest entries.
        .journal_size_bytes = 2 * (sector_size + @as(u64, small_entry_body_bytes)),
        // The zone holds a checkpoint (it does not set how often one runs).
        .checkpoint_zone_size_bytes = small_checkpoint_bytes,
        .entry_body_size_max = small_entry_body_bytes,
        .checkpoint_block_size = small_block_size,
        .grid_block_count = 1 << 14,
    };
    // The chain retention stays the primary's: retained blocks are evicted oldest-inserted
    // first, so after unwinds to one ancestor its side blocks could outlive it, and fewer
    // retained blocks could evict a block's parent (`UnknownParent`). A checkpoint holds the
    // retained blocks, and one block's memtable entries with room to spare.
    config.checkpoint_staging_bytes = small_checkpoint_bytes;
    config.queue_entries_max = 1;
    // A checkpoint writes this much per commit, and compaction runs on the same budget, so
    // merges span blocks and checkpoints.
    config.checkpoint_bytes_per_commit = 64 * small_block_size;
    config.flat_flush_entries_min = 1;
    config.flat_branch_flush_entries_min = 1;
    config.flat_cache_blocks = table_module.BlockCache.ways;
    config.disk_state.?.record_cache_entries = record_cache.ways;
    break :blk config;
};

comptime {
    assert(small_entry_body_bytes <= config_disk.engine.entry_body_size_max);
    assert(config_disk_small.engine.checkpoint_zone_size_bytes % small_block_size == 0);
    assert(config_disk_small.chain_bytes_capacity() < config_disk_small.checkpoint_staging_bytes);
}

/// `disk-deep`: `config_disk_small` with blocks of at most this many account and slot writes:
/// a request block is committed as that many database blocks as it takes (`commit_split`).
pub const deep_chunk_accounts = 8;
pub const deep_chunk_slots = 8;

const deep_changeset_config: db.changeset.Config = .{
    .accounts_max = deep_chunk_accounts,
    .storage_max = deep_chunk_slots,
    .codes_max = 1,
    .code_bytes_max = 1,
};
const deep_entry_body_bytes: u32 = blk: {
    const body = database.block_entry_fixed_size + 16 +
        db.changeset.encoded_length_max(deep_changeset_config);
    break :blk @intCast(std.mem.alignForward(u64, body, sector_size));
};
/// The fewest blocks retained with no native unwind: the head, its child and one more.
const deep_chain_blocks = 3;

/// The flat trees' memtables keep room for a replay of the journal and the retained chain,
/// and level 1 holds four memtables, each next level eight times more: so the smaller the
/// largest entry, the shallower the levels. With entries of 8 + 8 writes level 1 holds about
/// 1.5k storage (2k account) records and level 2 eight times that, which a request of tens of
/// blocks of hundreds of writes passes. The chain retains three blocks, so every insert
/// evicts the oldest (`evict_oldest`); unwinds are therefore never native (the chain is one
/// branch, and no block's parent is ever evicted).
pub const config_disk_deep: database.Config = blk: {
    var config = config_disk_small;
    config.engine.journal_size_bytes = 2 * (sector_size + @as(u64, deep_entry_body_bytes));
    config.engine.entry_body_size_max = deep_entry_body_bytes;
    config.chain = .{
        .blocks_max = deep_chain_blocks,
        .bytes_max = deep_chain_blocks * deep_entry_body_bytes,
        .transactions_max = 1,
        .canonical_max = 2,
        .reorg_depth_max = 1,
    };
    config.changeset = deep_changeset_config;
    const disk = &config.disk_state.?;
    disk.replay_record_writes_max = disk.record_writes_max * config.move_blocks_max();
    break :blk config;
};

comptime {
    assert(deep_entry_body_bytes < small_entry_body_bytes);
    assert(config_disk_deep.chain.canonical_max > config_disk_deep.chain.reorg_depth_max);
}

/// The in-memory state of a durable node without a grid (journal and checkpoints only).
pub const config_memory: database.Config = .{
    .engine = blk: {
        var engine = engine_config;
        engine.grid_block_count = 0;
        break :blk engine;
    },
    .state = .{
        .accounts_max = 1 << 14,
        .storage_slots_max = 1 << 16,
        .codes_max = 4,
        .code_bytes_max = 4096,
        .account_nodes_max = 1 << 16,
        .storage_nodes_max = 1 << 18,
    },
    .chain = chain_config,
    .changeset = changeset_config,
    .queue_entries_max = 4,
    .checkpoint_staging_bytes = 64 << 20,
};

const overlay_config: db.overlay.Config = .{
    .accounts_max = changeset_config.accounts_max,
    .slots_max = changeset_config.storage_max,
    .codes_max = 1,
};

pub const Error = error{ NodeFailed, Stalled } || database.OperationError ||
    state_db_module.Error || db.overlay.Error || database.ProofError;

pub const Node = struct {
    allocator: std.mem.Allocator,
    mode: Mode,
    io: FileIo = .{},
    fd: FileIo.Fd,
    storage: Storage,
    db: Database,
    /// Disk mode: the runner's `StateDb` over the database's state.
    state_db: StateDb,
    /// Memory mode: the block's writes by address.
    overlay: db.Overlay,
    /// The database file (it outlives the node: `reopen`).
    path: []const u8,
    /// Block hashes of the canonical chain by height modulo the ring (genesis at 0): the
    /// newest `blocks_max + 1`, more than an unwind reaches.
    hashes: [blocks_max + 1]Hash = undefined,
    height: u64 = 0,
    /// Blocks made so far (side blocks too): each gets a unique header.
    blocks_made: u64 = 0,
    room: room_module.Stats = .{},
    stats: Stats = .{},
    /// The headers of the block being committed and the one before (alternating).
    header_bytes: [2][16]u8 = undefined,

    /// Restarts and their opens (`reopen`).
    pub const Stats = struct {
        reopens_clean: u64 = 0,
        reopens_crash: u64 = 0,
        /// Crashes that dropped a checkpoint being written.
        crashes_mid_checkpoint: u64 = 0,
        /// Opens that loaded a checkpoint, that loaded the fallback one, and the journal
        /// entries they replayed.
        checkpoint_loads: u64 = 0,
        checkpoint_fallbacks: u64 = 0,
        entries_replayed: u64 = 0,
        /// Crash reopens that replayed journal entries.
        crash_replays: u64 = 0,
        /// Database blocks committed (`commit_split` makes several per request block).
        commits: u64 = 0,
    };

    fn config_of(mode: Mode) database.Config {
        return switch (mode) {
            .disk => config_disk,
            .disk_small => config_disk_small,
            .disk_deep => config_disk_deep,
            .memory => config_memory,
        };
    }

    /// Opens (or creates) the database file at `path` and builds everything over it.
    /// Heap-pinned: the storage and state point into it.
    fn init(
        allocator: std.mem.Allocator,
        mode: Mode,
        path: []const u8,
        open_mode: OpenMode,
    ) !*Node {
        const self = try allocator.create(Node);
        errdefer allocator.destroy(self);
        const config = config_of(mode);
        self.* = .{
            .allocator = allocator,
            .mode = mode,
            .path = path,
            .fd = undefined,
            .storage = undefined,
            .db = undefined,
            .state_db = undefined,
            .overlay = undefined,
        };
        self.fd = try self.io.open_file(path, open_mode);
        errdefer self.io.close_now(self.fd);
        const size_bytes = config.engine.size_bytes();
        const options: io_storage.Options = .{ .size_bytes = size_bytes };
        self.storage = try Storage.init(allocator, &self.io, self.fd, options);
        errdefer self.storage.deinit(allocator);
        self.db = try Database.init(allocator, &self.storage, config);
        errdefer self.db.deinit(allocator);
        const state_config = state_db_config(config.changeset);
        self.state_db = try StateDb.init_shared(allocator, state_config, &self.db.state);
        errdefer self.state_db.deinit(allocator);
        self.overlay = try db.Overlay.init(allocator, &self.db.state, overlay_config);
        return self;
    }

    /// `init` and `start`: a database ready at its genesis, or nothing.
    pub fn create(allocator: std.mem.Allocator, mode: Mode, path: []const u8) !*Node {
        const self = try init(allocator, mode, path, .create);
        self.start() catch |err| {
            self.destroy();
            return err;
        };
        assert(self.height == 0 and self.db.head_info.present);
        return self;
    }

    pub fn destroy(self: *Node) void {
        // The storage must hold no operation in flight: finish what was started, a paced
        // checkpoint unpaced (no commit grants it more).
        var ticks: u32 = 0;
        while (ticks < ticks_max and (!self.storage.idle() or self.draining())) : (ticks += 1) {
            self.db.checkpoint_flush();
            self.tick();
        }
        self.release();
    }

    /// Frees everything; operations still queued are dropped (`FileIo.close_now`).
    fn release(self: *Node) void {
        const allocator = self.allocator;
        self.overlay.deinit(allocator);
        self.state_db.deinit(allocator);
        self.db.deinit(allocator);
        self.storage.deinit(allocator);
        self.io.close_now(self.fd);
        allocator.destroy(self);
    }

    /// Restarts the database from its file: closes it cleanly (`crash_ticks` null: a
    /// checkpoint asked for and written, everything finished, so open loads it) or as a
    /// crash (a checkpoint asked for, `crash_ticks` storage ticks, then everything in flight
    /// dropped with the process: open loads the newest complete checkpoint and replays the
    /// journal after it), then opens it again at the same head. Returns the reopened node;
    /// `self` is gone (on failure too).
    pub fn reopen(self: *Node, crash_ticks: ?u32) Error!*Node {
        assert(self.mode != .memory);
        const allocator = self.allocator;
        const mode = self.mode;
        const path = self.path;
        const kept = .{ self.hashes, self.height, self.blocks_made, self.room };
        var stats = self.stats;
        const crash = crash_ticks != null;
        if (crash_ticks) |ticks| {
            stats.reopens_crash += 1;
            self.db.request_checkpoint();
            for (0..ticks) |_| {
                self.db.checkpoint_flush();
                self.tick();
            }
            if (self.db.engine.checkpoint_phase != .idle) stats.crashes_mid_checkpoint += 1;
            self.release();
        } else {
            stats.reopens_clean += 1;
            const closed = self.shutdown();
            self.release();
            try closed;
        }
        const node = init(allocator, mode, path, .read_write) catch return error.NodeFailed;
        errdefer node.release();
        node.hashes, node.height, node.blocks_made, node.room = kept;
        const replayed = stats.entries_replayed;
        try node.open_existing(&stats);
        if (crash and stats.entries_replayed > replayed) stats.crash_replays += 1;
        node.stats = stats;
        assert(node.height == node.db.head_info.number);
        return node;
    }

    /// A clean close: a checkpoint written, and nothing left in flight.
    fn shutdown(self: *Node) Error!void {
        self.db.request_checkpoint();
        var ticks: u32 = 0;
        while (self.db.checkpoint_wanted or self.draining() or !self.storage.idle()) {
            if (ticks >= ticks_max) return error.Stalled;
            ticks += 1;
            self.db.checkpoint_flush();
            self.tick();
        }
        if (self.db.checkpoint_error != null) return error.NodeFailed;
        assert(self.db.durable_sequence == self.db.submitted_sequence);
    }

    /// Opens the database on its file and checks it is at the head it was closed at
    /// (everything committed was durable).
    fn open_existing(self: *Node, stats: *Stats) Error!void {
        self.db.open();
        try self.tick_while(opening);
        if (self.db.open_error != null or self.db.phase != .ready) return error.NodeFailed;
        const result = self.db.engine.open_result catch return error.NodeFailed;
        if (result.checkpoint.size_bytes > 0) stats.checkpoint_loads += 1;
        if (result.checkpoint_fallback) stats.checkpoint_fallbacks += 1;
        stats.entries_replayed += result.entries_replayed;
        const head = self.db.head_info;
        if (!head.present or head.number != self.height) return error.NodeFailed;
        const hash = self.hash_at(self.height);
        if (!std.mem.eql(u8, &head.hash, &hash)) return error.NodeFailed;
    }

    /// A ready database with a commit or a checkpoint still going.
    fn draining(self: *const Node) bool {
        if (self.db.phase != .ready) return false;
        return !self.db.idle() or self.db.engine.checkpoint_phase != .idle;
    }

    fn state_db_config(changeset: db.changeset.Config) state_db_module.Config {
        const undo_bytes = 4 * changeset.storage_max * 128 + (1 << 20);
        return .{
            .block_accounts_max = changeset.accounts_max,
            .block_slots_max = changeset.storage_max,
            .block_codes_max = changeset.codes_max,
            .block_code_bytes_max = changeset.code_bytes_max,
            .undo_bytes_max = undo_bytes,
            .undo_blocks_max = 2,
        };
    }

    /// Formats and opens the database, and commits an empty genesis block at height 0.
    fn start(self: *Node) Error!void {
        self.db.format(0x7472_6965 + @as(u128, @backingInt(self.mode)));
        try self.tick_while(formatting);
        self.db.open();
        try self.tick_while(opening);
        if (self.db.open_error != null or self.db.phase != .ready) return error.NodeFailed;
        var genesis = self.block_input(@splat(0), 0);
        const commit = try self.db.execute_and_commit(&self.state_db.overlay, &genesis);
        try self.settle();
        self.hash_set(0, genesis.hash);
        assert(commit.sequence == self.db.submitted_sequence);
    }

    fn formatting(node: *const Node) bool {
        return node.db.phase == .formatting;
    }

    fn opening(node: *const Node) bool {
        return node.db.phase == .opening;
    }

    fn unsettled(node: *const Node) bool {
        const database_ = &node.db;
        if (database_.phase != .ready) return false;
        if (database_.durable_sequence < database_.submitted_sequence) return true;
        if (database_.idle()) return false;
        // A paced checkpoint waiting for the next commits' grants (disk-small) goes on with
        // them; anything else in flight finishes now.
        return !(database_.engine.checkpoint_paused() and node.storage.idle());
    }

    pub fn tick(self: *Node) void {
        self.storage.tick();
    }

    fn tick_while(self: *Node, comptime busy: fn (*const Node) bool) Error!void {
        var ticks: u32 = 0;
        while (busy(self)) : (ticks += 1) {
            if (ticks >= ticks_max) return error.Stalled;
            self.tick();
        }
        assert(!busy(self));
    }

    /// Ticks until everything submitted is durable and nothing is in flight.
    fn settle(self: *Node) Error!void {
        try self.tick_while(unsettled);
        if (self.db.phase != .ready) return error.NodeFailed;
        assert(self.db.durable_sequence == self.db.submitted_sequence);
    }

    /// A unique header (opaque bytes to the database) and its hash.
    fn block_input(self: *Node, parent_hash: Hash, number: u64) database.BlockInput {
        var header: [16]u8 = undefined;
        @memcpy(header[0..8], "nf-trie\x00");
        std.mem.writeInt(u64, header[8..16], self.blocks_made, .big);
        self.blocks_made += 1;
        const header_stored = self.header_bytes[@intCast(self.blocks_made % 2)][0..];
        header_stored.* = header;
        return .{
            .hash = trie.node.keccak256(&header),
            .parent_hash = parent_hash,
            .number = number,
            .timestamp = number,
            .header = header_stored,
            .body = &.{},
            .receipts = &.{},
            .transaction_hashes = &.{},
            .changeset = &.{},
        };
    }

    /// Moves the head back to height `height` (an unwind) with `set_head`: false when the
    /// database cannot (the block is no longer retained, or the unwind is deeper than a
    /// head move may be); nothing changed then.
    pub fn unwind_to(self: *Node, height: u64) Error!bool {
        assert(height <= self.height);
        if (height == self.height) return true;
        if (self.mode == .disk_deep) return false;
        if (self.height - height > reorg_depth_max) return false;
        comptime assert(reorg_depth_max < blocks_max);
        var attempts: u32 = 0;
        while (attempts < attempts_max) : (attempts += 1) {
            _ = self.db.set_head(self.hash_at(height)) catch |err| switch (err) {
                error.Busy => {
                    try self.wait_quiet();
                    continue;
                },
                error.UnknownBlock, error.ReorgTooDeep => return false,
                else => return err,
            };
            try self.settle();
            self.height = height;
            self.state_db.clear_undo();
            return true;
        }
        return error.Stalled;
    }

    fn hash_at(self: *const Node, height: u64) Hash {
        assert(height <= self.height and self.height - height <= blocks_max);
        return self.hashes[@intCast(height % self.hashes.len)];
    }

    fn hash_set(self: *Node, height: u64, hash: Hash) void {
        assert(height == self.height);
        self.hashes[@intCast(height % self.hashes.len)] = hash;
    }

    fn wait_quiet(self: *Node) Error!void {
        var ticks: u32 = 0;
        while (ticks < 64) : (ticks += 1) self.tick();
        try self.settle();
    }

    /// Disk mode: commits the next block from its writes in hashed key space.
    pub fn commit_hashed(self: *Node, writes: HashedWrites) Error!void {
        assert(self.mode != .memory);
        var attempts: u32 = 0;
        while (attempts < attempts_max) : (attempts += 1) {
            if (try self.attempt_hashed(writes)) {
                try self.settle();
                return;
            }
            try self.wait_quiet();
        }
        return error.Stalled;
    }

    /// `disk-deep`: commits `writes` as consecutive blocks of at most `deep_chunk_accounts`
    /// account and `deep_chunk_slots` slot changes (writes that change nothing ride along
    /// uncounted; one block when there are none). Owners go
    /// in key order, each whole: an account that is absent after the writes after its slots
    /// (so a deleted account's slots are cleared first), any other before them (so a created
    /// account exists first). Every block is a state the node can hold; the last is the
    /// writes' state. Each block's writes are index ranges of `writes`, so stay sorted.
    pub fn commit_split(self: *Node, writes: HashedWrites) Error!void {
        assert(self.mode == .disk_deep);
        var split: Split = .{ .writes = writes };
        var slot_index: usize = 0;
        for (writes.accounts, 0..) |*account, account_index| {
            assert(account_index == split.account_end);
            const slot_start = slot_index;
            while (slot_index < writes.slots.len and
                std.mem.eql(u8, &writes.slots[slot_index].key, &account.key)) slot_index += 1;
            if (account.info != null) try split.take_account(self);
            for (writes.slots[slot_start..slot_index]) |*slot| try split.take_slot(self, slot);
            if (account.info == null) try split.take_account(self);
        }
        // Every slot's owner has an account write (the model names every key it writes).
        assert(slot_index == writes.slots.len and split.slot_end == writes.slots.len);
        if (split.pending() or split.blocks == 0) try split.commit(self);
        assert(split.blocks > 0);
    }

    const Split = struct {
        writes: HashedWrites,
        account_start: usize = 0,
        account_end: usize = 0,
        slot_start: usize = 0,
        slot_end: usize = 0,
        account_changes: u32 = 0,
        slot_changes: u32 = 0,
        blocks: u32 = 0,

        fn pending(split: *const Split) bool {
            return split.account_end > split.account_start or split.slot_end > split.slot_start;
        }

        /// Each key is written once, so the database holds its value before the writes
        /// until its own block commits.
        fn take_account(split: *Split, node: *Node) Error!void {
            const write = &split.writes.accounts[split.account_end];
            const record = node.db.state.account_hashed(&write.key);
            const old: ?db.AccountInfo = if (record) |found| found.info else null;
            const same = if (old == null or write.info == null)
                old == null and write.info == null
            else
                old.?.eql(write.info.?);
            if (!same) {
                if (split.account_changes == deep_chunk_accounts) try split.commit(node);
                split.account_changes += 1;
            }
            split.account_end += 1;
        }

        fn take_slot(split: *Split, node: *Node, write: *const HashedSlotWrite) Error!void {
            assert(write == &split.writes.slots[split.slot_end]);
            if (node.db.state.storage_hashed(&write.key, &write.slot) != write.value) {
                if (split.slot_changes == deep_chunk_slots) try split.commit(node);
                split.slot_changes += 1;
            }
            split.slot_end += 1;
        }

        fn commit(split: *Split, node: *Node) Error!void {
            try node.commit_hashed(.{
                .accounts = split.writes.accounts[split.account_start..split.account_end],
                .slots = split.writes.slots[split.slot_start..split.slot_end],
            });
            split.account_start = split.account_end;
            split.slot_start = split.slot_end;
            split.account_changes = 0;
            split.slot_changes = 0;
            split.blocks += 1;
        }
    };

    /// One try: false when the database was busy (nothing changed).
    fn attempt_hashed(self: *Node, writes: HashedWrites) Error!bool {
        try self.make_room();
        self.db.hold_checkpoints(true);
        defer self.db.hold_checkpoints(false);
        self.state_db.commit_hashed(writes) catch |err| switch (err) {
            error.Busy => return false,
            else => return err,
        };
        var input = self.block_input(self.hash_at(self.height), self.height + 1);
        input.changeset = self.state_db.last_changeset().?; // This block's commit.
        const committed = self.db.commit_applied(&input) catch |err| {
            // A failed database cannot unwind; any other refusal changed nothing.
            if (self.db.phase == .ready) try self.rollback();
            if (err == error.Busy) return false;
            return err;
        };
        assert(std.mem.eql(u8, &self.db.head_info.state_root, &committed.state_root));
        self.height += 1;
        self.hash_set(self.height, input.hash);
        self.stats.commits += 1;
        return true;
    }

    fn rollback(self: *Node) Error!void {
        var ticks: u32 = 0;
        while (true) : (ticks += 1) {
            if (ticks >= ticks_max) return error.Stalled;
            self.state_db.rollback() catch |err| switch (err) {
                error.Busy => {
                    self.tick();
                    continue;
                },
                else => return err,
            };
            break;
        }
        const root = try self.db.state.state_root();
        assert(std.mem.eql(u8, &root, &self.db.head_info.state_root));
    }

    fn make_room(self: *Node) Error!void {
        const driver: to_disk.Driver = .{ .context = self, .tick = tick_driver };
        Room.make_room(&self.db, driver, null, &self.room, false) catch |err| {
            return switch (err) {
                error.NotReady, error.CheckpointFailed => error.NodeFailed,
                error.Stalled => error.Stalled,
            };
        };
        assert(!self.db.checkpoints_held);
    }

    fn tick_driver(context: *anyopaque) void {
        const self: *Node = @ptrCast(@alignCast(context));
        self.tick();
    }

    /// Memory mode: commits the block whose writes are in `overlay` (by address), as the
    /// durable node commits an executed block (`execute_and_commit`).
    pub fn commit_overlay(self: *Node) Error!void {
        assert(self.mode == .memory);
        if (self.height == blocks_max) return error.NodeFailed;
        const input = self.block_input(self.hash_at(self.height), self.height + 1);
        var attempts: u32 = 0;
        while (attempts < attempts_max) : (attempts += 1) {
            _ = self.db.execute_and_commit(&self.overlay, &input) catch |err| switch (err) {
                error.Busy => {
                    try self.wait_quiet();
                    continue;
                },
                else => return err,
            };
            try self.settle();
            self.height += 1;
            self.hash_set(self.height, input.hash);
            return;
        }
        return error.Stalled;
    }

    pub fn state_root(self: *const Node) Hash {
        assert(self.db.head_info.present);
        return self.db.head_info.state_root;
    }
};
