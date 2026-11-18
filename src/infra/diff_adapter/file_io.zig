//! A blocking file IO backend for the trie mode's on-disk databases (`IoStorageType`'s IO):
//! reads, writes and fsyncs are queued by `enqueue` and performed with blocking positional
//! calls (`utilities.io.os`) on the next `tick`, in submission order, on the calling thread.
//!
//! The node runs the same storage over io_uring; this backend differs only below the
//! storage interface. It makes every completion's timing a function of the request alone
//! (no kernel completion order, no threads), so the storage engine takes the same code paths
//! on every run of a request, and it needs no io_uring (often forbidden in containers).

const std = @import("std");
const assert = std.debug.assert;

const io_common = @import("../../utilities/io/common.zig");
const os = @import("../../utilities/io/os.zig");

pub const FileIo = struct {
    pub const Fd = os.fd_t;
    pub const Completion = struct {
        pub const Fd = os.fd_t;
        operation: io_common.Operation(os.fd_t) = .none,
        result: io_common.Result(os.fd_t) = .none,
        context: ?*anyopaque = null,
        callback: *const fn (?*anyopaque, *Completion) void = undefined,
        next: ?*Completion = null,
    };
    const methods = io_common.Methods(FileIo);
    pub const read = methods.read;
    pub const write = methods.write;
    pub const fsync = methods.fsync;

    queue: io_common.Queue(Completion) = .{},

    pub fn enqueue(io: *FileIo, completion: *Completion) void {
        assert(completion.next == null);
        assert(completion.operation != .none);
        io.queue.push(completion);
    }

    /// Performs and completes every operation queued at entry (callbacks may queue more:
    /// those wait for the next tick).
    pub fn tick(io: *FileIo) error{}!void {
        var pending = io.queue;
        io.queue = .{};
        const count = pending.count;
        var completed: u32 = 0;
        while (pending.pop()) |completion| : (completed += 1) {
            assert(completed < count);
            perform(completion);
            io_common.complete(Completion, completion);
        }
        assert(completed == count);
    }

    pub fn read_now(io: *FileIo, fd: Fd, buffer: []u8, offset: u64) io_common.ReadError!usize {
        _ = io;
        return os.pread(fd, buffer, offset);
    }

    pub fn open_file(io: *FileIo, path: []const u8, mode: io_common.OpenMode) !Fd {
        _ = io;
        return os.open_file(path, mode);
    }

    /// Operations still queued (a database dropped mid-checkpoint, or after a failure) are
    /// forgotten: their owner is going away with the file.
    pub fn close_now(io: *FileIo, fd: Fd) void {
        assert(fd >= 0);
        io.queue = .{};
        os.close(fd);
    }

    fn perform(completion: *Completion) void {
        completion.result = switch (completion.operation) {
            .read => |op| .{ .read = os.pread(op.fd, op.buffer, op.offset) },
            .write => |op| .{ .write = os.pwrite(op.fd, op.buffer, op.offset) },
            .fsync => |op| .{ .fsync = os.fsync(op.fd) },
            // The storage submits only reads, writes and fsyncs.
            else => unreachable,
        };
        assert(std.meta.activeTag(completion.result) == std.meta.activeTag(completion.operation));
    }
};
