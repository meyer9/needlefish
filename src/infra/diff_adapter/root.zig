//! Differential execution adapter (`base diff-adapter`): runs a fuzz harness's blocks on
//! needlefish's block execution path over stateless witnesses and reports every header
//! field, receipt and state change it computes, for comparison against base/base and other
//! clients. The protocol is newline-delimited JSON: one request line in, one response line
//! out (`request.zig`, `response.zig`); `adapter.zig` executes a case.

const std = @import("std");
const assert = std.debug.assert;

pub const request = @import("request.zig");
pub const adapter = @import("adapter.zig");
pub const response = @import("response.zig");
pub const Adapter = adapter.Adapter;

/// Answers one request line into `out` (no newline). Every line gets a response: requests
/// that cannot be processed get `ok: false`.
pub fn handle_line(
    self: *Adapter,
    arena: std.mem.Allocator,
    line: []const u8,
    out: *std.Io.Writer,
) std.Io.Writer.Error!void {
    const raw = request.parse(arena, line) catch |err| {
        const id = request.salvage_id(arena, line);
        return response.write_error(out, id, error_text(arena, "invalid request", err));
    };
    const case = request.decode(arena, &raw) catch |err| {
        return response.write_error(out, raw.id, error_text(arena, "invalid request", err));
    };
    const outcome = self.run(arena, &case) catch |err| {
        return response.write_error(out, raw.id, error_text(arena, "cannot execute", err));
    };
    return response.write_outcome(out, raw.id, &outcome);
}

fn error_text(arena: std.mem.Allocator, what: []const u8, err: anyerror) []const u8 {
    assert(what.len > 0);
    return std.fmt.allocPrint(arena, "{s}: {t}", .{ what, err }) catch what;
}

test {
    std.testing.refAllDecls(@This());
    _ = @import("adapter_test.zig");
}
