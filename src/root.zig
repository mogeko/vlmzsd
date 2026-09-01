//! vlmzsd — a modern-Zig reimplementation of the vlmcsd KMS emulator.

pub const crypto = @import("crypto.zig");
pub const kmsdata = @import("kmsdata.zig");
pub const kms = @import("kms.zig");
pub const rpc = @import("rpc.zig");

const std = @import("std");
const testutil = @import("testutil.zig");

test "testdata pipeline: load reference/vlmcsd.kmd" {
    const alloc = std.testing.allocator;

    // 0.16: file I/O goes through an `Io` instance (thread-pool backend here).
    // Tests run from the build root (the directory containing `build.zig`).
    var threaded = std.Io.Threaded.init(alloc, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const kmd = try std.Io.Dir.readFileAlloc(std.Io.Dir.cwd(), io, "reference/vlmcsd.kmd", alloc, .unlimited);
    defer alloc.free(kmd);

    try testutil.expectBytes(kmd[0..3], "KMD");
    try std.testing.expectEqual(@as(u8, 0), kmd[3]);
    try testutil.expectBytes(kmd[4..6], "\x00\x00");
    try testutil.expectBytes(kmd[6..8], "\x02\x00");
    try std.testing.expectEqual(@as(usize, 15079), kmd.len);
}

test {
    // Force analysis of submodules so `zig build test` collects their tests.
    _ = crypto;
    _ = kmsdata;
    _ = kms;
    _ = rpc;
}
