//! vlmzsd — a modern-Zig reimplementation of the vlmcsd KMS emulator.

const std = @import("std");
const testutil = @import("testutil.zig");

test "testdata pipeline: load etc/vlmcsd.kmd" {
    const alloc = std.testing.allocator;

    // 0.16: file I/O goes through an `Io` instance (thread-pool backend here).
    // Tests run from the build root (the directory containing `build.zig`).
    var threaded = std.Io.Threaded.init(alloc, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const kmd = try std.Io.Dir.readFileAlloc(std.Io.Dir.cwd(), io, "etc/vlmcsd.kmd", alloc, .unlimited);
    defer alloc.free(kmd);

    try testutil.expectBytes(kmd[0..3], "KMD");
    try std.testing.expectEqual(@as(u8, 0), kmd[3]);
    try testutil.expectBytes(kmd[4..6], "\x00\x00");
    try testutil.expectBytes(kmd[6..8], "\x02\x00");
    try std.testing.expectEqual(@as(usize, 15079), kmd.len);
}
