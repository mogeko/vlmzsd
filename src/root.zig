//! vlmzsd — an idiomatic Zig implementation of the KMS (Key Management Service) emulator.

pub const crypto = @import("crypto.zig");
pub const kmsdata = @import("kmsdata.zig");
pub const kms = @import("kms.zig");
pub const rpc = @import("rpc.zig");
pub const network = @import("network.zig");
pub const cli_helper = @import("cli_helper.zig");

const std = @import("std");
const testutil = @import("testutil.zig");

test "embedded .kmd data pipeline" {
    const kmd = @embedFile("vlmcsd.kmd");

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
    _ = network;
    _ = cli_helper;
}
