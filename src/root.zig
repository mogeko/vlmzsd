//! vlmzsd — an idiomatic Zig implementation of the KMS (Key Management Service) emulator.
//!
//! **Public API** (stable across patch releases; may change in 0.x):
//! `crypto` (AES/CMAC/HMAC), `kmsdata` (`.kmd` parsing), `kms` (KMS v4/v5/v6
//! protocol), and `rpc` (DCE/RPC framing). These four modules are pure logic
//! with no `std.Io` or libc dependency — downstream projects should
//! `@import("vlmzsd")` and use these.
//!
//! `network` and `cli_helper` are internal to the `vlmzsd`/`vlmzs` binaries and
//! are not part of the public API.

pub const crypto = @import("crypto.zig");
pub const kmsdata = @import("kmsdata.zig");
pub const kms = @import("kms.zig");
pub const rpc = @import("rpc.zig");

const std = @import("std");
const testutil = @import("testutil.zig");

test "embedded .kmd data pipeline" {
    const kmd = @embedFile("vlmcsd.kmd");

    try testutil.expectBytes(kmd[0..3], "KMD");
    try std.testing.expectEqual(@as(u8, 0), kmd[3]);
    try testutil.expectBytes(kmd[4..6], "\x00\x00");
    try testutil.expectBytes(kmd[6..8], "\x02\x00");
    try std.testing.expectEqual(@as(usize, 19371), kmd.len);
}

test {
    // Force analysis of submodules so `zig build test` collects their tests.
    _ = crypto;
    _ = kmsdata;
    _ = kms;
    _ = rpc;
}
