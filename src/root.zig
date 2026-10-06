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

test "@splat fills wire buffers with the repeated byte" {
    const alloc = std.testing.allocator;

    // 0.17 removed array multiplication (`[N]u8{v} ** N`), so the wire layer now
    // fills its buffers with `@splat`: GUIDs/cmids in `src/kms.zig`, RPC bodies
    // in `src/rpc.zig`, blocks in `src/crypto.zig`. Pin the bytes of the new
    // spelling. 16-byte GUID/CMID fields: docs/migration.md §3.1.
    const guid = kms.zeroGuid();
    try std.testing.expectEqual(@as(usize, 16), guid.len);
    try testutil.expectHex(alloc, &guid, "00000000000000000000000000000000");

    // The value must be *written*, not assumed: `**` built a fresh array,
    // whereas `@splat` also assigns over a buffer that already holds data.
    var reused: [16]u8 = @splat(0xFF);
    reused = @splat(0);
    try testutil.expectHex(alloc, &reused, "00000000000000000000000000000000");

    // The non-zero fills the wire tests seed CMIDs, KMS IDs and payloads with.
    var cmid: [16]u8 = @splat(1);
    try testutil.expectHex(alloc, &cmid, "01010101010101010101010101010101");
    var kms_id: [16]u8 = @splat(0xFF);
    try testutil.expectHex(alloc, &kms_id, "ffffffffffffffffffffffffffffffff");

    // The remaining widths the wire layer fills this way, from the 8-byte
    // dispatch buffer to the 64-byte block. `allEqual` only checks values, so
    // each is paired with its length.
    var small: [8]u8 = @splat(0);
    try std.testing.expectEqual(@as(usize, 8), small.len);
    try std.testing.expect(std.mem.allEqual(u8, &small, 0));

    var block64: [64]u8 = @splat(0);
    try std.testing.expectEqual(@as(usize, 64), block64.len);
    try std.testing.expect(std.mem.allEqual(u8, &block64, 0));

    // And the filled bytes are the ones the wire sees: a FAULT body is
    // AllocHint(32) + ServerFault(0) + Error.Code + Result(0), the three zeros
    // coming from `@splat(0)` — docs/migration.md §3.3.
    const fault = rpc.buildFault(rpc.nca_unk_if);
    try testutil.expectHex(alloc, fault[0..4], "20000000"); // AllocHint = 32
    try testutil.expectHex(alloc, fault[4..8], "00000000"); // ServerFault, from @splat(0)
    try testutil.expectHex(alloc, fault[8..12], "0300011c"); // Error.Code = nca_unk_if, LE
    try testutil.expectHex(alloc, fault[12..16], "00000000"); // Result
}

test {
    // Force analysis of submodules so `zig build test` collects their tests.
    _ = crypto;
    _ = kmsdata;
    _ = kms;
    _ = rpc;
}
