//! Byte-comparison and hex helpers for wire-compatibility tests.

const std = @import("std");
const Allocator = std.mem.Allocator;

/// Compare `actual` against the golden `expected` bytes.
///
/// On mismatch, prints a readable hex diff and returns `error.TestExpectedEqual`.
pub fn expectBytes(actual: []const u8, expected: []const u8) error{TestExpectedEqual}!void {
    if (std.mem.eql(u8, actual, expected)) return;
    printDiff(actual, expected);
    return error.TestExpectedEqual;
}

/// Return a lowercase hex string of `bytes`. The caller owns the returned buffer.
pub fn hexDump(allocator: Allocator, bytes: []const u8) Allocator.Error![]u8 {
    const out = try allocator.alloc(u8, bytes.len * 2);
    const digits = "0123456789abcdef";
    for (bytes, 0..) |b, i| {
        out[i * 2] = digits[b >> 4];
        out[i * 2 + 1] = digits[b & 0x0f];
    }
    return out;
}

fn printDiff(actual: []const u8, expected: []const u8) void {
    std.debug.print("byte mismatch: expected {d} bytes, got {d} bytes\n", .{
        expected.len, actual.len,
    });
    const n = @max(actual.len, expected.len);
    var i: usize = 0;
    while (i < n) : (i += 1) {
        const a: ?u8 = if (i < actual.len) actual[i] else null;
        const e: ?u8 = if (i < expected.len) expected[i] else null;
        if (a != e) {
            std.debug.print("  offset 0x{x:0>4}: expected ", .{i});
            printByte(e);
            std.debug.print(", got ", .{});
            printByte(a);
            std.debug.print("\n", .{});
        }
    }
}

fn printByte(byte: ?u8) void {
    if (byte) |b| {
        std.debug.print("0x{x:0>2}", .{b});
    } else {
        std.debug.print("--", .{});
    }
}

test "expectBytes passes on equal bytes" {
    try expectBytes("KMD", "KMD");
}

test "expectBytes fails on mismatch" {
    try std.testing.expectError(error.TestExpectedEqual, expectBytes("KMD", "KMX"));
}

test "hexDump" {
    const alloc = std.testing.allocator;
    const hex = try hexDump(alloc, "\xde\xad\xbe\xef");
    defer alloc.free(hex);
    try expectBytes(hex, "deadbeef");
}
