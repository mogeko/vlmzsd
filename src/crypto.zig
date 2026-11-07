//! Crypto primitives reimplemented to match the vlmcsd reference byte-for-byte.
//!
//! AES is implemented from scratch (FIPS-197) because the reference uses
//! parameters `std.crypto` does not support:
//!   * v4 uses a 160-bit key (Rijndael, Nk=5 → 11 rounds);
//!   * v6 XORs 0x73/0x09/0xE4 into the first byte of round keys 4/6/8 after a
//!     standard 128-bit key expansion.
//! SHA-256 and HMAC-SHA256 are standard and use `std.crypto`.
//!
//! `Key` carries the whole key schedule: its variant fixes both the width
//! (160-bit v4, 128-bit v5/v6) and the derivation, so a cipher call cannot pair
//! a key with the wrong parameters. CBC takes its plaintext length from the
//! slice, so "encrypt past the buffer" cannot be written either.

const std = @import("std");
const testutil = @import("testutil.zig");

const Block = [16]u8;

// Standard AES S-box (FIPS-197).
const sbox = [256]u8{
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
};

// Standard AES inverse S-box (FIPS-197).
const sbox_inv = [256]u8{
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d,
};

const rcon = [11]u8{ 0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36 };

/// A KMS AES key: the variant fixes the key width and the key expansion, so
/// the two cannot be paired wrongly (only `v6` applies the extra round-key
/// XOR, and only `v4` uses a 160-bit key).
pub const Key = union(enum) {
    /// 160-bit Rijndael key (Nk=5, 11 rounds) — the v4 MAC.
    v4: [20]u8,
    /// Plain 128-bit schedule — v5 CBC.
    v5: [16]u8,
    /// 128-bit schedule with the v6 round-key XOR — v6 CBC.
    v6: [16]u8,
};

pub const aes_key_v4: Key = .{ .v4 = .{ 0x05, 0x3d, 0x83, 0x07, 0xf9, 0xe5, 0xf0, 0x88, 0xeb, 0x5e, 0xa6, 0x68, 0x6c, 0xf0, 0x37, 0xc7, 0xe4, 0xef, 0xd2, 0xd6 } };
pub const aes_key_v5: Key = .{ .v5 = .{ 0xcd, 0x7e, 0x79, 0x6f, 0x2a, 0xb2, 0x5d, 0xcb, 0x55, 0xff, 0xc8, 0xef, 0x83, 0x64, 0xc4, 0x70 } };
pub const aes_key_v6: Key = .{ .v6 = .{ 0xa9, 0x4a, 0x41, 0x95, 0xe2, 0x01, 0x43, 0x2d, 0x9b, 0xcb, 0x46, 0x04, 0x05, 0xd8, 0x4a, 0x21 } };

comptime {
    // Key bytes pinned to `AesKeyV4`/`AesKeyV5`/`AesKeyV6` — docs/migration.md §3.2.
    std.debug.assert(std.mem.eql(u8, &aes_key_v4.v4, &[_]u8{ 0x05, 0x3d, 0x83, 0x07, 0xf9, 0xe5, 0xf0, 0x88, 0xeb, 0x5e, 0xa6, 0x68, 0x6c, 0xf0, 0x37, 0xc7, 0xe4, 0xef, 0xd2, 0xd6 }));
    std.debug.assert(std.mem.eql(u8, &aes_key_v5.v5, &[_]u8{ 0xcd, 0x7e, 0x79, 0x6f, 0x2a, 0xb2, 0x5d, 0xcb, 0x55, 0xff, 0xc8, 0xef, 0x83, 0x64, 0xc4, 0x70 }));
    std.debug.assert(std.mem.eql(u8, &aes_key_v6.v6, &[_]u8{ 0xa9, 0x4a, 0x41, 0x95, 0xe2, 0x01, 0x43, 0x2d, 0x9b, 0xcb, 0x46, 0x04, 0x05, 0xd8, 0x4a, 0x21 }));
}

fn beWord(b: []const u8) u32 {
    return (@as(u32, b[0]) << 24) | (@as(u32, b[1]) << 16) | (@as(u32, b[2]) << 8) | b[3];
}

fn writeBeWord(b: []u8, w: u32) void {
    b[0] = @truncate(w >> 24);
    b[1] = @truncate(w >> 16);
    b[2] = @truncate(w >> 8);
    b[3] = @truncate(w);
}

fn rotWord(w: u32) u32 {
    return std.math.rotl(u32, w, 8);
}

fn subWord(w: u32) u32 {
    const b0 = sbox[@intCast((w >> 24) & 0xff)];
    const b1 = sbox[@intCast((w >> 16) & 0xff)];
    const b2 = sbox[@intCast((w >> 8) & 0xff)];
    const b3 = sbox[@intCast(w & 0xff)];
    return (@as(u32, b0) << 24) | (@as(u32, b1) << 16) | (@as(u32, b2) << 8) | b3;
}

fn expandKey(comptime nk: usize, key: []const u8, is_v6: bool) [16 * (nk + 7)]u8 {
    std.debug.assert(key.len == nk * 4); // 128-bit (nk=4) or 160-bit (nk=5) key
    const nr = nk + 6;
    const words = 4 * (nr + 1);

    var w: [words]u32 = undefined;
    for (0..nk) |i| {
        w[i] = beWord(key[i * 4 ..][0..4]);
    }
    for (nk..words) |i| {
        var temp = w[i - 1];
        if (i % nk == 0) {
            temp = subWord(rotWord(temp)) ^ (@as(u32, rcon[i / nk]) << 24);
        }
        w[i] = w[i - nk] ^ temp;
    }

    var rk: [16 * (nk + 7)]u8 = undefined;
    for (0..words) |i| {
        writeBeWord(rk[i * 4 ..][0..4], w[i]);
    }

    if (is_v6) {
        rk[64] ^= 0x73;
        rk[96] ^= 0x09;
        rk[128] ^= 0xe4;
    }

    return rk;
}

fn subBytes(state: *Block) void {
    for (state) |*b| {
        b.* = sbox[@intCast(b.*)];
    }
}

fn shiftRows(state: *Block) void {
    const t = state.*;
    for (0..4) |r| {
        for (0..4) |c| {
            state[r + 4 * c] = t[r + 4 * ((c + r) % 4)];
        }
    }
}

fn xtime(x: u8) u8 {
    const shifted: u8 = @truncate(@as(u16, x) << 1);
    return shifted ^ (if (x & 0x80 != 0) @as(u8, 0x1b) else 0);
}

fn mixColumns(state: *Block) void {
    for (0..4) |c| {
        const i = 4 * c;
        const a0 = state[i];
        const a1 = state[i + 1];
        const a2 = state[i + 2];
        const a3 = state[i + 3];
        state[i] = xtime(a0) ^ (xtime(a1) ^ a1) ^ a2 ^ a3;
        state[i + 1] = a0 ^ xtime(a1) ^ (xtime(a2) ^ a2) ^ a3;
        state[i + 2] = a0 ^ a1 ^ xtime(a2) ^ (xtime(a3) ^ a3);
        state[i + 3] = (xtime(a0) ^ a0) ^ a1 ^ a2 ^ xtime(a3);
    }
}

fn aesEncrypt(comptime nk: usize, block: Block, rk: []const u8) Block {
    const nr = nk + 6;
    var state = block;

    for (0..16) |i| state[i] ^= rk[i];

    for (1..nr) |round| {
        subBytes(&state);
        shiftRows(&state);
        mixColumns(&state);
        for (0..16) |i| state[i] ^= rk[round * 16 + i];
    }

    subBytes(&state);
    shiftRows(&state);
    for (0..16) |i| state[i] ^= rk[nr * 16 + i];

    return state;
}

fn xtime2(x: u8) u8 {
    return xtime(xtime(x));
}

fn xtime3(x: u8) u8 {
    return xtime(xtime2(x));
}

fn mul9(x: u8) u8 {
    return xtime3(x) ^ x;
}

fn mul11(x: u8) u8 {
    return xtime3(x) ^ xtime(x) ^ x;
}

fn mul13(x: u8) u8 {
    return xtime3(x) ^ xtime2(x) ^ x;
}

fn mul14(x: u8) u8 {
    return xtime3(x) ^ xtime2(x) ^ xtime(x);
}

fn invSubBytes(state: *Block) void {
    for (state) |*b| {
        b.* = sbox_inv[@intCast(b.*)];
    }
}

fn invShiftRows(state: *Block) void {
    const t = state.*;
    for (0..4) |r| {
        for (0..4) |c| {
            state[r + 4 * c] = t[r + 4 * ((c + 4 - r) % 4)];
        }
    }
}

fn invMixColumns(state: *Block) void {
    for (0..4) |c| {
        const i = 4 * c;
        const a0 = state[i];
        const a1 = state[i + 1];
        const a2 = state[i + 2];
        const a3 = state[i + 3];
        state[i] = mul14(a0) ^ mul11(a1) ^ mul13(a2) ^ mul9(a3);
        state[i + 1] = mul9(a0) ^ mul14(a1) ^ mul11(a2) ^ mul13(a3);
        state[i + 2] = mul13(a0) ^ mul9(a1) ^ mul14(a2) ^ mul11(a3);
        state[i + 3] = mul11(a0) ^ mul13(a1) ^ mul9(a2) ^ mul14(a3);
    }
}

fn aesDecrypt(comptime nk: usize, block: Block, rk: []const u8) Block {
    const nr = nk + 6;
    var state = block;

    for (0..16) |i| state[i] ^= rk[nr * 16 + i];

    var round: usize = nr - 1;
    while (round > 0) : (round -= 1) {
        invShiftRows(&state);
        invSubBytes(&state);
        for (0..16) |i| state[i] ^= rk[round * 16 + i];
        invMixColumns(&state);
    }

    invShiftRows(&state);
    invSubBytes(&state);
    for (0..16) |i| state[i] ^= rk[i];

    return state;
}

/// v4 MAC: CBC-MAC with a zero IV and ISO 9797-1 padding (0x80…) under
/// AES with the 160-bit `AesKeyV4`. `message` may be any length; the
/// reference (`AesCmacV4` in crypto.c) appends 0x80 followed by zeros up to
/// the next block boundary (a full padding block when already aligned).
pub fn aesCmacV4(message: []const u8, out: *Block) void {
    const rk = expandKey(5, &aes_key_v4.v4, false);
    var mac: Block = @splat(0);

    // Absorb every full 16-byte block.
    var offset: usize = 0;
    while (offset + 16 <= message.len) : (offset += 16) {
        var block: Block = undefined;
        @memcpy(block[0..], message[offset..][0..16]);
        for (0..16) |i| mac[i] ^= block[i];
        mac = aesEncrypt(5, mac, &rk);
    }

    // Final block: remaining bytes, 0x80, then zeros (ISO 9797-1 method 2).
    var pad: Block = @splat(0);
    const remaining = message.len - offset;
    @memcpy(pad[0..remaining], message[offset..]);
    pad[remaining] = 0x80;
    for (0..16) |i| mac[i] ^= pad[i];
    mac = aesEncrypt(5, mac, &rk);

    out.* = mac;
}

/// Encrypt one block under `key`'s schedule. `nk` (the key width in 32-bit
/// words) and `is_v6` (the round-key modification) are supplied by the
/// `Key` variant, so neither appears in a public signature.
fn encryptBlock(comptime nk: usize, is_v6: bool, key: *const [nk * 4]u8, block: Block) Block {
    const rk = expandKey(nk, key, is_v6);
    return aesEncrypt(nk, block, &rk);
}

fn decryptBlock(comptime nk: usize, is_v6: bool, key: *const [nk * 4]u8, block: Block) Block {
    const rk = expandKey(nk, key, is_v6);
    return aesDecrypt(nk, block, &rk);
}

/// AES-encrypt one block.
pub fn aesEncryptBlock(key: *const Key, block: Block) Block {
    return switch (key.*) {
        .v4 => |*k| encryptBlock(5, false, k, block),
        .v5 => |*k| encryptBlock(4, false, k, block),
        .v6 => |*k| encryptBlock(4, true, k, block),
    };
}

/// AES-decrypt one block (inverse of `aesEncryptBlock`).
pub fn aesDecryptBlock(key: *const Key, block: Block) Block {
    return switch (key.*) {
        .v4 => |*k| decryptBlock(5, false, k, block),
        .v5 => |*k| decryptBlock(4, false, k, block),
        .v6 => |*k| decryptBlock(4, true, k, block),
    };
}

/// v6 AES: encrypt one block under the v6 key.
pub fn aesV6EncryptBlock(block: *const Block) Block {
    return aesEncryptBlock(&aes_key_v6, block.*);
}

fn cbcEncrypt(comptime nk: usize, rk: []const u8, iv: ?*const Block, data: []u8) void {
    std.debug.assert(data.len % 16 == 0);
    var prev: Block = undefined;
    var offset: usize = 0;
    while (offset < data.len) : (offset += 16) {
        var block: Block = undefined;
        @memcpy(block[0..], data[offset..][0..16]);
        if (offset == 0) {
            if (iv) |ivb| {
                for (0..16) |i| block[i] ^= ivb[i];
            }
        } else {
            for (0..16) |i| block[i] ^= prev[i];
        }
        const enc = aesEncrypt(nk, block, rk);
        @memcpy(data[offset..][0..16], enc[0..]);
        prev = enc;
    }
}

fn cbcDecrypt(comptime nk: usize, rk: []const u8, iv: ?*const Block, data: []u8) void {
    std.debug.assert(data.len % 16 == 0);
    var offset: usize = data.len;
    while (offset > 0) {
        offset -= 16;
        var ciphertext: Block = undefined;
        @memcpy(ciphertext[0..], data[offset..][0..16]);
        const plain = aesDecrypt(nk, ciphertext, rk);
        var out: Block = plain;
        if (offset == 0) {
            if (iv) |ivb| {
                for (0..16) |i| out[i] ^= ivb[i];
            }
        } else {
            for (0..16) |i| out[i] ^= data[offset - 16 + i];
        }
        @memcpy(data[offset..][0..16], out[0..]);
    }
}

fn cbcEncryptWith(comptime nk: usize, is_v6: bool, key: *const [nk * 4]u8, iv: ?*const Block, data: []u8) void {
    const rk = expandKey(nk, key, is_v6);
    cbcEncrypt(nk, &rk, iv, data);
}

fn cbcDecryptWith(comptime nk: usize, is_v6: bool, key: *const [nk * 4]u8, iv: ?*const Block, data: []u8) void {
    const rk = expandKey(nk, key, is_v6);
    cbcDecrypt(nk, &rk, iv, data);
}

/// CBC-encrypt `plaintext` with PKCS#7 padding (always pads) and write the
/// ciphertext to `out`, which must hold `plaintext.len` plus a whole padding
/// block. For an in-place encryption `plaintext` is `out[0..plaintext.len]` —
/// the same buffer and the same start. A `null` `iv` starts from a zero block,
/// which is the KMS wire convention. Returns the ciphertext length.
pub fn aesCbcEncrypt(key: *const Key, iv: ?*const Block, plaintext: []const u8, out: []u8) usize {
    const pad: usize = if (plaintext.len % 16 == 0) 16 else 16 - (plaintext.len % 16);
    const new_len = plaintext.len + pad;
    std.debug.assert(out.len >= new_len);
    const ciphertext = out[0..new_len];

    if (@intFromPtr(plaintext.ptr) != @intFromPtr(ciphertext.ptr)) {
        // Separate buffers: copy the plaintext in, then pad after it.
        @memcpy(ciphertext[0..plaintext.len], plaintext);
    }
    @memset(ciphertext[plaintext.len..], @intCast(pad));

    switch (key.*) {
        .v4 => |*k| cbcEncryptWith(5, false, k, iv, ciphertext),
        .v5 => |*k| cbcEncryptWith(4, false, k, iv, ciphertext),
        .v6 => |*k| cbcEncryptWith(4, true, k, iv, ciphertext),
    }
    return new_len;
}

/// CBC-decrypt `data` in place. `data.len` must be a whole number of blocks; a
/// `null` `iv` is a zero block.
pub fn aesCbcDecrypt(key: *const Key, iv: ?*const Block, data: []u8) void {
    std.debug.assert(data.len % 16 == 0);
    switch (key.*) {
        .v4 => |*k| cbcDecryptWith(5, false, k, iv, data),
        .v5 => |*k| cbcDecryptWith(4, false, k, iv, data),
        .v6 => |*k| cbcDecryptWith(4, true, k, iv, data),
    }
}

/// HMAC-SHA256 (the reference hardcodes a 16-byte key; the algorithm itself is
/// standard HMAC-SHA256, so any key length is supported here).
pub fn hmacSha256(key: []const u8, data: []const u8, out: *[32]u8) void {
    std.crypto.auth.hmac.sha2.HmacSha256.create(out, data, key);
}

pub fn sha256(data: []const u8, out: *[32]u8) void {
    std.crypto.hash.sha2.Sha256.hash(data, out, .{});
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "v4 CMAC reference vectors" {
    const alloc = std.testing.allocator;

    var msg32: [32]u8 = @splat(0);
    var msg64: [64]u8 = @splat(0);
    var mac: Block = undefined;

    aesCmacV4(&msg32, &mac);
    try testutil.expectHex(alloc, &mac, "1c3cb37a2a7283b1f2158220eb321c46"); // from upstream C dump_vectors

    aesCmacV4(msg32[0..16], &mac);
    try testutil.expectHex(alloc, &mac, "2a090d7c1155251ab86445447d060335"); // from upstream C dump_vectors

    aesCmacV4(msg64[0..20], &mac);
    try testutil.expectHex(alloc, &mac, "268a68935873a958f7d05c7f3699fb82"); // from upstream C dump_vectors

    aesCmacV4(msg64[0..34], &mac);
    try testutil.expectHex(alloc, &mac, "ba177194ba0223ab1f4441bfe8a3d782"); // from upstream C dump_vectors
}

test "v6 AES reference vector" {
    const alloc = std.testing.allocator;
    const zero: [16]u8 = @splat(0);
    const enc = aesV6EncryptBlock(&zero);
    try testutil.expectHex(alloc, &enc, "8ca59de0c483c04aa7026a22d6dd208e"); // from upstream C dump_vectors
}

test "v6 key schedule XOR" {
    // After the standard 128-bit expansion, v6 XORs 0x73/0x09/0xE4 into the
    // first byte of round keys 4/6/8 (rk offsets 64/96/128) — docs/migration.md §3.2.
    const std_rk = expandKey(4, &aes_key_v6.v6, false);
    const v6_rk = expandKey(4, &aes_key_v6.v6, true);

    for (0..std_rk.len) |i| {
        const expected_diff: u8 = switch (i) {
            64 => 0x73,
            96 => 0x09,
            128 => 0xE4,
            else => 0,
        };
        try std.testing.expectEqual(std_rk[i] ^ expected_diff, v6_rk[i]);
    }
}

test "HMAC-SHA256 reference vector" {
    const alloc = std.testing.allocator;
    const key: [16]u8 = @splat(0);
    const data: [32]u8 = @splat(0);
    var out: [32]u8 = undefined;
    hmacSha256(&key, &data, &out);
    try testutil.expectHex(alloc, &out, "33ad0a1c607ec03b09e6cd9893680ce210adf300aa1f2660e1b22e10f170f92a"); // from upstream C dump_vectors
}

test "v5 AES reference vector" {
    const alloc = std.testing.allocator;
    const zero: [16]u8 = @splat(0);
    const enc = aesEncryptBlock(&aes_key_v5, zero);
    try testutil.expectHex(alloc, &enc, "ec7c7e75b1923978eac4b2d2260235d5"); // from upstream C dump_vectors
}

test "v6 AES decrypt reference vector" {
    const alloc = std.testing.allocator;
    const zero: [16]u8 = @splat(0);
    const enc = aesEncryptBlock(&aes_key_v6, zero);
    const dec = aesDecryptBlock(&aes_key_v6, enc);
    try testutil.expectHex(alloc, &dec, "00000000000000000000000000000000"); // round-trip, not a wire vector
}

test "v6 CBC reference vectors" {
    const alloc = std.testing.allocator;

    var data: [64]u8 = @splat(0);
    const iv: [16]u8 = @splat(0);

    const new_len = aesCbcEncrypt(&aes_key_v6, &iv, data[0..32], data[0..]);
    try std.testing.expectEqual(@as(usize, 48), new_len);

    try testutil.expectHex(alloc, data[0..48], "8ca59de0c483c04aa7026a22d6dd208e43abf3a9a6b76d992a2c6b1732e80c8ca39d3d0e063cefedecf8cc6e09d14eac"); // from upstream C dump_vectors

    aesCbcDecrypt(&aes_key_v6, &iv, data[0..48]);
    try testutil.expectHex(alloc, data[0..48], "000000000000000000000000000000000000000000000000000000000000000010101010101010101010101010101010"); // from upstream C dump_vectors
}

test "AesCmacV4 leaves input unchanged" {
    // Zig uses a separate pad buffer; the C reference wrote the 0x80 padding
    // byte into the input buffer — docs/migration.md §5.
    var msg: [34]u8 = @splat(0xAB);
    const original = msg;
    var mac: Block = undefined;
    aesCmacV4(&msg, &mac);
    try std.testing.expectEqualSlices(u8, &original, &msg);
}

test "the key width is part of the type" {
    // Each `Key` variant holds a fixed-size array, so a key of another width cannot be
    // passed to the cipher at all — the misuse the C reference turns into a
    // key-schedule overflow.
    comptime std.debug.assert(@FieldType(Key, "v4") == [20]u8);
    comptime std.debug.assert(@FieldType(Key, "v5") == [16]u8);
    comptime std.debug.assert(@FieldType(Key, "v6") == [16]u8);

    // Every variant round-trips a block, which also exercises each (nk, is_v6)
    // pair the switch in `aesEncryptBlock` can select.
    const zero: Block = @splat(0);
    for ([_]Key{ aes_key_v4, aes_key_v5, aes_key_v6 }) |key| {
        const enc = aesEncryptBlock(&key, zero);
        try std.testing.expectEqual(zero, aesDecryptBlock(&key, enc));
    }

    // The same plaintext under v5 and v6 keys must differ, i.e. the variant is
    // not being ignored.
    try std.testing.expect(!std.mem.eql(u8, &aesEncryptBlock(&aes_key_v5, zero), &aesEncryptBlock(&aes_key_v6, zero)));
}

test "in-place and separate-buffer CBC encryption agree" {
    const iv: Block = @splat(0x5a);
    for ([_]usize{ 0, 1, 15, 16, 17, 32 }) |n| {
        var plain: [64]u8 = undefined;
        for (&plain, 0..) |*b, i| b.* = @intCast(i);
        const prefix = plain[0..n];

        var in_place: [64]u8 = @splat(0);
        @memcpy(in_place[0..n], prefix);
        const in_place_len = aesCbcEncrypt(&aes_key_v6, &iv, in_place[0..n], &in_place);

        var separate: [64]u8 = @splat(0);
        const separate_len = aesCbcEncrypt(&aes_key_v6, &iv, prefix, separate[0..]);

        try std.testing.expectEqual(in_place_len, separate_len);
        try std.testing.expectEqualSlices(u8, in_place[0..in_place_len], separate[0..separate_len]);
        try std.testing.expectEqual((n / 16 + 1) * 16, in_place_len);
    }
}

test "CBC decrypt of an empty slice is a no-op" {
    // The C reference computes `data + len - 16` here and touches memory before
    // the buffer; an empty slice must simply do nothing.
    var data: [16]u8 = @splat(0xAA);
    const before = data;
    aesCbcDecrypt(&aes_key_v6, null, data[0..0]);
    try std.testing.expectEqualSlices(u8, &before, &data);
}
