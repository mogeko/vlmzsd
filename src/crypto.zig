//! Crypto primitives reimplemented to match the vlmcsd reference byte-for-byte.
//!
//! AES is implemented from scratch (FIPS-197) because the reference uses
//! parameters `std.crypto` does not support:
//!   * v4 uses a 160-bit key (Rijndael, Nk=5 → 11 rounds);
//!   * v6 XORs 0x73/0x09/0xE4 into the first byte of round keys 4/6/8 after a
//!     standard 128-bit key expansion.
//! SHA-256 and HMAC-SHA256 are standard and use `std.crypto`.

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

const aes_key_v4 = [20]u8{ 0x05, 0x3d, 0x83, 0x07, 0xf9, 0xe5, 0xf0, 0x88, 0xeb, 0x5e, 0xa6, 0x68, 0x6c, 0xf0, 0x37, 0xc7, 0xe4, 0xef, 0xd2, 0xd6 };
const aes_key_v5 = [16]u8{ 0xcd, 0x7e, 0x79, 0x6f, 0x2a, 0xb2, 0x5d, 0xcb, 0x55, 0xff, 0xc8, 0xef, 0x83, 0x64, 0xc4, 0x70 };
const aes_key_v6 = [16]u8{ 0xa9, 0x4a, 0x41, 0x95, 0xe2, 0x01, 0x43, 0x2d, 0x9b, 0xcb, 0x46, 0x04, 0x05, 0xd8, 0x4a, 0x21 };

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

/// v4 MAC: CBC-MAC with a zero IV and ISO 9797-1 padding (0x80...) under
/// AES with the 160-bit `AesKeyV4`. `message.len` must be a multiple of 16.
pub fn aesCmacV4(message: []const u8, out: *Block) void {
    std.debug.assert(message.len % 16 == 0);

    const rk = expandKey(5, &aes_key_v4, false);
    var mac: Block = [_]u8{0} ** 16;

    var offset: usize = 0;
    while (offset < message.len) : (offset += 16) {
        var block: Block = undefined;
        @memcpy(block[0..], message[offset..][0..16]);
        for (0..16) |i| mac[i] ^= block[i];
        mac = aesEncrypt(5, mac, &rk);
    }

    var pad: Block = [_]u8{0} ** 16;
    pad[0] = 0x80;
    for (0..16) |i| mac[i] ^= pad[i];
    mac = aesEncrypt(5, mac, &rk);

    out.* = mac;
}

/// AES-encrypt one block with a 16- or 20-byte key. `is_v6` selects the
/// non-standard v6 key-schedule modification (16-byte keys only).
pub fn aesEncryptBlock(key: []const u8, is_v6: bool, block: Block) Block {
    return switch (key.len) {
        16 => blk: {
            const rk = expandKey(4, key, is_v6);
            break :blk aesEncrypt(4, block, &rk);
        },
        20 => blk: {
            const rk = expandKey(5, key, false);
            break :blk aesEncrypt(5, block, &rk);
        },
        else => unreachable,
    };
}

/// AES-decrypt one block (inverse of `aesEncryptBlock`).
pub fn aesDecryptBlock(key: []const u8, is_v6: bool, block: Block) Block {
    return switch (key.len) {
        16 => blk: {
            const rk = expandKey(4, key, is_v6);
            break :blk aesDecrypt(4, block, &rk);
        },
        20 => blk: {
            const rk = expandKey(5, key, false);
            break :blk aesDecrypt(5, block, &rk);
        },
        else => unreachable,
    };
}

/// v6 AES: encrypt one block under `AesKeyV6` with the non-standard v6 key
/// schedule modification.
pub fn aesV6EncryptBlock(block: *const Block) Block {
    return aesEncryptBlock(&aes_key_v6, true, block.*);
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

/// CBC-encrypt `data[0..len]` in place with PKCS#7 padding (always pads).
/// `data` must have capacity for the padded length. Returns the padded length.
pub fn aesCbcEncrypt(key: []const u8, is_v6: bool, iv: ?*const Block, data: []u8, len: usize) usize {
    const pad: usize = if (len % 16 == 0) 16 else 16 - (len % 16);
    const new_len = len + pad;
    std.debug.assert(data.len >= new_len);
    @memset(data[len..new_len], @intCast(pad));
    switch (key.len) {
        16 => {
            const rk = expandKey(4, key, is_v6);
            cbcEncrypt(4, &rk, iv, data[0..new_len]);
        },
        20 => {
            const rk = expandKey(5, key, false);
            cbcEncrypt(5, &rk, iv, data[0..new_len]);
        },
        else => unreachable,
    }
    return new_len;
}

/// CBC-decrypt `data[0..len]` in place. `len` must be a multiple of 16.
pub fn aesCbcDecrypt(key: []const u8, is_v6: bool, iv: ?*const Block, data: []u8, len: usize) void {
    switch (key.len) {
        16 => {
            const rk = expandKey(4, key, is_v6);
            cbcDecrypt(4, &rk, iv, data[0..len]);
        },
        20 => {
            const rk = expandKey(5, key, false);
            cbcDecrypt(5, &rk, iv, data[0..len]);
        },
        else => unreachable,
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

test "v4 CMAC reference vectors" {
    const alloc = std.testing.allocator;

    var msg32 = [_]u8{0} ** 32;
    var mac: Block = undefined;

    aesCmacV4(&msg32, &mac);
    const hex = try testutil.hexDump(alloc, &mac);
    defer alloc.free(hex);
    try testutil.expectBytes(hex, "1c3cb37a2a7283b1f2158220eb321c46");

    aesCmacV4(msg32[0..16], &mac);
    const hex16 = try testutil.hexDump(alloc, &mac);
    defer alloc.free(hex16);
    try testutil.expectBytes(hex16, "2a090d7c1155251ab86445447d060335");
}

test "v6 AES reference vector" {
    const alloc = std.testing.allocator;
    const zero = [_]u8{0} ** 16;
    const enc = aesV6EncryptBlock(&zero);
    const hex = try testutil.hexDump(alloc, &enc);
    defer alloc.free(hex);
    try testutil.expectBytes(hex, "8ca59de0c483c04aa7026a22d6dd208e");
}

test "HMAC-SHA256 reference vector" {
    const alloc = std.testing.allocator;
    const key = [_]u8{0} ** 16;
    const data = [_]u8{0} ** 32;
    var out: [32]u8 = undefined;
    hmacSha256(&key, &data, &out);
    const hex = try testutil.hexDump(alloc, &out);
    defer alloc.free(hex);
    try testutil.expectBytes(hex, "33ad0a1c607ec03b09e6cd9893680ce210adf300aa1f2660e1b22e10f170f92a");
}

test "v5 AES reference vector" {
    const alloc = std.testing.allocator;
    const zero = [_]u8{0} ** 16;
    const enc = aesEncryptBlock(&aes_key_v5, false, zero);
    const hex = try testutil.hexDump(alloc, &enc);
    defer alloc.free(hex);
    try testutil.expectBytes(hex, "ec7c7e75b1923978eac4b2d2260235d5");
}

test "v6 AES decrypt reference vector" {
    const alloc = std.testing.allocator;
    const zero = [_]u8{0} ** 16;
    const enc = aesEncryptBlock(&aes_key_v6, true, zero);
    const dec = aesDecryptBlock(&aes_key_v6, true, enc);
    const hex = try testutil.hexDump(alloc, &dec);
    defer alloc.free(hex);
    try testutil.expectBytes(hex, "00000000000000000000000000000000");
}

test "v6 CBC reference vectors" {
    const alloc = std.testing.allocator;

    var data: [64]u8 = [_]u8{0} ** 64;
    const iv = [_]u8{0} ** 16;

    const new_len = aesCbcEncrypt(&aes_key_v6, true, &iv, data[0..], 32);
    try std.testing.expectEqual(@as(usize, 48), new_len);

    const enc_hex = try testutil.hexDump(alloc, data[0..48]);
    defer alloc.free(enc_hex);
    try testutil.expectBytes(enc_hex, "8ca59de0c483c04aa7026a22d6dd208e43abf3a9a6b76d992a2c6b1732e80c8ca39d3d0e063cefedecf8cc6e09d14eac");

    aesCbcDecrypt(&aes_key_v6, true, &iv, data[0..48], 48);
    const dec_hex = try testutil.hexDump(alloc, data[0..48]);
    defer alloc.free(dec_hex);
    try testutil.expectBytes(dec_hex, "000000000000000000000000000000000000000000000000000000000000000010101010101010101010101010101010");
}
