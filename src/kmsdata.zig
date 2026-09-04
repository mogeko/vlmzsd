//! Parser for the vlmcsd `.kmd` binary data file.
//!
//! The format is a little-endian packed structure tree, parsed here field by
//! field (no `@ptrCast` to padded structs) to match `loadKmsData` in the
//! upstream vlmcsd `helpers.c` (see `docs/migration.md`).

const std = @import("std");
const testutil = @import("testutil.zig");

const Allocator = std.mem.Allocator;

const header_size = 72;
const csvlk_size = 32;
const item_size = 32;
const hostbuild_size = 32;

comptime {
    // `.kmd` record sizes — docs/migration.md §3.4.
    std.debug.assert(header_size == 72);
    std.debug.assert(csvlk_size == 32);
    std.debug.assert(item_size == 32);
    std.debug.assert(hostbuild_size == 32);
}

pub const CsvlkData = struct {
    epid: []const u8,
    /// Human-readable CSVLC name (the string immediately following `epid` in
    /// the string pool) — used for `--epid <name>=<epid>` lookups.
    name: []const u8,
    release_date: i64,
    group_id: u32,
    min_key_id: u32,
    max_key_id: u32,
    min_active_clients: u8,
};

pub const VlmcsdData = struct {
    guid: [16]u8,
    name: []const u8,
    app_index: u8,
    kms_index: u8,
    protocol_version: u8,
    n_count_policy: u8,
    is_retail: u8,
    is_preview: u8,
    epid_index: u8,
};

pub const HostBuild = struct {
    display_name: []const u8,
    release_date: i64,
    build_number: i32,
    platform_id: i32,
    flags: u32,
};

pub const KmsData = struct {
    minor_ver: u16,
    major_ver: u16,
    flags: u8,
    csvlk: []CsvlkData,
    /// App + KMS + SKU items, contiguous in the file in that order.
    items: []VlmcsdData,
    app_count: usize,
    kms_count: usize,
    sku_count: usize,
    host_builds: []HostBuild,

    pub fn apps(self: *const KmsData) []VlmcsdData {
        return self.items[0..self.app_count];
    }

    pub fn kms(self: *const KmsData) []VlmcsdData {
        return self.items[self.app_count..][0..self.kms_count];
    }

    pub fn skus(self: *const KmsData) []VlmcsdData {
        return self.items[self.app_count + self.kms_count ..];
    }

    pub fn deinit(self: *KmsData, allocator: Allocator) void {
        allocator.free(self.items);
        allocator.free(self.csvlk);
        allocator.free(self.host_builds);
    }
};

fn readLe(comptime T: type, raw: []const u8, offset: usize) T {
    const n = @divExact(@typeInfo(T).int.bits, 8);
    return std.mem.readInt(T, raw[offset..][0..n].ptr[0..n], .little);
}

fn cString(raw: []const u8, offset: usize) error{InvalidFormat}![]const u8 {
    if (offset >= raw.len) return error.InvalidFormat;
    var end = offset;
    while (end < raw.len and raw[end] != 0) : (end += 1) {}
    if (end >= raw.len) return error.InvalidFormat;
    return raw[offset..end];
}

pub fn parse(allocator: Allocator, raw: []const u8) !KmsData {
    if (raw.len < header_size) return error.InvalidFormat;
    if (!std.mem.eql(u8, raw[0..4], "KMD\x00")) return error.InvalidFormat;
    // Mirrors `loadKmsData` (`data[size-1] != 0` → format error when
    // UNSAFE_DATA_LOAD is off).
    if (raw[raw.len - 1] != 0) return error.InvalidFormat;

    const minor_ver = readLe(u16, raw, 4);
    const major_ver = readLe(u16, raw, 6);
    if (major_ver != 2) return error.InvalidFormat;

    const flags = raw[9];
    const csvlk_count: usize = raw[8];
    const app_count: usize = @intCast(readLe(u32, raw, 12));
    const kms_count: usize = @intCast(readLe(u32, raw, 16));
    const sku_count: usize = @intCast(readLe(u32, raw, 20));
    const hostbuild_count: usize = @intCast(readLe(u32, raw, 24));

    const app_offset: usize = @intCast(readLe(u64, raw, 32));
    const hostbuild_offset: usize = @intCast(readLe(u64, raw, 56));

    // Basic bounds checks (the file is trusted, but avoid wild allocations).
    const total_items = app_count + kms_count + sku_count;
    if (header_size + csvlk_count * csvlk_size > raw.len) return error.InvalidFormat;
    if (app_offset + total_items * item_size > raw.len) return error.InvalidFormat;
    if (hostbuild_offset + hostbuild_count * hostbuild_size > raw.len) return error.InvalidFormat;

    const csvlk = try allocator.alloc(CsvlkData, csvlk_count);
    errdefer allocator.free(csvlk);
    for (csvlk, 0..) |*rec, i| {
        const base = header_size + i * csvlk_size;
        const epid_offset: usize = @intCast(readLe(u64, raw, base));
        const epid = try cString(raw, epid_offset);
        const name = try cString(raw, epid_offset + epid.len + 1);
        rec.* = .{
            .epid = epid,
            .name = name,
            .release_date = readLe(i64, raw, base + 8),
            .group_id = readLe(u32, raw, base + 16),
            .min_key_id = readLe(u32, raw, base + 20),
            .max_key_id = readLe(u32, raw, base + 24),
            .min_active_clients = raw[base + 28],
        };
    }

    const items = try allocator.alloc(VlmcsdData, total_items);
    errdefer allocator.free(items);
    for (items, 0..) |*item, i| {
        const base = app_offset + i * item_size;
        var guid: [16]u8 = undefined;
        @memcpy(guid[0..], raw[base..][0..16]);
        item.* = .{
            .guid = guid,
            .name = try cString(raw, @intCast(readLe(u64, raw, base + 16))),
            .app_index = raw[base + 24],
            .kms_index = raw[base + 25],
            .protocol_version = raw[base + 26],
            .n_count_policy = raw[base + 27],
            .is_retail = raw[base + 28],
            .is_preview = raw[base + 29],
            .epid_index = raw[base + 30],
        };
    }

    const host_builds = try allocator.alloc(HostBuild, hostbuild_count);
    errdefer allocator.free(host_builds);
    for (host_builds, 0..) |*hb, i| {
        const base = hostbuild_offset + i * hostbuild_size;
        hb.* = .{
            .display_name = try cString(raw, @intCast(readLe(u64, raw, base))),
            .release_date = readLe(i64, raw, base + 8),
            .build_number = readLe(i32, raw, base + 16),
            .platform_id = readLe(i32, raw, base + 20),
            .flags = readLe(u32, raw, base + 24),
        };
    }

    return .{
        .minor_ver = minor_ver,
        .major_ver = major_ver,
        .flags = flags,
        .csvlk = csvlk,
        .items = items,
        .app_count = app_count,
        .kms_count = kms_count,
        .sku_count = sku_count,
        .host_builds = host_builds,
    };
}

test "parse embedded .kmd data" {
    const alloc = std.testing.allocator;

    const raw: []const u8 = @embedFile("vlmcsd.kmd");
    var data = try parse(alloc, raw);
    defer data.deinit(alloc);

    try std.testing.expectEqual(@as(u16, 2), data.major_ver);
    try std.testing.expectEqual(@as(u16, 0), data.minor_ver);
    try std.testing.expectEqual(@as(u8, 1), data.flags);

    try std.testing.expectEqual(@as(usize, 6), data.csvlk.len);
    try std.testing.expectEqual(@as(usize, 3), data.app_count);
    try std.testing.expectEqual(@as(usize, 29), data.kms_count);
    try std.testing.expectEqual(@as(usize, 202), data.sku_count);
    try std.testing.expectEqual(@as(usize, 234), data.items.len);
    try std.testing.expectEqual(@as(usize, 6), data.host_builds.len);

    try testutil.expectBytes(data.csvlk[0].epid, "06401-00206-560-594696-03-1033-9600.0000-2962018");
    try testutil.expectBytes(data.csvlk[0].name, "Windows");
    try std.testing.expectEqual(@as(i64, 1538438400), data.csvlk[0].release_date);
    try std.testing.expectEqual(@as(u32, 206), data.csvlk[0].group_id);
    try std.testing.expectEqual(@as(u32, 551000000), data.csvlk[0].min_key_id);
    try std.testing.expectEqual(@as(u32, 570999999), data.csvlk[0].max_key_id);
    try std.testing.expectEqual(@as(u8, 0), data.csvlk[0].min_active_clients);

    try testutil.expectBytes(data.items[0].guid[0..], "\x34\x27\xc9\x55\x82\xd6\x71\x4d\x98\x3e\xd6\xec\x3f\x16\x05\x9f");
    try testutil.expectBytes(data.items[0].name, "Windows");
    try std.testing.expectEqual(@as(u8, 50), data.items[0].n_count_policy);
    try std.testing.expectEqual(@as(u8, 0), data.items[0].app_index);
    try std.testing.expectEqual(@as(u8, 0), data.items[0].kms_index);
    try std.testing.expectEqual(@as(u8, 0), data.items[0].protocol_version);
    try std.testing.expectEqual(@as(u8, 0), data.items[0].is_retail);
    try std.testing.expectEqual(@as(u8, 0), data.items[0].is_preview);
    try std.testing.expectEqual(@as(u8, 0), data.items[0].epid_index);

    try std.testing.expectEqual(@as(i32, 17763), data.host_builds[0].build_number);
    try std.testing.expectEqual(@as(i32, 3612), data.host_builds[0].platform_id);
    try std.testing.expectEqual(@as(u32, 7), data.host_builds[0].flags);
    try std.testing.expectEqual(@as(i64, 1538438400), data.host_builds[0].release_date);
    try testutil.expectBytes(data.host_builds[0].display_name, "Windows 10 1809 / Server 2019");
}

test "kmd header fields" {
    // 72-byte header + default-data size pinned to docs/migration.md §3.4.
    const raw: []const u8 = @embedFile("vlmcsd.kmd");

    try std.testing.expectEqual(@as(usize, 15079), raw.len);
    try std.testing.expectEqualStrings("KMD", raw[0..3]); // Magic
    try std.testing.expectEqual(@as(u8, 0), raw[3]); // Magic[3] = NUL
    try std.testing.expectEqual(@as(u16, 0), readLe(u16, raw, 4)); // MinorVer
    try std.testing.expectEqual(@as(u16, 2), readLe(u16, raw, 6)); // MajorVer
    try std.testing.expectEqual(@as(u8, 6), raw[8]); // CsvlkCount
    try std.testing.expectEqual(@as(u8, 1), raw[9]); // Flags
    try std.testing.expectEqual(@as(u32, 3), readLe(u32, raw, 12)); // AppItemCount
    try std.testing.expectEqual(@as(u32, 29), readLe(u32, raw, 16)); // KmsItemCount
    try std.testing.expectEqual(@as(u32, 202), readLe(u32, raw, 20)); // SkuItemCount
    try std.testing.expectEqual(@as(u32, 6), readLe(u32, raw, 24)); // HostBuildCount
    try std.testing.expectEqual(@as(u64, 264), readLe(u64, raw, 32)); // AppItemOffset
    try std.testing.expectEqual(@as(u64, 7752), readLe(u64, raw, 56)); // HostBuildOffset
    try std.testing.expectEqual(@as(u8, 0), raw[raw.len - 1]); // trailing NUL
}
