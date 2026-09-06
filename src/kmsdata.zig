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

fn writeLe(comptime T: type, raw: []u8, offset: usize, value: T) void {
    const n = @divExact(@typeInfo(T).int.bits, 8);
    std.mem.writeInt(T, raw[offset..][0..n], value, .little);
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

/// Serialize `data` back into a `.kmd` byte buffer (the inverse of `parse`).
/// The string pool is rebuilt without deduplication, so the result is
/// semantically identical to the source but not necessarily byte-identical.
/// The caller owns the returned slice.
pub fn write(allocator: Allocator, data: *const KmsData) ![]u8 {
    if (data.major_ver != 2) return error.InvalidFormat;
    const csvlk_count = data.csvlk.len;
    const total_items = data.items.len;
    const hb_count = data.host_builds.len;
    if (csvlk_count > std.math.maxInt(u8)) return error.InvalidFormat;
    if (data.app_count + data.kms_count + data.sku_count != total_items) return error.InvalidFormat;

    const app_offset = header_size + csvlk_count * csvlk_size;
    const hostbuild_offset = app_offset + total_items * item_size;
    const string_pool_offset = hostbuild_offset + hb_count * hostbuild_size;

    // Build the string pool, recording each field's offset within it. The
    // CSVLC `name` follows its `epid` with a NUL between them (see `parse`).
    var pool: std.ArrayList(u8) = .empty;
    defer pool.deinit(allocator);

    const epid_offsets = try allocator.alloc(usize, csvlk_count);
    defer allocator.free(epid_offsets);
    for (data.csvlk, 0..) |c, i| {
        epid_offsets[i] = pool.items.len;
        try pool.appendSlice(allocator, c.epid);
        try pool.append(allocator, 0);
        try pool.appendSlice(allocator, c.name);
        try pool.append(allocator, 0);
    }

    const item_name_offsets = try allocator.alloc(usize, total_items);
    defer allocator.free(item_name_offsets);
    for (data.items, 0..) |it, i| {
        item_name_offsets[i] = pool.items.len;
        try pool.appendSlice(allocator, it.name);
        try pool.append(allocator, 0);
    }

    const hb_name_offsets = try allocator.alloc(usize, hb_count);
    defer allocator.free(hb_name_offsets);
    for (data.host_builds, 0..) |hb, i| {
        hb_name_offsets[i] = pool.items.len;
        try pool.appendSlice(allocator, hb.display_name);
        try pool.append(allocator, 0);
    }

    if (pool.items.len == 0) try pool.append(allocator, 0); // trailing NUL

    const total_size = string_pool_offset + pool.items.len;
    const buf = try allocator.alloc(u8, total_size);
    errdefer allocator.free(buf);
    @memset(buf, 0);

    // Header.
    @memcpy(buf[0..4], "KMD\x00");
    writeLe(u16, buf, 4, data.minor_ver);
    writeLe(u16, buf, 6, data.major_ver);
    buf[8] = @intCast(csvlk_count);
    buf[9] = data.flags;
    writeLe(u32, buf, 12, @intCast(data.app_count));
    writeLe(u32, buf, 16, @intCast(data.kms_count));
    writeLe(u32, buf, 20, @intCast(data.sku_count));
    writeLe(u32, buf, 24, @intCast(hb_count));
    writeLe(u64, buf, 32, app_offset);
    writeLe(u64, buf, 56, hostbuild_offset);

    // CSVLC records.
    for (data.csvlk, 0..) |c, i| {
        const base = header_size + i * csvlk_size;
        writeLe(u64, buf, base, string_pool_offset + epid_offsets[i]);
        writeLe(i64, buf, base + 8, c.release_date);
        writeLe(u32, buf, base + 16, c.group_id);
        writeLe(u32, buf, base + 20, c.min_key_id);
        writeLe(u32, buf, base + 24, c.max_key_id);
        buf[base + 28] = c.min_active_clients;
    }

    // Item records (app + kms + sku, contiguous).
    for (data.items, 0..) |it, i| {
        const base = app_offset + i * item_size;
        @memcpy(buf[base..][0..16], it.guid[0..]);
        writeLe(u64, buf, base + 16, string_pool_offset + item_name_offsets[i]);
        buf[base + 24] = it.app_index;
        buf[base + 25] = it.kms_index;
        buf[base + 26] = it.protocol_version;
        buf[base + 27] = it.n_count_policy;
        buf[base + 28] = it.is_retail;
        buf[base + 29] = it.is_preview;
        buf[base + 30] = it.epid_index;
    }

    // HostBuild records.
    for (data.host_builds, 0..) |hb, i| {
        const base = hostbuild_offset + i * hostbuild_size;
        writeLe(u64, buf, base, string_pool_offset + hb_name_offsets[i]);
        writeLe(i64, buf, base + 8, hb.release_date);
        writeLe(i32, buf, base + 16, hb.build_number);
        writeLe(i32, buf, base + 20, hb.platform_id);
        writeLe(u32, buf, base + 24, hb.flags);
    }

    // String pool.
    @memcpy(buf[string_pool_offset..], pool.items);

    return buf;
}

test "kmd write round-trip" {
    const alloc = std.testing.allocator;
    const raw: []const u8 = @embedFile("vlmcsd.kmd");

    var data = try parse(alloc, raw);
    defer data.deinit(alloc);

    const rebuilt = try write(alloc, &data);
    defer alloc.free(rebuilt);

    var data2 = try parse(alloc, rebuilt);
    defer data2.deinit(alloc);

    try std.testing.expectEqual(data.minor_ver, data2.minor_ver);
    try std.testing.expectEqual(data.major_ver, data2.major_ver);
    try std.testing.expectEqual(data.flags, data2.flags);
    try std.testing.expectEqual(data.csvlk.len, data2.csvlk.len);
    try std.testing.expectEqual(data.app_count, data2.app_count);
    try std.testing.expectEqual(data.kms_count, data2.kms_count);
    try std.testing.expectEqual(data.sku_count, data2.sku_count);
    try std.testing.expectEqual(data.items.len, data2.items.len);
    try std.testing.expectEqual(data.host_builds.len, data2.host_builds.len);

    for (data.csvlk, data2.csvlk) |a, b| {
        try std.testing.expectEqualStrings(a.epid, b.epid);
        try std.testing.expectEqualStrings(a.name, b.name);
        try std.testing.expectEqual(a.release_date, b.release_date);
        try std.testing.expectEqual(a.group_id, b.group_id);
        try std.testing.expectEqual(a.min_key_id, b.min_key_id);
        try std.testing.expectEqual(a.max_key_id, b.max_key_id);
        try std.testing.expectEqual(a.min_active_clients, b.min_active_clients);
    }
    for (data.items, data2.items) |a, b| {
        try std.testing.expectEqualSlices(u8, a.guid[0..], b.guid[0..]);
        try std.testing.expectEqualStrings(a.name, b.name);
        try std.testing.expectEqual(a.app_index, b.app_index);
        try std.testing.expectEqual(a.kms_index, b.kms_index);
        try std.testing.expectEqual(a.protocol_version, b.protocol_version);
        try std.testing.expectEqual(a.n_count_policy, b.n_count_policy);
        try std.testing.expectEqual(a.is_retail, b.is_retail);
        try std.testing.expectEqual(a.is_preview, b.is_preview);
        try std.testing.expectEqual(a.epid_index, b.epid_index);
    }
    for (data.host_builds, data2.host_builds) |a, b| {
        try std.testing.expectEqualStrings(a.display_name, b.display_name);
        try std.testing.expectEqual(a.release_date, b.release_date);
        try std.testing.expectEqual(a.build_number, b.build_number);
        try std.testing.expectEqual(a.platform_id, b.platform_id);
        try std.testing.expectEqual(a.flags, b.flags);
    }
}

test "parse embedded .kmd data" {
    const alloc = std.testing.allocator;

    const raw: []const u8 = @embedFile("vlmcsd.kmd");
    var data = try parse(alloc, raw);
    defer data.deinit(alloc);

    try std.testing.expectEqual(@as(u16, 2), data.major_ver);
    try std.testing.expectEqual(@as(u16, 0), data.minor_ver);
    try std.testing.expectEqual(@as(u8, 1), data.flags);

    try std.testing.expectEqual(@as(usize, 8), data.csvlk.len);
    try std.testing.expectEqual(@as(usize, 3), data.app_count);
    try std.testing.expectEqual(@as(usize, 36), data.kms_count);
    try std.testing.expectEqual(@as(usize, 261), data.sku_count);
    try std.testing.expectEqual(@as(usize, 300), data.items.len);
    try std.testing.expectEqual(@as(usize, 8), data.host_builds.len);

    try testutil.expectBytes(data.csvlk[0].epid, "03612-04919-019-192355-03-1033-17763.0000-2622024");
    try testutil.expectBytes(data.csvlk[0].name, "Windows");
    try std.testing.expectEqual(@as(i64, 1714089600), data.csvlk[0].release_date);
    try std.testing.expectEqual(@as(u32, 4919), data.csvlk[0].group_id);
    try std.testing.expectEqual(@as(u32, 20000), data.csvlk[0].min_key_id);
    try std.testing.expectEqual(@as(u32, 20019999), data.csvlk[0].max_key_id);
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

    try std.testing.expectEqual(@as(i32, 26100), data.host_builds[0].build_number);
    try std.testing.expectEqual(@as(i32, 3612), data.host_builds[0].platform_id);
    try std.testing.expectEqual(@as(u32, 7), data.host_builds[0].flags);
    try std.testing.expectEqual(@as(i64, 1714089600), data.host_builds[0].release_date);
    try testutil.expectBytes(data.host_builds[0].display_name, "Windows 11 24H2 / Server 2025");
}

test "kmd header fields" {
    // 72-byte header + default-data size pinned to docs/migration.md §3.4.
    const raw: []const u8 = @embedFile("vlmcsd.kmd");

    try std.testing.expectEqual(@as(usize, 19371), raw.len);
    try std.testing.expectEqualStrings("KMD", raw[0..3]); // Magic
    try std.testing.expectEqual(@as(u8, 0), raw[3]); // Magic[3] = NUL
    try std.testing.expectEqual(@as(u16, 0), readLe(u16, raw, 4)); // MinorVer
    try std.testing.expectEqual(@as(u16, 2), readLe(u16, raw, 6)); // MajorVer
    try std.testing.expectEqual(@as(u8, 8), raw[8]); // CsvlkCount
    try std.testing.expectEqual(@as(u8, 1), raw[9]); // Flags
    try std.testing.expectEqual(@as(u32, 3), readLe(u32, raw, 12)); // AppItemCount
    try std.testing.expectEqual(@as(u32, 36), readLe(u32, raw, 16)); // KmsItemCount
    try std.testing.expectEqual(@as(u32, 261), readLe(u32, raw, 20)); // SkuItemCount
    try std.testing.expectEqual(@as(u32, 8), readLe(u32, raw, 24)); // HostBuildCount
    try std.testing.expectEqual(@as(u64, 328), readLe(u64, raw, 32)); // AppItemOffset
    try std.testing.expectEqual(@as(u64, 9928), readLe(u64, raw, 56)); // HostBuildOffset
    try std.testing.expectEqual(@as(u8, 0), raw[raw.len - 1]); // trailing NUL
}
