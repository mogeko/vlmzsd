//! `kmdconv` — convert between the `.kmd` binary data format and JSON.
//!
//! A developer tool (not installed by default). The default direction reads a
//! JSON file and writes a `.kmd` file; `-r` reverses it (read `.kmd`, write
//! JSON). Input `-` reads stdin; output goes to stdout unless `-o <file>` is
//! given.

const std = @import("std");
const cli_helper = @import("cli_helper.zig");
const vlmzsd = @import("vlmzsd");
const kmsdata = vlmzsd.kmsdata;

const build_options = @import("build_options");
const version_display = build_options.version_display;

const Allocator = std.mem.Allocator;
const Io = std.Io;
const Json = std.json;

/// Options, in help order. One table drives parsing and the help text, so the
/// two cannot drift apart (the same contract `vlmzsd`/`vlmzs` follow). `-` is a
/// positional, described in the note below the table.
const opts_table = [_]cli_helper.Opt{
    .{ .name = "help", .short = 'h', .group = "Options", .desc = "print this help and exit" },
    .{ .name = "version", .short = 'V', .group = "Options", .desc = "print version and exit" },
    .{ .name = "reverse", .short = 'r', .group = "Options", .desc = "reverse: read a `.kmd` file, write JSON" },
    .{ .name = "output", .short = 'o', .kind = .str, .hint = "file", .group = "Options", .desc = "write output to <file> (default: derived)" },
};

/// The notes printed under the shared option table: `kmdconv` inputs and outputs
/// need more explanation than an option's one-line description.
const help_notes =
    \\
    \\Convert between the `.kmd` binary data format and JSON.
    \\
    \\Notes:
    \\  <file>       input JSON file (or a `.kmd` file with -r); `-` reads stdin
    \\  no -o        written in the current directory as <stem>.<suffix>:
    \\               `data.json` -> `data.kmd`, `data.kmd` -> `data.json`
    \\
;

/// Report a fatal error on stderr and exit with status 1.
fn fatal(io: Io, comptime fmt: []const u8, args: anytype) noreturn {
    var ebuf: [512]u8 = undefined;
    var ew = std.Io.File.writer(std.Io.File.stderr(), io, &ebuf);
    ew.interface.print(fmt, args) catch {};
    ew.interface.flush() catch {};
    std.process.exit(1);
}

/// Derive the default output path: the input's stem plus `.json` (with `-r`)
/// or `.kmd` (default), written to the current directory regardless of the
/// input's location. e.g. `dir/data.json` → `data.kmd`.
fn deriveOutputPath(gpa: Allocator, input: []const u8, reverse: bool) ![]u8 {
    const ext = if (reverse) ".json" else ".kmd";
    const stem = std.fs.path.stem(input);
    return gpa.print("{s}{s}", .{ stem, ext });
}

fn readStdin(io: Io, gpa: Allocator) ![]u8 {
    var rbuf: [8192]u8 = undefined;
    var reader = std.Io.File.reader(std.Io.File.stdin(), io, &rbuf);
    var list: std.ArrayList(u8) = .empty;
    errdefer list.deinit(gpa);
    var chunk: [8192]u8 = undefined;
    while (true) {
        const n = try reader.interface.readSliceShort(&chunk);
        if (n == 0) break;
        try list.appendSlice(gpa, chunk[0..n]);
    }
    return list.toOwnedSlice(gpa);
}

pub fn main(init: std.process.Init) !void {
    const prog: cli_helper.Program = .{
        .name = "kmdconv",
        .version_display = version_display,
        .positional_hint = "<file>",
        .extra_help = help_notes,
    };
    var res = (try cli_helper.parseProcess(init, &opts_table, prog)) orelse return;
    defer res.deinit();

    // Exactly one positional: the input file, or `-` for stdin.
    if (res.positionals.items.len == 0) {
        fatal(init.io, "kmdconv: error: missing input file (use - for stdin)\n", .{});
    }
    if (res.positionals.items.len > 1) {
        fatal(init.io, "kmdconv: error: too many positional arguments\n", .{});
    }
    const input: []const u8 = res.positionals.items[0];
    const reverse = res.hasFlag("reverse");
    const output_path = res.get("output");

    // Read input.
    var input_data: []const u8 = undefined;
    var input_owned = false;
    defer if (input_owned) init.gpa.free(@constCast(input_data));
    if (std.mem.eql(u8, input, "-")) {
        input_data = try readStdin(init.io, init.gpa);
        input_owned = true;
    } else {
        input_data = std.Io.Dir.readFileAlloc(std.Io.Dir.cwd(), init.io, input, init.gpa, .unlimited) catch |e|
            fatal(init.io, "kmdconv: error: cannot read {s}: {s}\n", .{ input, @errorName(e) });
        input_owned = true;
    }

    // Convert.
    var output_data: []const u8 = undefined;
    var output_owned = false;
    defer if (output_owned) init.gpa.free(@constCast(output_data));
    if (reverse) {
        var arena: std.heap.ArenaAllocator = .init(init.gpa);
        defer arena.deinit();
        const data = kmsdata.parse(arena.allocator(), input_data) catch |e|
            fatal(
                init.io,
                "kmdconv: error: invalid .kmd data: {s} (is this a JSON file? remove -r to convert it to .kmd)\n",
                .{@errorName(e)},
            );
        output_data = kmsDataToJson(&data, init.gpa) catch |e|
            fatal(init.io, "kmdconv: error: cannot serialize JSON: {s}\n", .{@errorName(e)});
        output_owned = true;
    } else {
        var arena: std.heap.ArenaAllocator = .init(init.gpa);
        defer arena.deinit();
        const data = jsonToKmsData(arena.allocator(), input_data) catch |e|
            fatal(
                init.io,
                "kmdconv: error: invalid JSON input: {s} (is this a .kmd file? use -r to convert it to JSON)\n",
                .{@errorName(e)},
            );
        output_data = kmsdata.write(init.gpa, &data) catch |e|
            fatal(init.io, "kmdconv: error: cannot build .kmd data: {s}\n", .{@errorName(e)});
        output_owned = true;
    }

    // Determine the output path: `-o/--output` wins; otherwise derive the
    // input's stem plus the matching suffix in the current directory, when the
    // input is a real file (not stdin).
    var derived: ?[]u8 = null;
    defer if (derived) |p| init.gpa.free(p);
    if (output_path == null and !std.mem.eql(u8, input, "-")) {
        derived = deriveOutputPath(init.gpa, input, reverse) catch |e|
            fatal(init.io, "kmdconv: error: cannot derive output path: {s}\n", .{@errorName(e)});
    }
    const out_path: ?[]const u8 = output_path orelse derived;

    // Write output.
    if (out_path) |p| {
        std.Io.Dir.writeFile(std.Io.Dir.cwd(), init.io, .{ .sub_path = p, .data = output_data }) catch |e|
            fatal(init.io, "kmdconv: error: cannot write {s}: {s}\n", .{ p, @errorName(e) });
    } else {
        var obuf: [8192]u8 = undefined;
        var ow = std.Io.File.writer(std.Io.File.stdout(), init.io, &obuf);
        ow.interface.writeAll(output_data) catch {};
        ow.interface.flush() catch {};
    }
}

// ---------------------------------------------------------------------------
// KMS data -> JSON
// ---------------------------------------------------------------------------

fn kmsDataToJson(data: *const kmsdata.KmsData, gpa: Allocator) ![]u8 {
    var out: std.Io.Writer.Allocating = .init(gpa);
    errdefer out.deinit();
    var js: Json.Stringify = .{
        .writer = &out.writer,
        .options = .{ .whitespace = .indent_2 },
    };

    try js.beginObject();
    try js.objectField("minor_ver");
    try js.write(data.minor_ver);
    try js.objectField("major_ver");
    try js.write(data.major_ver);
    try js.objectField("flags");
    try js.write(data.flags);

    try js.objectField("csvlk");
    try js.beginArray();
    for (data.csvlk) |c| {
        try js.beginObject();
        try js.objectField("epid");
        try js.write(c.epid);
        try js.objectField("name");
        try js.write(c.name);
        try js.objectField("release_date");
        try js.write(c.release_date);
        try js.objectField("group_id");
        try js.write(c.group_id);
        try js.objectField("min_key_id");
        try js.write(c.min_key_id);
        try js.objectField("max_key_id");
        try js.write(c.max_key_id);
        try js.objectField("min_active_clients");
        try js.write(c.min_active_clients);
        try js.endObject();
    }
    try js.endArray();

    try writeItems(&js, "apps", data.apps());
    try writeItems(&js, "kms", data.kms());
    try writeItems(&js, "skus", data.skus());

    try js.objectField("hostbuilds");
    try js.beginArray();
    for (data.host_builds) |hb| {
        try js.beginObject();
        try js.objectField("display_name");
        try js.write(hb.display_name);
        try js.objectField("release_date");
        try js.write(hb.release_date);
        try js.objectField("build_number");
        try js.write(hb.build_number);
        try js.objectField("platform_id");
        try js.write(hb.platform_id);
        try js.objectField("flags");
        try js.write(hb.flags);
        try js.endObject();
    }
    try js.endArray();

    try js.endObject();
    return out.toOwnedSlice();
}

fn writeItems(js: *Json.Stringify, key: []const u8, items: []const kmsdata.VlmcsdData) !void {
    try js.objectField(key);
    try js.beginArray();
    for (items) |it| {
        const hex = std.fmt.bytesToHex(it.guid[0..], .lower);
        try js.beginObject();
        try js.objectField("guid");
        try js.write(hex[0..]);
        try js.objectField("name");
        try js.write(it.name);
        try js.objectField("app_index");
        try js.write(it.app_index);
        try js.objectField("kms_index");
        try js.write(it.kms_index);
        try js.objectField("protocol_version");
        try js.write(it.protocol_version);
        try js.objectField("n_count_policy");
        try js.write(it.n_count_policy);
        try js.objectField("is_retail");
        try js.write(it.is_retail);
        try js.objectField("is_preview");
        try js.write(it.is_preview);
        try js.objectField("epid_index");
        try js.write(it.epid_index);
        try js.endObject();
    }
    try js.endArray();
}

// ---------------------------------------------------------------------------
// JSON -> KMS data
// ---------------------------------------------------------------------------

fn jsonToKmsData(a: Allocator, text: []const u8) !kmsdata.KmsData {
    const parsed = try Json.parseFromSlice(Json.Value, a, text, .{ .parse_numbers = true });
    const obj = switch (parsed.value) {
        .object => |o| o,
        else => return error.InvalidJson,
    };

    const apps = try parseItems(a, obj.get("apps"));
    const kms = try parseItems(a, obj.get("kms"));
    const skus = try parseItems(a, obj.get("skus"));

    const items = try a.alloc(kmsdata.VlmcsdData, apps.len + kms.len + skus.len);
    @memcpy(items[0..apps.len], apps);
    @memcpy(items[apps.len..][0..kms.len], kms);
    @memcpy(items[apps.len + kms.len ..], skus);

    return .{
        .minor_ver = try getU16(obj, "minor_ver"),
        .major_ver = try getU16(obj, "major_ver"),
        .flags = try getU8(obj, "flags"),
        .csvlk = try parseCsvlk(a, obj.get("csvlk")),
        .items = items,
        .app_count = apps.len,
        .kms_count = kms.len,
        .sku_count = skus.len,
        .host_builds = try parseHostBuilds(a, obj.get("hostbuilds")),
    };
}

fn parseCsvlk(a: Allocator, v: ?Json.Value) ![]kmsdata.CsvlkData {
    const arr = switch (v orelse return error.MissingField) {
        .array => |arr| arr,
        else => return error.TypeMismatch,
    };
    const out = try a.alloc(kmsdata.CsvlkData, arr.items.len);
    for (arr.items, 0..) |item, i| {
        const obj = switch (item) {
            .object => |o| o,
            else => return error.TypeMismatch,
        };
        out[i] = .{
            .epid = try getStr(obj, "epid"),
            .name = try getStr(obj, "name"),
            .release_date = try getI64(obj, "release_date"),
            .group_id = try getU32(obj, "group_id"),
            .min_key_id = try getU32(obj, "min_key_id"),
            .max_key_id = try getU32(obj, "max_key_id"),
            .min_active_clients = try getU8(obj, "min_active_clients"),
        };
    }
    return out;
}

fn parseItems(a: Allocator, v: ?Json.Value) ![]kmsdata.VlmcsdData {
    const arr = switch (v orelse return error.MissingField) {
        .array => |arr| arr,
        else => return error.TypeMismatch,
    };
    const out = try a.alloc(kmsdata.VlmcsdData, arr.items.len);
    for (arr.items, 0..) |item, i| {
        const obj = switch (item) {
            .object => |o| o,
            else => return error.TypeMismatch,
        };
        out[i] = .{
            .guid = try parseGuid(try getStr(obj, "guid")),
            .name = try getStr(obj, "name"),
            .app_index = try getU8(obj, "app_index"),
            .kms_index = try getU8(obj, "kms_index"),
            .protocol_version = try getU8(obj, "protocol_version"),
            .n_count_policy = try getU8(obj, "n_count_policy"),
            .is_retail = try getU8(obj, "is_retail"),
            .is_preview = try getU8(obj, "is_preview"),
            .epid_index = try getU8(obj, "epid_index"),
        };
    }
    return out;
}

fn parseHostBuilds(a: Allocator, v: ?Json.Value) ![]kmsdata.HostBuild {
    const arr = switch (v orelse return error.MissingField) {
        .array => |arr| arr,
        else => return error.TypeMismatch,
    };
    const out = try a.alloc(kmsdata.HostBuild, arr.items.len);
    for (arr.items, 0..) |item, i| {
        const obj = switch (item) {
            .object => |o| o,
            else => return error.TypeMismatch,
        };
        out[i] = .{
            .display_name = try getStr(obj, "display_name"),
            .release_date = try getI64(obj, "release_date"),
            .build_number = try getI32(obj, "build_number"),
            .platform_id = try getI32(obj, "platform_id"),
            .flags = try getU32(obj, "flags"),
        };
    }
    return out;
}

fn parseGuid(s: []const u8) ![16]u8 {
    if (s.len != 32) return error.InvalidGuid;
    var guid: [16]u8 = undefined;
    _ = std.fmt.hexToBytes(guid[0..], s) catch return error.InvalidGuid;
    return guid;
}

// ---------------------------------------------------------------------------
// JSON field access helpers
// ---------------------------------------------------------------------------

fn getU8(obj: Json.ObjectMap, key: []const u8) !u8 {
    const v = obj.get(key) orelse return error.MissingField;
    return switch (v) {
        .integer => |i| std.math.cast(u8, i) orelse error.Overflow,
        else => error.TypeMismatch,
    };
}

fn getU16(obj: Json.ObjectMap, key: []const u8) !u16 {
    const v = obj.get(key) orelse return error.MissingField;
    return switch (v) {
        .integer => |i| std.math.cast(u16, i) orelse error.Overflow,
        else => error.TypeMismatch,
    };
}

fn getU32(obj: Json.ObjectMap, key: []const u8) !u32 {
    const v = obj.get(key) orelse return error.MissingField;
    return switch (v) {
        .integer => |i| std.math.cast(u32, i) orelse error.Overflow,
        else => error.TypeMismatch,
    };
}

fn getI32(obj: Json.ObjectMap, key: []const u8) !i32 {
    const v = obj.get(key) orelse return error.MissingField;
    return switch (v) {
        .integer => |i| std.math.cast(i32, i) orelse error.Overflow,
        else => error.TypeMismatch,
    };
}

fn getI64(obj: Json.ObjectMap, key: []const u8) !i64 {
    const v = obj.get(key) orelse return error.MissingField;
    return switch (v) {
        .integer => |i| i,
        else => error.TypeMismatch,
    };
}

fn getStr(obj: Json.ObjectMap, key: []const u8) ![]const u8 {
    const v = obj.get(key) orelse return error.MissingField;
    return switch (v) {
        .string => |s| s,
        else => error.TypeMismatch,
    };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "the option table accepts the documented spellings and nothing else" {
    // One table drives parsing, so this pins the forms `docs/kmdconv.md` shows
    // plus the ones the sibling binaries accept (`--opt=value`, clustered
    // shorts), which a hand-rolled parser used to reject.
    const gpa = std.testing.allocator;
    const accepted = [_][]const u8{
        "-h", "--help",
        "-V", "--version",
        "-r", "--reverse",
        "-o", "--output",
    };
    for (accepted) |arg| {
        const takes_value = std.mem.eql(u8, arg, "-o") or std.mem.eql(u8, arg, "--output");
        const args: []const []const u8 = if (takes_value) &.{ arg, "out.json" } else &.{arg};
        var res = try cli_helper.parse(gpa, &opts_table, args);
        defer res.deinit();
        try std.testing.expectEqual(@as(usize, 0), res.positionals.items.len);
    }

    {
        var res = try cli_helper.parse(gpa, &opts_table, &.{ "--output=out.json", "-r", "in.kmd" });
        defer res.deinit();
        try std.testing.expectEqualStrings("out.json", res.get("output").?);
        try std.testing.expect(res.hasFlag("reverse"));
        try std.testing.expectEqualStrings("in.kmd", res.positionals.items[0]);
    }
    {
        // `-` is the stdin positional, not an option.
        var res = try cli_helper.parse(gpa, &opts_table, &.{"-"});
        defer res.deinit();
        try std.testing.expectEqualStrings("-", res.positionals.items[0]);
    }

    try std.testing.expectError(error.UnknownOption, cli_helper.parse(gpa, &opts_table, &.{"--nope"}));
    try std.testing.expectError(error.MissingValue, cli_helper.parse(gpa, &opts_table, &.{"--output"}));
}

test "JSON round-trip reproduces the embedded .kmd byte for byte" {
    // The converter's contract: `.kmd` → JSON → `.kmd` reproduces the input.
    // The string pool is rebuilt without deduplication, so this also pins that
    // the embedded data needs none for a byte-identical result.
    const gpa = std.testing.allocator;
    const raw: []const u8 = @embedFile("vlmcsd.kmd");

    var arena: std.heap.ArenaAllocator = .init(gpa);
    defer arena.deinit();

    const data = try kmsdata.parse(arena.allocator(), raw);
    const json = try kmsDataToJson(&data, gpa);
    defer gpa.free(json);

    const converted = try jsonToKmsData(arena.allocator(), json);
    const bytes = try kmsdata.write(gpa, &converted);
    defer gpa.free(bytes);

    try std.testing.expectEqualSlices(u8, raw, bytes);
}

test "the JSON document names every field the writer needs" {
    const gpa = std.testing.allocator;

    var arena: std.heap.ArenaAllocator = .init(gpa);
    defer arena.deinit();

    const data = try kmsdata.parse(arena.allocator(), @embedFile("vlmcsd.kmd"));
    const json = try kmsDataToJson(&data, gpa);
    defer gpa.free(json);

    var parsed = try std.json.parseFromSlice(std.json.Value, gpa, json, .{ .parse_numbers = true });
    defer parsed.deinit();
    const obj = parsed.value.object;

    try std.testing.expectEqual(@as(i64, data.major_ver), obj.get("major_ver").?.integer);
    try std.testing.expectEqual(@as(i64, data.minor_ver), obj.get("minor_ver").?.integer);
    try std.testing.expectEqual(@as(i64, data.flags), obj.get("flags").?.integer);

    try std.testing.expectEqual(data.csvlk.len, obj.get("csvlk").?.array.items.len);
    try std.testing.expectEqual(data.app_count, obj.get("apps").?.array.items.len);
    try std.testing.expectEqual(data.kms_count, obj.get("kms").?.array.items.len);
    try std.testing.expectEqual(data.sku_count, obj.get("skus").?.array.items.len);
    try std.testing.expectEqual(data.host_builds.len, obj.get("hostbuilds").?.array.items.len);

    // Every per-record key the reverse direction reads back.
    const csvlk = obj.get("csvlk").?.array.items[0].object;
    try std.testing.expectEqualStrings(data.csvlk[0].epid, csvlk.get("epid").?.string);
    try std.testing.expectEqualStrings(data.csvlk[0].name, csvlk.get("name").?.string);
    try std.testing.expectEqual(@as(i64, data.csvlk[0].group_id), csvlk.get("group_id").?.integer);
    try std.testing.expectEqual(@as(i64, data.csvlk[0].max_key_id), csvlk.get("max_key_id").?.integer);

    const item = obj.get("apps").?.array.items[0].object;
    try std.testing.expectEqualStrings(data.apps()[0].name, item.get("name").?.string);
    try std.testing.expectEqual(@as(usize, 32), item.get("guid").?.string.len);

    const host_build = obj.get("hostbuilds").?.array.items[0].object;
    try std.testing.expectEqualStrings(data.host_builds[0].display_name, host_build.get("display_name").?.string);
    try std.testing.expectEqual(@as(i64, data.host_builds[0].build_number), host_build.get("build_number").?.integer);
}

test "jsonToKmsData rejects malformed input" {
    const gpa = std.testing.allocator;
    // Every case is a self-contained document: the first field that fails is
    // the one named in the expectation.
    const Case = struct { json: []const u8, expected: anyerror };
    const cases = [_]Case{
        .{
            .json = "[]",
            .expected = error.InvalidJson,
        },
        .{
            // `apps`/`kms`/`skus` are required.
            .json = "{\"minor_ver\":0,\"major_ver\":2,\"flags\":1}",
            .expected = error.MissingField,
        },
        .{
            .json = "{\"apps\":[],\"kms\":[],\"skus\":[],\"csvlk\":[],\"hostbuilds\":[],\"minor_ver\":0,\"major_ver\":2,\"flags\":\"x\"}",
            .expected = error.TypeMismatch,
        },
        .{
            .json = "{\"apps\":[],\"kms\":[],\"skus\":[],\"csvlk\":[],\"hostbuilds\":[],\"minor_ver\":70000,\"major_ver\":2,\"flags\":1}",
            .expected = error.Overflow,
        },
        .{
            // A GUID is exactly 32 hex digits.
            .json = "{\"apps\":[{\"guid\":\"00112233445566778899aabbccddee\",\"name\":\"X\",\"app_index\":0,\"kms_index\":0}],\"kms\":[],\"skus\":[],\"csvlk\":[],\"hostbuilds\":[],\"minor_ver\":0,\"major_ver\":2,\"flags\":1}",
            .expected = error.InvalidGuid,
        },
        .{
            .json = "{\"apps\":[],\"kms\":[],\"skus\":[],\"csvlk\":[],\"hostbuilds\":[],\"minor_ver\":0,\"major_ver\":2,\"flags\":1,\"extra\":0,,}",
            .expected = error.SyntaxError,
        },
    };

    for (cases) |case| {
        var arena: std.heap.ArenaAllocator = .init(gpa);
        defer arena.deinit();
        try std.testing.expectError(case.expected, jsonToKmsData(arena.allocator(), case.json));
    }
}

test "empty record arrays convert but are rejected by the writer" {
    // docs/kmdconv.md: every array must be non-empty. The JSON parser accepts
    // the document; `kmsdata.write` is where the format rule is enforced.
    const gpa = std.testing.allocator;
    const json = "{\"apps\":[],\"kms\":[],\"skus\":[],\"csvlk\":[],\"hostbuilds\":[],\"minor_ver\":0,\"major_ver\":2,\"flags\":1}";

    var arena: std.heap.ArenaAllocator = .init(gpa);
    defer arena.deinit();
    const data = try jsonToKmsData(arena.allocator(), json);
    try std.testing.expectError(error.InvalidFormat, kmsdata.write(gpa, &data));
}

test "parseGuid accepts 32 hex digits and nothing else" {
    const lower = try parseGuid("00112233445566778899aabbccddeeff");
    try std.testing.expectEqualSlices(u8, &.{
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
    }, &lower);
    const upper = try parseGuid("00112233445566778899AABBCCDDEEFF");
    try std.testing.expectEqualSlices(u8, &lower, &upper);

    try std.testing.expectError(error.InvalidGuid, parseGuid("00112233445566778899aabbccddee"));
    try std.testing.expectError(error.InvalidGuid, parseGuid("00112233445566778899aabbccddeeff00"));
    try std.testing.expectError(error.InvalidGuid, parseGuid("00112233445566778899aabbccddeeg"));
}

test "the default output path keeps the stem and swaps the suffix" {
    const gpa = std.testing.allocator;

    const cases = [_]struct { input: []const u8, reverse: bool, want: []const u8 }{
        .{ .input = "data.json", .reverse = false, .want = "data.kmd" },
        .{ .input = "dir/sub/data.json", .reverse = false, .want = "data.kmd" },
        .{ .input = "data.kmd", .reverse = true, .want = "data.json" },
        .{ .input = "src/vlmcsd.kmd", .reverse = true, .want = "vlmcsd.json" },
    };
    for (cases) |case| {
        const got = try deriveOutputPath(gpa, case.input, case.reverse);
        defer gpa.free(got);
        try std.testing.expectEqualStrings(case.want, got);
    }
}

test "a name with an interior NUL does not survive a round-trip" {
    // The format is a NUL-terminated string pool, so a name carrying a NUL is
    // truncated on the way back in. `write` cannot represent it; the converter
    // must either reject it or the caller must not be surprised. Pin which.
    const gpa = std.testing.allocator;
    const raw: []const u8 = @embedFile("vlmcsd.kmd");

    var arena: std.heap.ArenaAllocator = .init(gpa);
    defer arena.deinit();

    const data = try kmsdata.parse(arena.allocator(), raw);
    const json = try kmsDataToJson(&data, gpa);
    defer gpa.free(json);

    var converted = try jsonToKmsData(arena.allocator(), json);
    // Inject an interior NUL into the first product name.
    const name = try arena.allocator().dupe(u8, "AB\x00CD");
    converted.items[converted.app_count].name = name;

    const bytes = try kmsdata.write(gpa, &converted);
    defer gpa.free(bytes);
    var reparsed = try kmsdata.parse(gpa, bytes);
    defer reparsed.deinit(gpa);
    try std.testing.expectEqualStrings("AB", reparsed.items[converted.app_count].name);
}
