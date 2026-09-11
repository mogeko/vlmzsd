//! `kmdconv` — convert between the `.kmd` binary data format and JSON.
//!
//! A developer tool (not installed by default). The default direction reads a
//! JSON file and writes a `.kmd` file; `-r` reverses it (read `.kmd`, write
//! JSON). Input `-` reads stdin; output goes to stdout unless `-o <file>` is
//! given.

const std = @import("std");
const vlmzsd = @import("vlmzsd");
const kmsdata = vlmzsd.kmsdata;

const build_options = @import("build_options");
const version = build_options.version;
const git_hash = build_options.git_hash;
const build_date = build_options.build_date;

const Allocator = std.mem.Allocator;
const Io = std.Io;
const Json = std.json;

fn writeHelp(w: *std.Io.Writer) !void {
    try w.print(
        \\Usage: kmdconv [OPTIONS] <file>
        \\
        \\Convert between the `.kmd` binary data format and JSON.
        \\  <file>           input JSON file (or a `.kmd` file with -r); output
        \\                   defaults to a sibling file with the matching suffix
        \\
        \\Options:
        \\  -h, --help            print this help and exit
        \\  -V, --version         print version and exit
        \\  -                     read input from stdin (instead of <file>)
        \\  -r, --reverse         reverse: read a `.kmd` file, write JSON
        \\  -o, --output <file>   write output to <file> (default: derived)
        \\
    , .{});
}

fn errOut(io: Io, comptime fmt: []const u8, args: anytype) void {
    var ebuf: [512]u8 = undefined;
    var ew = std.Io.File.writer(std.Io.File.stderr(), io, &ebuf);
    ew.interface.print(fmt, args) catch {};
    ew.interface.flush() catch {};
}

/// Derive the default output path: the input's stem plus `.json` (with `-r`)
/// or `.kmd` (default), written to the current directory regardless of the
/// input's location. e.g. `dir/data.json` → `data.kmd`.
fn deriveOutputPath(gpa: Allocator, input: []const u8, reverse: bool) ![]u8 {
    const ext = if (reverse) ".json" else ".kmd";
    const stem = std.fs.path.stem(input);
    return std.fmt.allocPrint(gpa, "{s}{s}", .{ stem, ext });
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
    var args: std.ArrayList([]const u8) = .empty;
    defer args.deinit(init.gpa);
    var it = std.process.Args.Iterator.init(init.minimal.args);
    _ = it.skip();
    while (it.next()) |a| try args.append(init.gpa, a);

    var reverse = false;
    var output_path: ?[]const u8 = null;
    var input: ?[]const u8 = null;

    var i: usize = 0;
    while (i < args.items.len) : (i += 1) {
        const a = args.items[i];
        if (std.mem.eql(u8, a, "-h") or std.mem.eql(u8, a, "--help")) {
            var hbuf: [2048]u8 = undefined;
            var hw = std.Io.File.writer(std.Io.File.stdout(), init.io, &hbuf);
            try writeHelp(&hw.interface);
            try hw.interface.flush();
            return;
        } else if (std.mem.eql(u8, a, "-V") or std.mem.eql(u8, a, "--version")) {
            var vbuf: [64]u8 = undefined;
            var vw = std.Io.File.writer(std.Io.File.stdout(), init.io, &vbuf);
            try vw.interface.print("kmdconv {s} ({s} {s})\n", .{ version, git_hash, build_date });
            try vw.interface.flush();
            return;
        } else if (std.mem.eql(u8, a, "-r") or std.mem.eql(u8, a, "--reverse")) {
            reverse = true;
        } else if (std.mem.eql(u8, a, "-o") or std.mem.eql(u8, a, "--output")) {
            i += 1;
            if (i >= args.items.len) {
                errOut(init.io, "kmdconv: error: -o/--output requires an argument\n", .{});
                std.process.exit(1);
            }
            output_path = args.items[i];
        } else if (a.len > 0 and a[0] == '-' and !std.mem.eql(u8, a, "-")) {
            errOut(init.io, "kmdconv: error: unknown option {s}\n", .{a});
            std.process.exit(1);
        } else if (input == null) {
            input = a;
        } else {
            errOut(init.io, "kmdconv: error: too many positional arguments\n", .{});
            std.process.exit(1);
        }
    }

    if (input == null) {
        errOut(init.io, "kmdconv: error: missing input file (use - for stdin)\n", .{});
        std.process.exit(1);
    }

    // Read input.
    var input_data: []const u8 = undefined;
    var input_owned = false;
    defer if (input_owned) init.gpa.free(@constCast(input_data));
    if (std.mem.eql(u8, input.?, "-")) {
        input_data = try readStdin(init.io, init.gpa);
        input_owned = true;
    } else {
        input_data = std.Io.Dir.readFileAlloc(std.Io.Dir.cwd(), init.io, input.?, init.gpa, .unlimited) catch |e| {
            errOut(init.io, "kmdconv: error: cannot read {s}: {s}\n", .{ input.?, @errorName(e) });
            std.process.exit(1);
        };
        input_owned = true;
    }

    // Convert.
    var output_data: []const u8 = undefined;
    var output_owned = false;
    defer if (output_owned) init.gpa.free(@constCast(output_data));
    if (reverse) {
        var arena = std.heap.ArenaAllocator.init(init.gpa);
        defer arena.deinit();
        const data = kmsdata.parse(arena.allocator(), input_data) catch |e| {
            errOut(init.io, "kmdconv: error: invalid .kmd data: {s} (is this a JSON file? remove -r to convert it to .kmd)\n", .{@errorName(e)});
            std.process.exit(1);
        };
        output_data = kmsDataToJson(&data, init.gpa) catch |e| {
            errOut(init.io, "kmdconv: error: cannot serialize JSON: {s}\n", .{@errorName(e)});
            std.process.exit(1);
        };
        output_owned = true;
    } else {
        var arena = std.heap.ArenaAllocator.init(init.gpa);
        defer arena.deinit();
        const data = jsonToKmsData(arena.allocator(), input_data) catch |e| {
            errOut(init.io, "kmdconv: error: invalid JSON input: {s} (is this a .kmd file? use -r to convert it to JSON)\n", .{@errorName(e)});
            std.process.exit(1);
        };
        output_data = kmsdata.write(init.gpa, &data) catch |e| {
            errOut(init.io, "kmdconv: error: cannot build .kmd data: {s}\n", .{@errorName(e)});
            std.process.exit(1);
        };
        output_owned = true;
    }

    // Determine the output path: `-o/--output` wins; otherwise derive a sibling
    // file with the matching extension when the input is a real file (not stdin).
    var derived: ?[]u8 = null;
    defer if (derived) |p| init.gpa.free(p);
    if (output_path == null and !std.mem.eql(u8, input.?, "-")) {
        derived = deriveOutputPath(init.gpa, input.?, reverse) catch |e| {
            errOut(init.io, "kmdconv: error: cannot derive output path: {s}\n", .{@errorName(e)});
            std.process.exit(1);
        };
    }
    const out_path: ?[]const u8 = output_path orelse derived;

    // Write output.
    if (out_path) |p| {
        std.Io.Dir.writeFile(std.Io.Dir.cwd(), init.io, .{ .sub_path = p, .data = output_data }) catch |e| {
            errOut(init.io, "kmdconv: error: cannot write {s}: {s}\n", .{ p, @errorName(e) });
            std.process.exit(1);
        };
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
