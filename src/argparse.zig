//! Data-driven command-line parser — a hand-written, std-only replacement for zig-clap.
//!
//! Single source of truth: an `Opt` table drives parsing, `--help` rendering,
//! and validation alike, so the parse logic and the help text cannot drift
//! apart. Self-contained (std only); does not depend on zig-clap.
//!
//! Status: production. `vlmzs` parses its CLI through this module; the generic
//! tests below exercise the parser's full surface (flags, values, positionals,
//! `--` terminator, and grouped help).

const std = @import("std");

const Allocator = std.mem.Allocator;

/// What a string value means (drives caller-side validation).
pub const ValueKind = enum {
    flag, // no value
    str, // free-form string
    guid, // GUID string (caller validates via cli_helper.parseGuid)
    int, // integer, width decided by the caller
};

/// One option. `name` is the long name without `--`; `short` without `-`.
pub const Opt = struct {
    name: []const u8,
    short: ?u8 = null,
    kind: ValueKind = .flag,
    group: []const u8 = "",
    desc: []const u8 = "",
    /// Value placeholder shown in `--help` (e.g. "u16", "guid"). Flags ignore it.
    hint: []const u8 = "",
    repeatable: bool = false,
};

pub const ParseError = error{
    UnknownOption,
    MissingValue,
    FlagTakesNoValue,
    OutOfMemory,
};

/// Parsed result. Values are kept as raw strings; the caller converts them
/// with its own semantic parsers (duration / GUID / integer width).
pub const Result = struct {
    allocator: Allocator,
    flags: std.StringHashMap(void),
    values: std.StringHashMap([][]const u8),
    positionals: std.ArrayList([]const u8),

    pub fn deinit(self: *Result) void {
        self.flags.deinit();
        var it = self.values.valueIterator();
        while (it.next()) |list| self.allocator.free(list.*);
        self.values.deinit();
        self.positionals.deinit(self.allocator);
    }

    pub fn hasFlag(self: *const Result, name: []const u8) bool {
        return self.flags.contains(name);
    }

    /// Last value for a single-value option (repeated specs: last wins).
    pub fn get(self: *const Result, name: []const u8) ?[]const u8 {
        const list = self.values.get(name) orelse return null;
        return if (list.len > 0) list[list.len - 1] else null;
    }

    pub fn getAll(self: *const Result, name: []const u8) []const []const u8 {
        return self.values.get(name) orelse &.{};
    }
};

fn findLong(opts: []const Opt, name: []const u8) ?*const Opt {
    for (opts) |*o| {
        if (std.mem.eql(u8, o.name, name)) return o;
    }
    return null;
}

fn findShort(opts: []const Opt, c: u8) ?*const Opt {
    for (opts) |*o| {
        if (o.short == c) return o;
    }
    return null;
}

fn appendValue(res: *Result, opt: *const Opt, value: []const u8) ParseError!void {
    const gop = try res.values.getOrPut(opt.name);
    if (!gop.found_existing) gop.value_ptr.* = &.{};
    const old = gop.value_ptr.*;
    const new = try res.allocator.alloc([]const u8, old.len + 1);
    @memcpy(new[0..old.len], old);
    new[old.len] = value;
    if (old.len > 0) res.allocator.free(old);
    gop.value_ptr.* = new;
}

/// Parse `args` against `opts`. Supports `--long`, `--long=value`,
/// `--long value`, `-s`, `-svalue`, `--` terminator, and positionals.
pub fn parse(allocator: Allocator, opts: []const Opt, args: []const []const u8) ParseError!Result {
    var res = Result{
        .allocator = allocator,
        .flags = std.StringHashMap(void).init(allocator),
        .values = std.StringHashMap([][]const u8).init(allocator),
        .positionals = std.ArrayList([]const u8).empty,
    };
    errdefer res.deinit();

    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        const arg = args[i];

        if (std.mem.eql(u8, arg, "--")) {
            i += 1;
            while (i < args.len) : (i += 1) try res.positionals.append(res.allocator, args[i]);
            break;
        }

        if (arg.len > 2 and arg[0] == '-' and arg[1] == '-') {
            const body = arg[2..];
            if (std.mem.indexOfScalar(u8, body, '=')) |eq| {
                const opt = findLong(opts, body[0..eq]) orelse return error.UnknownOption;
                if (opt.kind == .flag) return error.FlagTakesNoValue;
                try appendValue(&res, opt, body[eq + 1 ..]);
            } else {
                const opt = findLong(opts, body) orelse return error.UnknownOption;
                if (opt.kind == .flag) {
                    try res.flags.put(opt.name, {});
                } else {
                    i += 1;
                    if (i >= args.len) return error.MissingValue;
                    try appendValue(&res, opt, args[i]);
                }
            }
        } else if (arg.len >= 2 and arg[0] == '-' and arg[1] != '-') {
            const opt = findShort(opts, arg[1]) orelse return error.UnknownOption;
            if (opt.kind == .flag) {
                try res.flags.put(opt.name, {});
            } else if (arg.len > 2) {
                try appendValue(&res, opt, arg[2..]);
            } else {
                i += 1;
                if (i >= args.len) return error.MissingValue;
                try appendValue(&res, opt, args[i]);
            }
        } else {
            try res.positionals.append(res.allocator, arg);
        }
    }
    return res;
}

/// Render grouped `--help` text. `positional_hint` is the usage line's
/// positional (e.g. "[HOST[:PORT]]").
pub fn writeHelp(writer: *std.Io.Writer, prog: []const u8, opts: []const Opt, positional_hint: []const u8) !void {
    try writer.print("Usage: {s} [OPTIONS]", .{prog});
    if (positional_hint.len > 0) try writer.print(" {s}", .{positional_hint});
    try writer.print("\n\n", .{});

    var current_group: ?[]const u8 = null;
    for (opts) |o| {
        if (current_group == null or !std.mem.eql(u8, current_group.?, o.group)) {
            try writer.print("{s}:\n", .{o.group});
            current_group = o.group;
        }
        try writer.print("    ", .{});
        if (o.short) |s| {
            try writer.print("-{c}, ", .{s});
        } else {
            try writer.print("    ", .{});
        }
        try writer.print("--{s}", .{o.name});
        if (o.kind != .flag) {
            const default_hint: []const u8 = switch (o.kind) {
                .guid => "guid",
                .int => "int",
                else => "str",
            };
            try writer.print(" <{s}>", .{if (o.hint.len > 0) o.hint else default_hint});
        }
        try writer.print("\n        {s}\n", .{o.desc});
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// Generic option table used by the tests (covers flag / int / str / repeatable).
const test_opts = [_]Opt{
    .{ .name = "verbose", .short = 'v', .group = "Output", .desc = "Verbose logging." },
    .{ .name = "protocol", .kind = .int, .hint = "u16", .group = "Request", .desc = "KMS protocol version." },
    .{ .name = "count", .short = 'n', .kind = .int, .hint = "u32", .group = "Request", .desc = "Number of requests." },
    .{ .name = "reconnect-per-request", .short = 'T', .group = "Connection", .desc = "Reconnect for each request." },
};

test "parse flag, value and positional" {
    const alloc = std.testing.allocator;
    var res = try parse(alloc, &test_opts, &.{ "--verbose", "--protocol", "4", "localhost" });
    defer res.deinit();

    try std.testing.expect(res.hasFlag("verbose"));
    try std.testing.expectEqualStrings("4", res.get("protocol").?);
    try std.testing.expectEqual(@as(usize, 1), res.positionals.items.len);
    try std.testing.expectEqualStrings("localhost", res.positionals.items[0]);
}

test "parse --opt=value and short glued value" {
    const alloc = std.testing.allocator;
    var res = try parse(alloc, &test_opts, &.{ "--protocol=5", "-n3", "-T" });
    defer res.deinit();

    try std.testing.expectEqualStrings("5", res.get("protocol").?);
    try std.testing.expectEqualStrings("3", res.get("count").?);
    try std.testing.expect(res.hasFlag("reconnect-per-request"));
}

test "parse repeatable and -- terminator" {
    const alloc = std.testing.allocator;
    const opts = [_]Opt{
        .{ .name = "listen", .short = 'L', .kind = .str, .repeatable = true },
    };
    var res = try parse(alloc, &opts, &.{ "-L", "0.0.0.0", "-L", "::", "--", "--listen", "x" });
    defer res.deinit();

    try std.testing.expectEqual(@as(usize, 2), res.getAll("listen").len);
    try std.testing.expectEqualStrings("::", res.getAll("listen")[1]);
    try std.testing.expectEqual(@as(usize, 2), res.positionals.items.len);
    try std.testing.expectEqualStrings("--listen", res.positionals.items[0]);
}

test "parse errors" {
    const alloc = std.testing.allocator;
    try std.testing.expectError(error.UnknownOption, parse(alloc, &test_opts, &.{"--bogus"}));
    try std.testing.expectError(error.MissingValue, parse(alloc, &test_opts, &.{"--protocol"}));
    try std.testing.expectError(error.FlagTakesNoValue, parse(alloc, &test_opts, &.{"--verbose=1"}));
}

test "help renders groups" {
    var buf: [4096]u8 = undefined;
    var w = std.Io.Writer.fixed(&buf);
    try writeHelp(&w, "vlmzs", &test_opts, "[HOST[:PORT]]");
    const text = w.buffered();

    try std.testing.expect(std.mem.indexOf(u8, text, "Output:") != null);
    try std.testing.expect(std.mem.indexOf(u8, text, "Request:") != null);
    try std.testing.expect(std.mem.indexOf(u8, text, "Connection:") != null);
    try std.testing.expect(std.mem.indexOf(u8, text, "--protocol <u16>") != null);
    try std.testing.expect(std.mem.indexOf(u8, text, "-v, --verbose") != null);
}
