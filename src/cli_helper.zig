//! Shared CLI helpers for the `vlmzsd` (server) and `vlmzs` (client) binaries:
//! the data-driven argument parser (`Opt` table → parse/help/validate), the
//! value parsers (duration, boolean, GUID), the fixed-format stdout logger, and
//! the thin environment-variable helpers used to implement the three-tier
//! `default < env < CLI` precedence from `docs/cli.md`.

const std = @import("std");

pub const Io = std.Io;

const Allocator = std.mem.Allocator;

/// What a string value means (drives caller-side validation).
pub const ValueKind = enum {
    flag, // no value
    str, // free-form string
    guid, // GUID string (caller validates via `parseGuid`)
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

/// Parse `<n><unit>` into seconds. Units: `s`/`m`/`h`/`d`/`w`.
/// Examples: `30s`, `2h`, `7d`, `90m`.
pub fn parseDurationSeconds(str: []const u8) error{InvalidDuration}!u64 {
    if (str.len < 2) return error.InvalidDuration;
    const unit = str[str.len - 1];
    const n = std.fmt.parseInt(u64, str[0 .. str.len - 1], 10) catch
        return error.InvalidDuration;
    const mult: u64 = switch (unit) {
        's' => 1,
        'm' => 60,
        'h' => 3600,
        'd' => 86400,
        'w' => 604800,
        else => return error.InvalidDuration,
    };
    return std.math.mul(u64, n, mult) catch error.InvalidDuration;
}

/// Parse a boolean per the env-var convention: `1`/`true`/`yes`/`on` vs
/// `0`/`false`/`no`/`off` (case-insensitive).
pub fn parseBool(str: []const u8) error{InvalidBool}!bool {
    if (std.ascii.eqlIgnoreCase(str, "1") or
        std.ascii.eqlIgnoreCase(str, "true") or
        std.ascii.eqlIgnoreCase(str, "yes") or
        std.ascii.eqlIgnoreCase(str, "on")) return true;
    if (std.ascii.eqlIgnoreCase(str, "0") or
        std.ascii.eqlIgnoreCase(str, "false") or
        std.ascii.eqlIgnoreCase(str, "no") or
        std.ascii.eqlIgnoreCase(str, "off")) return false;
    return error.InvalidBool;
}

fn hexVal(c: u8) error{InvalidGuid}!u8 {
    return switch (c) {
        '0'...'9' => c - '0',
        'a'...'f' => c - 'a' + 10,
        'A'...'F' => c - 'A' + 10,
        else => error.InvalidGuid,
    };
}

/// Parse a GUID in `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx` form (case-insensitive)
/// into its 16 raw bytes.
pub fn parseGuid(str: []const u8) error{InvalidGuid}![16]u8 {
    if (str.len != 36) return error.InvalidGuid;
    var out: [16]u8 = undefined;
    var oi: usize = 0;
    var i: usize = 0;
    while (i < str.len) : (i += 1) {
        if (i == 8 or i == 13 or i == 18 or i == 23) {
            if (str[i] != '-') return error.InvalidGuid;
            continue;
        }
        const hi = try hexVal(str[i]);
        const lo = try hexVal(str[i + 1]);
        out[oi] = (hi << 4) | lo;
        oi += 1;
        i += 1;
    }
    if (oi != 16) return error.InvalidGuid;
    return out;
}

/// Log level, from most to least verbose.
pub const Level = enum {
    debug,
    info,
    warn,
    err,
};

/// Timestamped, leveled logger. `debug`/`info` write to stdout; `warn`/`err`
/// write to stderr (Unix convention). Every line is prefixed with a UTC
/// ISO-8601 timestamp. The format is fixed — no CLI surface (see `docs/cli.md`).
pub const Logger = struct {
    io: Io,
    out_writer: std.Io.File.Writer,
    err_writer: std.Io.File.Writer,
    mutex: Io.Mutex = .init,
    /// Messages below this level are dropped.
    min_level: Level = .info,

    pub fn init(io: Io, out_buffer: []u8, err_buffer: []u8) Logger {
        return .{
            .io = io,
            .out_writer = std.Io.File.writer(std.Io.File.stdout(), io, out_buffer),
            .err_writer = std.Io.File.writer(std.Io.File.stderr(), io, err_buffer),
        };
    }

    fn emit(self: *Logger, level: Level, comptime fmt: []const u8, args: anytype) void {
        if (@intFromEnum(level) < @intFromEnum(self.min_level)) return;
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        const to_err = level == .warn or level == .err;
        const w: *std.Io.Writer = if (to_err) &self.err_writer.interface else &self.out_writer.interface;
        writeTimestamp(w, self.io);
        w.writeAll(levelLabel(level)) catch {};
        w.print(fmt, args) catch {};
        w.writeAll("\n") catch {};
        w.flush() catch {};
    }

    pub fn debug(self: *Logger, comptime fmt: []const u8, args: anytype) void {
        self.emit(.debug, fmt, args);
    }

    pub fn info(self: *Logger, comptime fmt: []const u8, args: anytype) void {
        self.emit(.info, fmt, args);
    }

    pub fn warn(self: *Logger, comptime fmt: []const u8, args: anytype) void {
        self.emit(.warn, fmt, args);
    }

    pub fn err(self: *Logger, comptime fmt: []const u8, args: anytype) void {
        self.emit(.err, fmt, args);
    }
};

fn levelLabel(level: Level) []const u8 {
    return switch (level) {
        .debug => "debug: ",
        .info => "",
        .warn => "warning: ",
        .err => "error: ",
    };
}

/// Write a UTC `YYYY-MM-DDTHH:MM:SSZ` timestamp followed by a space.
fn writeTimestamp(w: *std.Io.Writer, io: Io) void {
    const secs: u64 = @intCast(@divTrunc(Io.Clock.now(.real, io).nanoseconds, std.time.ns_per_s));
    const epoch = std.time.epoch.EpochSeconds{ .secs = secs };
    const yad = epoch.getEpochDay().calculateYearDay();
    const mad = yad.calculateMonthDay();
    const day_secs: u64 = secs % 86400;
    var buf: [20]u8 = undefined;
    const ts = std.fmt.bufPrint(&buf, "{d:0>4}-{d:0>2}-{d:0>2}T{d:0>2}:{d:0>2}:{d:0>2}Z", .{
        @as(u32, yad.year),
        @as(u32, @intFromEnum(mad.month)) + 1,
        @as(u32, mad.day_index) + 1,
        @as(u32, @intCast(day_secs / 3600)),
        @as(u32, @intCast((day_secs % 3600) / 60)),
        @as(u32, @intCast(day_secs % 60)),
    }) catch unreachable;
    w.writeAll(ts) catch {};
    w.writeAll(" ") catch {};
}

/// Current Unix time in seconds (via the `realtime` clock).
pub fn nowUnix(io: Io) i64 {
    const now = Io.Clock.now(.real, io);
    return @intCast(@divTrunc(now.nanoseconds, std.time.ns_per_s));
}

/// A non-cryptographic seed mixing the realtime clock with stack (ASLR) entropy.
pub fn makeSeed(io: Io) u64 {
    const now = Io.Clock.now(.real, io);
    const nanos: u128 = @intCast(now.nanoseconds);
    const ptr_entropy: u64 = @truncate(@as(u128, @intCast(@intFromPtr(&now))));
    return @as(u64, @truncate(nanos)) ^ ptr_entropy;
}

test "parseDurationSeconds" {
    try std.testing.expectEqual(@as(u64, 30), try parseDurationSeconds("30s"));
    try std.testing.expectEqual(@as(u64, 7200), try parseDurationSeconds("2h"));
    try std.testing.expectEqual(@as(u64, 604800), try parseDurationSeconds("7d"));
    try std.testing.expectEqual(@as(u64, 5400), try parseDurationSeconds("90m"));
    try std.testing.expectError(error.InvalidDuration, parseDurationSeconds("h"));
    try std.testing.expectError(error.InvalidDuration, parseDurationSeconds("12x"));
    try std.testing.expectError(error.InvalidDuration, parseDurationSeconds(""));
}

test "parseBool" {
    try std.testing.expectEqual(true, try parseBool("1"));
    try std.testing.expectEqual(true, try parseBool("TRUE"));
    try std.testing.expectEqual(true, try parseBool("yes"));
    try std.testing.expectEqual(false, try parseBool("0"));
    try std.testing.expectEqual(false, try parseBool("Off"));
    try std.testing.expectError(error.InvalidBool, parseBool("maybe"));
}

test "parseGuid" {
    const g = try parseGuid("00112233-4455-6677-8899-aabbccddeeff");
    try std.testing.expectEqualSlices(u8, &.{ 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff }, &g);
    try std.testing.expectEqualSlices(u8, &(try parseGuid("00112233-4455-6677-8899-AABBCCDDEEFF")), &.{ 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff });
    try std.testing.expectError(error.InvalidGuid, parseGuid("nope"));
    try std.testing.expectError(error.InvalidGuid, parseGuid("00112233-4455-6677-8899-aabbccddee"));
}

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
