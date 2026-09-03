//! Shared CLI helpers for the `vlmzsd` (server) and `vlmzs` (client) binaries:
//! value parsers (duration, boolean), the fixed-format stdout logger, and the
//! thin environment-variable helpers used to implement the three-tier
//! `default < env < CLI` precedence from `docs/cli.md`.

const std = @import("std");

pub const Io = std.Io;

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

/// Fixed-format logger writing to stdout. No CLI surface (see `docs/cli.md`):
/// redirecting/persisting output is the supervisor's (systemd/Docker) job.
pub const Logger = struct {
    file_writer: std.Io.File.Writer,

    pub fn init(io: Io, buffer: []u8) Logger {
        return .{ .file_writer = std.Io.File.writer(std.Io.File.stdout(), io, buffer) };
    }

    fn emit(self: *Logger, level: []const u8, comptime fmt: []const u8, args: anytype) void {
        const w = &self.file_writer.interface;
        w.writeAll(level) catch {};
        w.print(fmt, args) catch {};
        w.writeAll("\n") catch {};
        w.flush() catch {};
    }

    pub fn info(self: *Logger, comptime fmt: []const u8, args: anytype) void {
        self.emit("", fmt, args);
    }

    pub fn warn(self: *Logger, comptime fmt: []const u8, args: anytype) void {
        self.emit("warning: ", fmt, args);
    }

    pub fn err(self: *Logger, comptime fmt: []const u8, args: anytype) void {
        self.emit("error: ", fmt, args);
    }
};

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
