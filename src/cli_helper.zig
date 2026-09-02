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
