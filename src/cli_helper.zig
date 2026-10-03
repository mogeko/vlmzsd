//! Shared CLI helpers for the `vlmzsd` (server) and `vlmzs` (client) binaries:
//! the data-driven argument parser (`Opt` table → parse/help/validate), the
//! value parsers (duration, boolean, GUID), the fixed-format stdout logger, and
//! the thin environment-variable helpers used to implement the three-tier
//! `default < env < CLI` precedence from `docs/cli.md`.

const std = @import("std");
const line_queue = @import("line_queue.zig");

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

/// Placeholder shown for a value-taking option when no explicit `hint` is set.
fn defaultHint(kind: ValueKind) []const u8 {
    return switch (kind) {
        .guid => "guid",
        .int => "int",
        else => "str",
    };
}

/// Width of the option spec column (`-x, --long [hint]`), excluding the
/// leading indent. Options without a short flag render as just `--long`.
fn optColumnWidth(o: Opt) usize {
    var w: usize = if (o.short != null) 4 else 0; // "-x, "
    w += 2 + o.name.len; // "--name"
    if (o.kind != .flag) w += 3 + (if (o.hint.len > 0) o.hint else defaultHint(o.kind)).len; // " [hint]"
    return w;
}

/// Groups are separated by a blank line, value placeholders use square brackets
/// (`--port [u16]`), and every description aligns to the single widest option
/// column. `positional_hint` is the usage line's positional (e.g.
/// "[HOST[:PORT]]"). Options are expected to be ordered by `group` (contiguous
/// runs).
pub fn writeHelp(writer: *std.Io.Writer, prog: []const u8, opts: []const Opt, positional_hint: []const u8) !void {
    try writer.print("Usage: {s} [OPTIONS]", .{prog});
    if (positional_hint.len > 0) try writer.print(" {s}", .{positional_hint});
    try writer.print("\n\n", .{});

    // Two passes: measure the widest option spec, then render every option
    // with its description aligned to the same (global) column.
    var max_width: usize = 0;
    for (opts) |o| {
        const w = optColumnWidth(o);
        if (w > max_width) max_width = w;
    }

    var current_group: ?[]const u8 = null;
    for (opts) |o| {
        if (current_group == null or !std.mem.eql(u8, current_group.?, o.group)) {
            // A blank line separates groups (not before the first, since the
            // usage line already ends with one).
            if (current_group != null) try writer.print("\n", .{});
            try writer.print("{s}:\n", .{o.group});
            current_group = o.group;
        }
        try writer.print("    ", .{});
        if (o.short) |s| {
            try writer.print("-{c}, ", .{s});
        }
        try writer.print("--{s}", .{o.name});
        if (o.kind != .flag) {
            try writer.print(" [{s}]", .{if (o.hint.len > 0) o.hint else defaultHint(o.kind)});
        }
        try writer.splatByteAll(' ', max_width - optColumnWidth(o) + 2);
        try writer.print("{s}\n", .{o.desc});
    }
}

/// Parse `<n><unit>` into seconds. Units: `s`/`m`/`h`/`d`/`w`.
/// Examples: `30s`, `2h`, `7d`, `90m`. A bare `0` is accepted as "disabled",
/// which is how `--timeout 0` is documented for both binaries.
pub fn parseDurationSeconds(str: []const u8) error{InvalidDuration}!u64 {
    if (std.mem.eql(u8, str, "0")) return 0;
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
///
/// A log call is a producer of a lossy FIFO (`line_queue`): it formats the line
/// on the calling thread, hands it over, and returns without touching the
/// stdout/stderr descriptors. The blocking `write`/`flush` belongs to a
/// dedicated writer task (`writerLoop`), so a slow consumer can never stall a
/// worker. If that task cannot be started, `direct` degrades to writing
/// synchronously from the calling thread.
pub const Logger = struct {
    io: Io,
    /// Messages below this level are dropped. Written once by `main` before any
    /// producer exists, so producers read it without synchronization.
    min_level: Level = .info,
    queue: line_queue.LineQueue,
    /// Backing buffers for the writer's stdout/stderr writers. They are owned by
    /// the caller so that `init` can return by value: a `File.Writer` stored in
    /// this struct would point into the temporary that was just moved.
    out_buffer: []u8,
    err_buffer: []u8,
    /// Degraded mode: writers write synchronously (the pre-queue behavior).
    /// Set once, before any producer thread starts.
    direct: bool = false,
    /// Test seam for the degraded path. When set, `writeDirect` writes here
    /// instead of the process descriptors: `zig build test` runs the test binary
    /// with `--listen=-`, where stdout carries the runner's protocol, so a test
    /// must never write to the real stdout. Production leaves these null.
    direct_out: ?*std.Io.Writer = null,
    direct_err: ?*std.Io.Writer = null,
    /// Set by the writer task once every accepted line has been flushed.
    done: Io.Event = .unset,
    /// Guards the degraded synchronous path only.
    direct_mutex: Io.Mutex = .init,
    /// Lines refused because the queue was full or already closed, and not yet
    /// reported: the writer clears these when it reports them, so every report
    /// covers exactly the loss since the previous one.
    dropped: std.atomic.Value(u64) = .init(0),
    /// Lines shortened to fit a slot (see `emit`). Reported and cleared the same
    /// way as `dropped`.
    truncated: std.atomic.Value(u64) = .init(0),
    /// Totals for the whole run, accumulated by the writer as it clears the two
    /// counters above. Plain fields because only the consumer touches them; a
    /// producer never needs to know a total.
    total_dropped: u64 = 0,
    total_truncated: u64 = 0,

    /// Slots the writer copies out per lock acquisition.
    const batch_size = 16;

    pub fn init(gpa: Allocator, io: Io, out_buffer: []u8, err_buffer: []u8) Allocator.Error!Logger {
        return .{
            .io = io,
            .queue = try line_queue.LineQueue.init(gpa),
            .out_buffer = out_buffer,
            .err_buffer = err_buffer,
        };
    }

    /// Release the queue's slots. Only valid after `shutdown` returned and the
    /// writer task has been joined (see `main`).
    pub fn deinit(self: *Logger, gpa: Allocator) void {
        self.queue.deinit(gpa);
    }

    fn emit(self: *Logger, level: Level, comptime fmt: []const u8, args: anytype) void {
        if (@intFromEnum(level) < @intFromEnum(self.min_level)) return;

        // Format on the calling thread so the queue's critical section only has
        // to copy. The timestamp is taken here, at call time: it records when
        // the event happened, not when the writer got to it.
        var line: [line_queue.slot_size]u8 = undefined;
        var writer: std.Io.Writer = .fixed(&line);
        writeTimestamp(&writer, self.io);
        writer.writeAll(levelLabel(level)) catch {};
        var full = false;
        writer.print(fmt, args) catch {
            full = true;
        };
        if (!full) writer.writeAll("\n") catch {
            full = true;
        };
        var bytes = writer.buffered();
        if (full) {
            // A fixed writer only fails when the buffer is full, so the line
            // holds exactly `slot_size` bytes. Overwrite the last byte with the
            // newline to keep it a single, greppable line.
            std.debug.assert(bytes.len == line_queue.slot_size);
            line[line_queue.slot_size - 1] = '\n';
            bytes = line[0..];
            _ = self.truncated.fetchAdd(1, .monotonic);
        }

        const to_err = level == .warn or level == .err;
        if (self.direct) {
            self.writeDirect(bytes, to_err);
            return;
        }
        if (!self.queue.tryPush(self.io, bytes, to_err)) {
            _ = self.dropped.fetchAdd(1, .monotonic);
        }
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

    /// Synchronous fallback for `direct` mode: take the lock, write and flush
    /// from the calling thread, exactly like the pre-queue logger did.
    fn writeDirect(self: *Logger, bytes: []const u8, to_err: bool) void {
        self.direct_mutex.lockUncancelable(self.io);
        defer self.direct_mutex.unlock(self.io);
        if (if (to_err) self.direct_err else self.direct_out) |writer| {
            writer.writeAll(bytes) catch {};
            writer.flush() catch {};
            return;
        }
        const file = if (to_err) std.Io.File.stderr() else std.Io.File.stdout();
        var file_writer = std.Io.File.writer(file, self.io, if (to_err) self.err_buffer else self.out_buffer);
        file_writer.interface.writeAll(bytes) catch {};
        file_writer.interface.flush() catch {};
    }

    /// Writer task body, dispatched with `Group.concurrent`. Owns the blocking
    /// I/O for both streams.
    pub fn writerLoop(self: *Logger) void {
        std.debug.assert(!self.direct);
        var out_writer = std.Io.File.writer(std.Io.File.stdout(), self.io, self.out_buffer);
        var err_writer = std.Io.File.writer(std.Io.File.stderr(), self.io, self.err_buffer);
        self.runWriter(&out_writer.interface, &err_writer.interface);
    }

    /// Drain the queue into the two sinks until it is closed and empty, then
    /// flush and latch `done`. The sinks are parameters so that tests can run
    /// this on the test thread against memory writers.
    fn runWriter(self: *Logger, out_writer: *std.Io.Writer, err_writer: *std.Io.Writer) void {
        var batch: [batch_size]line_queue.Slot = undefined;

        while (true) {
            if (self.drainOnce(out_writer, err_writer, &batch) > 0) continue;
            // Nothing queued. Either the run is over, or report the idle loss and
            // park: `awaitWork` owns the arm/test/park order that makes the wait
            // race-free.
            if (self.queue.isClosed()) break;
            // Tell the operator what was lost while the writer was behind — the
            // delta for this period; the final drain reports the run's total.
            self.reportCounters(err_writer, .idle);
            // `error.Canceled` means shutdown is stopping the writer; the final
            // drain below still flushes every accepted line.
            const wake = self.queue.awaitWork(self.io) catch break;
            if (wake == .closed) break;
        }

        // Final drain: every line the queue accepted must reach the sink, and a
        // cancelation request must not cut the flush short.
        const previous = self.io.swapCancelProtection(.blocked);
        defer _ = self.io.swapCancelProtection(previous);
        while (self.drainOnce(out_writer, err_writer, &batch) > 0) {}
        // Final report: the run's totals, written even when the idle reports
        // already covered them, so the last word on the log is the tally.
        self.reportCounters(err_writer, .final);
        out_writer.flush() catch {};
        err_writer.flush() catch {};
        self.done.set(self.io);
    }

    /// Pop one batch, write the lines, and flush both streams. Returns how many
    /// lines were written.
    fn drainOnce(
        self: *Logger,
        out_writer: *std.Io.Writer,
        err_writer: *std.Io.Writer,
        batch: []line_queue.Slot,
    ) usize {
        const count = self.queue.popBatch(self.io, batch);
        if (count == 0) return 0;
        for (batch[0..count]) |slot| {
            const writer = if (slot.err) err_writer else out_writer;
            writer.writeAll(slot.bytes[0..slot.len]) catch {};
        }
        // One flush per batch keeps the syscall count low; `runWriter` loops
        // until the queue is empty, so a lone line is still flushed promptly.
        out_writer.flush() catch {};
        err_writer.flush() catch {};
        return count;
    }

    /// Which shape of loss report to write. The two are deliberately different
    /// text, so a reader can tell a running notice from the final tally without
    /// doing arithmetic on the numbers.
    const CounterReport = enum {
        /// The delta since the last report, from when the writer caught up.
        idle,
        /// The totals for the whole run, from the final drain.
        final,
    };

    /// Report lines that never made it into the log, then clear the counters so
    /// the next report covers only new loss. Written by the consumer itself: the
    /// queue may already be closed, so these must not be enqueued.
    ///
    /// `swap` — not load-then-store — is what makes the clear safe: a producer
    /// adding a line concurrently is counted by this report or by the next one,
    /// never by neither. The idle shape stays silent when this period lost
    /// nothing; the final shape stays silent when the run lost nothing.
    fn reportCounters(self: *Logger, err_writer: *std.Io.Writer, kind: CounterReport) void {
        const period_dropped = self.dropped.swap(0, .acq_rel);
        const period_truncated = self.truncated.swap(0, .acq_rel);
        self.total_dropped += period_dropped;
        self.total_truncated += period_truncated;
        switch (kind) {
            .idle => {
                if (period_dropped == 0 and period_truncated == 0) return;
                writeCounterLine(err_writer, self.io, period_dropped, period_truncated, "since the last report");
            },
            .final => {
                if (self.total_dropped == 0 and self.total_truncated == 0) return;
                writeCounterLine(err_writer, self.io, self.total_dropped, self.total_truncated, "in total");
            },
        }
    }

    /// Stop accepting lines and block until the writer task has drained and
    /// flushed everything. Must be called before `Group.cancel` (which would
    /// cancel the writer) and before `deinit`. Idempotent.
    pub fn shutdown(self: *Logger, io: Io) void {
        if (self.direct) return;
        self.queue.close(io);
        self.done.waitUncancelable(io);
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

/// One loss report: `<timestamp> warning: logging: dropped N line(s), truncated
/// M line(s) <scope>`, where the scope names the period the numbers cover.
fn writeCounterLine(w: *std.Io.Writer, io: Io, dropped: u64, truncated: u64, scope: []const u8) void {
    writeTimestamp(w, io);
    w.writeAll(levelLabel(.warn)) catch {};
    w.print("logging: dropped {d} line(s), truncated {d} line(s) {s}\n", .{ dropped, truncated, scope }) catch {};
    w.flush() catch {};
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
        @as(u32, @intFromEnum(mad.month)),
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

/// FHS/XDG system search directories for external `.kmd` data files, highest
/// priority first. The user-level `$HOME/.local/share/vlmzsd` directory is
/// searched before these (see `loadFhsKmd`).
const fhs_system_dirs = [_][]const u8{
    "/etc/vlmzsd",
    "/var/lib/vlmzsd",
    "/usr/local/share/vlmzsd",
    "/usr/share/vlmzsd",
};

/// A `.kmd` data file found on the FHS/XDG search path.
pub const FhsKmd = struct {
    path: []u8,
    data: []u8,
};

/// Read the `.kmd` data file found by the FHS/XDG search, or null when none
/// exists. Directories are searched highest priority first (user-level
/// `$HOME/.local/share/vlmzsd` → `/etc/vlmzsd` → `/var/lib/vlmzsd` →
/// `/usr/local/share/vlmzsd` → `/usr/share/vlmzsd`); within a directory, the
/// alphabetically greatest `*.kmd` name wins. On success the caller owns
/// `path` and `data`. `environ` supplies `HOME`, passed in explicitly so this
/// file needs no libc.
pub fn loadFhsKmd(io: Io, gpa: Allocator, environ: std.process.Environ) !?FhsKmd {
    // 1. User-level: $HOME/.local/share/vlmzsd
    if (std.process.Environ.getPosix(environ, "HOME")) |home| {
        const dir = try std.fmt.allocPrint(gpa, "{s}/.local/share/vlmzsd", .{home});
        defer gpa.free(dir);
        if (try findLastKmd(io, gpa, dir)) |name| {
            defer gpa.free(name);
            return try loadKmdFrom(io, gpa, dir, name);
        }
    }
    // 2. System-level directories.
    for (fhs_system_dirs) |dir| {
        if (try findLastKmd(io, gpa, dir)) |name| {
            defer gpa.free(name);
            return try loadKmdFrom(io, gpa, dir, name);
        }
    }
    return null;
}

/// Return the alphabetically greatest `*.kmd` file name in `dir`, or null when
/// the directory has none (or does not exist).
fn findLastKmd(io: Io, gpa: Allocator, dir_path: []const u8) !?[]u8 {
    var dir = std.Io.Dir.openDirAbsolute(io, dir_path, .{ .iterate = true }) catch |e| switch (e) {
        error.FileNotFound, error.NotDir => return null,
        else => return e,
    };
    defer dir.close(io);

    var best: ?[]u8 = null;
    var it = dir.iterate();
    while (try it.next(io)) |entry| {
        if (entry.kind != .file) continue;
        if (!std.mem.endsWith(u8, entry.name, ".kmd")) continue;
        const better = if (best) |b| std.mem.order(u8, entry.name, b) == .gt else true;
        if (better) {
            if (best) |b| gpa.free(b);
            best = try gpa.dupe(u8, entry.name);
        }
    }
    return best;
}

/// Load the `.kmd` file at `dir_path/name`.
fn loadKmdFrom(io: Io, gpa: Allocator, dir_path: []const u8, name: []const u8) !FhsKmd {
    const full_path = try std.fmt.allocPrint(gpa, "{s}/{s}", .{ dir_path, name });
    errdefer gpa.free(full_path);
    const data = try std.Io.Dir.readFileAlloc(std.Io.Dir.cwd(), io, full_path, gpa, .unlimited);
    return .{ .path = full_path, .data = data };
}

test "parseDurationSeconds" {
    try std.testing.expectEqual(@as(u64, 30), try parseDurationSeconds("30s"));
    try std.testing.expectEqual(@as(u64, 7200), try parseDurationSeconds("2h"));
    try std.testing.expectEqual(@as(u64, 604800), try parseDurationSeconds("7d"));
    try std.testing.expectEqual(@as(u64, 5400), try parseDurationSeconds("90m"));
    // `--timeout 0` / `--activation-interval 0` mean "disabled" and are
    // documented as such; a bare `0` is the only unit-less spelling accepted.
    try std.testing.expectEqual(@as(u64, 0), try parseDurationSeconds("0"));
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
    .{ .name = "verbose", .short = 'v', .group = "Output", .desc = "Verbose logging" },
    .{ .name = "protocol", .kind = .int, .hint = "u16", .group = "Request", .desc = "KMS protocol version" },
    .{ .name = "count", .short = 'n', .kind = .int, .hint = "u32", .group = "Request", .desc = "Number of requests" },
    .{ .name = "reconnect-per-request", .short = 'T', .group = "Connection", .desc = "Reconnect for each request" },
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
    try std.testing.expect(std.mem.indexOf(u8, text, "--protocol [u16]") != null);
    try std.testing.expect(std.mem.indexOf(u8, text, "-v, --verbose") != null);
}

// The producer/writer split is pinned here: formatting and stream routing, the
// `min_level` early return, drop/truncate accounting, drain-on-shutdown, and
// the degraded `direct` path. The writer loop runs on the test thread against
// memory sinks (they are parameters of `runWriter`), so each case is
// deterministic; only the real task dispatch is left to `main`.
//
// No test may write to the process descriptors: `zig build test` runs the test
// binary with `--listen=-`, where stdout is the runner's protocol channel, and a
// stray line deadlocks the build. Hence the injectable `direct_*` sinks.
test "logger routes levels to the matching sink" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    var out_buffer: [4096]u8 = undefined;
    var err_buffer: [4096]u8 = undefined;
    var log = try Logger.init(gpa, io, &out_buffer, &err_buffer);
    defer log.deinit(gpa);
    log.min_level = .debug;

    log.info("hello {d}", .{1});
    log.warn("careful {s}", .{"now"});

    var out_sink: [512]u8 = undefined;
    var err_sink: [512]u8 = undefined;
    var out_writer: std.Io.Writer = .fixed(&out_sink);
    var err_writer: std.Io.Writer = .fixed(&err_sink);
    log.queue.close(io);
    log.runWriter(&out_writer, &err_writer);

    const out_text = out_writer.buffered();
    const err_text = err_writer.buffered();
    try std.testing.expect(std.mem.indexOf(u8, out_text, "hello 1") != null);
    try std.testing.expect(std.mem.indexOf(u8, out_text, "careful") == null);
    try std.testing.expect(std.mem.indexOf(u8, err_text, "warning: careful now") != null);
    try std.testing.expect(std.mem.indexOf(u8, err_text, "hello 1") == null);
    // Both lines carry the fixed ISO-8601 UTC prefix.
    try std.testing.expectEqual(@as(usize, 1), std.mem.count(u8, out_text, "Z "));
    try std.testing.expectEqual(@as(usize, 1), std.mem.count(u8, err_text, "Z "));
}

test "min_level filters before the queue" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    var out_buffer: [4096]u8 = undefined;
    var err_buffer: [4096]u8 = undefined;
    var log = try Logger.init(gpa, io, &out_buffer, &err_buffer);
    defer log.deinit(gpa);
    log.min_level = .info;

    log.debug("filtered {d}", .{1});

    var batch: [4]line_queue.Slot = undefined;
    try std.testing.expectEqual(@as(usize, 0), log.queue.popBatch(io, &batch));
    try std.testing.expectEqual(@as(u64, 0), log.dropped.load(.monotonic));
    try std.testing.expectEqual(@as(u64, 0), log.truncated.load(.monotonic));
}

test "a full queue drops and counts instead of blocking" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    var out_buffer: [4096]u8 = undefined;
    var err_buffer: [4096]u8 = undefined;
    var log = try Logger.init(gpa, io, &out_buffer, &err_buffer);
    defer log.deinit(gpa);
    log.min_level = .debug;

    const overflow = 8;
    var i: usize = 0;
    while (i < line_queue.capacity + overflow) : (i += 1) log.info("line {d}", .{i});
    try std.testing.expectEqual(@as(u64, overflow), log.dropped.load(.monotonic));

    // Every accepted line is intact (newline-terminated), and none is lost.
    var batch: [Logger.batch_size]line_queue.Slot = undefined;
    var drained: usize = 0;
    while (true) {
        const count = log.queue.popBatch(io, &batch);
        if (count == 0) break;
        for (batch[0..count]) |slot| {
            try std.testing.expectEqual(@as(u8, '\n'), slot.bytes[slot.len - 1]);
            drained += 1;
        }
    }
    try std.testing.expectEqual(@as(usize, line_queue.capacity), drained);
}

test "an overlong line becomes one truncated line" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    var out_buffer: [4096]u8 = undefined;
    var err_buffer: [4096]u8 = undefined;
    var log = try Logger.init(gpa, io, &out_buffer, &err_buffer);
    defer log.deinit(gpa);
    log.min_level = .debug;

    log.info("{d:>300}", .{1});

    var batch: [4]line_queue.Slot = undefined;
    try std.testing.expectEqual(@as(usize, 1), log.queue.popBatch(io, &batch));
    try std.testing.expectEqual(@as(u16, line_queue.slot_size), batch[0].len);
    try std.testing.expectEqual(@as(u8, '\n'), batch[0].bytes[line_queue.slot_size - 1]);
    try std.testing.expectEqual(@as(u64, 1), log.truncated.load(.monotonic));
}

test "shutdown drains what the queue accepted and is idempotent" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    var out_buffer: [4096]u8 = undefined;
    var err_buffer: [4096]u8 = undefined;
    var log = try Logger.init(gpa, io, &out_buffer, &err_buffer);
    defer log.deinit(gpa);
    log.min_level = .debug;

    log.info("before shutdown", .{});

    // Pretend the writer task was already parked: close, then drain here.
    log.queue.close(io);
    var out_sink: [512]u8 = undefined;
    var err_sink: [512]u8 = undefined;
    var out_writer: std.Io.Writer = .fixed(&out_sink);
    var err_writer: std.Io.Writer = .fixed(&err_sink);
    log.runWriter(&out_writer, &err_writer);
    try std.testing.expect(std.mem.indexOf(u8, out_writer.buffered(), "before shutdown") != null);

    // `done` is latched by `runWriter`, so both calls return without blocking.
    log.shutdown(io);
    log.shutdown(io);
}

test "direct mode writes synchronously and bypasses the queue" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    var out_buffer: [4096]u8 = undefined;
    var err_buffer: [4096]u8 = undefined;
    var log = try Logger.init(gpa, io, &out_buffer, &err_buffer);
    defer log.deinit(gpa);
    log.direct = true;
    log.min_level = .debug;

    var sink: [512]u8 = undefined;
    var sink_writer: std.Io.Writer = .fixed(&sink);
    log.direct_out = &sink_writer;

    log.info("direct {d}", .{1});

    try std.testing.expect(std.mem.indexOf(u8, sink_writer.buffered(), "direct 1") != null);
    var batch: [4]line_queue.Slot = undefined;
    try std.testing.expectEqual(@as(usize, 0), log.queue.popBatch(io, &batch));
}

// The loss report has two shapes: the delta since the writer's last report when
// it catches up (an idle period), and the totals for the whole run from the
// final drain. Reporting clears what it reported, so the producers' counters
// always hold exactly the unreported loss. Pinned here without running the loop.
test "loss is reported as an idle delta and as a final total" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    var out_buffer: [4096]u8 = undefined;
    var err_buffer: [4096]u8 = undefined;
    var log = try Logger.init(gpa, io, &out_buffer, &err_buffer);
    defer log.deinit(gpa);

    var sink: [2048]u8 = undefined;
    var err_writer: std.Io.Writer = .fixed(&sink);

    // Nothing lost: the idle report is silent, and so is the final one.
    log.reportCounters(&err_writer, .idle);
    log.reportCounters(&err_writer, .final);
    try std.testing.expectEqual(@as(usize, 0), err_writer.buffered().len);

    // An idle period reports the loss it covers, as a delta, and clears the
    // counters it just reported.
    _ = log.dropped.fetchAdd(3, .monotonic);
    log.reportCounters(&err_writer, .idle);
    try std.testing.expect(std.mem.indexOf(u8, err_writer.buffered(), "dropped 3 line(s), truncated 0 line(s) since the last report") != null);
    try std.testing.expectEqual(@as(u64, 0), log.dropped.load(.acquire));
    try std.testing.expectEqual(@as(u64, 3), log.total_dropped);

    // Nothing new since: silent, not a repeat of the same numbers.
    const after_first = err_writer.buffered().len;
    log.reportCounters(&err_writer, .idle);
    try std.testing.expectEqual(after_first, err_writer.buffered().len);

    // A second episode reports only its own loss...
    _ = log.truncated.fetchAdd(2, .monotonic);
    log.reportCounters(&err_writer, .idle);
    try std.testing.expect(std.mem.indexOf(u8, err_writer.buffered(), "dropped 0 line(s), truncated 2 line(s) since the last report") != null);

    // ...while the final report gives the totals for the whole run, including
    // the periods the idle reports already covered.
    log.reportCounters(&err_writer, .final);
    try std.testing.expect(std.mem.indexOf(u8, err_writer.buffered(), "dropped 3 line(s), truncated 2 line(s) in total") != null);
    try std.testing.expectEqual(@as(u64, 3), log.total_dropped);
    try std.testing.expectEqual(@as(u64, 2), log.total_truncated);
    try std.testing.expectEqual(@as(usize, 2), std.mem.count(u8, err_writer.buffered(), "since the last report"));
}
