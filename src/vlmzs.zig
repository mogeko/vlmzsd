//! `vlmzs` — the KMS activation client binary (for testing).
//!
//! Implements the `vlmzs` CLI surface from `docs/cli.md`: sends one or more
//! activation requests to an existing KMS server and prints the result.

const std = @import("std");
const vlmzsd = @import("vlmzsd");
const cli_helper = @import("cli_helper.zig");
const network = @import("network.zig");
const kms = vlmzsd.kms;
const kmsdata = vlmzsd.kmsdata;
const rpc = vlmzsd.rpc;

const Io = std.Io;
const Allocator = std.mem.Allocator;

const build_options = @import("build_options");
const version_display = build_options.version_display;
const default_port: u16 = 1688;
const default_grace_minutes: u32 = 43200;
/// Largest `--license-status` value (docs/cli.md §6).
const max_license_status: u32 = 6;
/// Idle timeout for the BIND reply and every RESPONSE read, mirroring the
/// server's `--timeout` default.
const default_timeout_seconds: u32 = 30;
/// Embedded default `.kmd` data, unless built with `-Dno-embedded-data`
/// (then `--data <file>` is required at runtime).
const embedded_kmd: []const u8 = if (build_options.embedded_data) @embedFile("vlmcsd.kmd") else &.{};

/// One page, the buffer size of every stream and stage in the client: the stdout
/// and stderr writers, a session's socket buffers, and one request's report.
/// The largest report is a `--verbose` request+response dump (~1.5 KiB), so this
/// leaves more than 2x headroom; `Report` also has a spill path so that no text
/// is dropped.
const io_buffer_size = cli_helper.io_buffer_size;
const report_buffer_size = io_buffer_size;

// ---------------------------------------------------------------------------
// Output and report
// ---------------------------------------------------------------------------

/// Bare stdout/stderr writers for the client. The client is a CLI debugging
/// tool, not a service: its answer (ePID) and `--verbose` protocol dumps go to
/// stdout, errors go to stderr — no timestamp, no level, matching the C
/// `vlmcs` client (`printf`/`errorout`). The server-side `cli_helper.Logger`
/// is deliberately not used here.
const Output = struct {
    io: Io,
    out: std.Io.File.Writer,
    err: std.Io.File.Writer,
    /// Guards every write: each `print`/`eprint`, and each whole `writeBlock`
    /// (one request's staged report), is written under this lock.
    mutex: Io.Mutex = .init,
    /// Test seam: when set, output goes here instead of the process
    /// descriptors. `zig build test` runs this binary with `--listen=-`, where
    /// stdout carries the runner's protocol, so a test must never write to the
    /// real stdout (see AGENTS.md → Pitfalls).
    test_out: ?*std.Io.Writer = null,
    test_err: ?*std.Io.Writer = null,

    fn init(io: Io, out_buf: []u8, err_buf: []u8) Output {
        return .{
            .io = io,
            .out = std.Io.File.writer(std.Io.File.stdout(), io, out_buf),
            .err = std.Io.File.writer(std.Io.File.stderr(), io, err_buf),
        };
    }

    fn outWriter(self: *Output) *std.Io.Writer {
        return self.test_out orelse &self.out.interface;
    }

    fn errWriter(self: *Output) *std.Io.Writer {
        return self.test_err orelse &self.err.interface;
    }

    /// Write to stdout and flush (the answer/progress stream).
    fn print(self: *Output, comptime fmt: []const u8, args: anytype) void {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        const writer = self.outWriter();
        writer.print(fmt, args) catch {};
        writer.flush() catch {};
    }

    /// Write to stderr and flush (the error stream).
    fn eprint(self: *Output, comptime fmt: []const u8, args: anytype) void {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        const writer = self.errWriter();
        writer.print(fmt, args) catch {};
        writer.flush() catch {};
    }

    /// Write one request's staged report under a single lock acquisition, so
    /// parallel `--reconnect-per-request` tasks cannot interleave inside a
    /// report. Empty streams are skipped.
    fn writeBlock(self: *Output, out_bytes: []const u8, err_bytes: []const u8) void {
        if (out_bytes.len == 0 and err_bytes.len == 0) return;
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        if (out_bytes.len > 0) {
            const writer = self.outWriter();
            writer.writeAll(out_bytes) catch {};
            writer.flush() catch {};
        }
        if (err_bytes.len > 0) {
            const writer = self.errWriter();
            writer.writeAll(err_bytes) catch {};
            writer.flush() catch {};
        }
    }
};

/// Report a configuration error and exit. The client has no log queue to drain.
fn fatal(out: *Output, comptime fmt: []const u8, args: anytype) noreturn {
    out.eprint(fmt, args);
    std.process.exit(1);
}

/// One request's staged output. A request emits many fragments — a `--verbose`
/// request+response dump is ~25 lines — and they are *mid-line* fragments: the
/// `Sending activation request` prefix has no newline of its own. Writing them
/// straight to `Output` makes every fragment a separate lock acquisition, so
/// parallel tasks splice each other's lines. Staging the whole report and
/// writing it once keeps one request atomic.
///
/// The report-printing helpers below take this as `out` (same `print`/`eprint`
/// methods as `Output`, but staged); everything outside a request keeps writing
/// straight to `Output`.
const Report = struct {
    output: *Output,
    out: std.Io.Writer,
    err: std.Io.Writer,
    /// Kept so the spill path can re-arm the writers. The buffers live in the
    /// caller's frame: `init` returns by value, so embedding them here would
    /// leave the writers pointing into the struct that was just moved.
    out_buffer: []u8,
    err_buffer: []u8,

    fn init(output: *Output, out_buffer: []u8, err_buffer: []u8) Report {
        return .{
            .output = output,
            .out = .fixed(out_buffer),
            .err = .fixed(err_buffer),
            .out_buffer = out_buffer,
            .err_buffer = err_buffer,
        };
    }

    fn print(self: *Report, comptime fmt: []const u8, args: anytype) void {
        self.out.print(fmt, args) catch self.spillOut(fmt, args);
    }

    fn eprint(self: *Report, comptime fmt: []const u8, args: anytype) void {
        self.err.print(fmt, args) catch self.spillErr(fmt, args);
    }

    /// Terminate a half-written report. A request that fails on the wire (peer
    /// vanished mid-exchange) returns after the `Sending activation request`
    /// prefix was staged but before the result completed that line; the caller
    /// then reports the failure on stderr, which would visually continue the
    /// unterminated stdout line. Called from the `errdefer` in `Session.exchange`
    /// *before* the block is flushed, so even the failure path emits a
    /// complete line.
    fn endLine(self: *Report) void {
        if (self.out.buffered().len == 0) return;
        self.print("\n", .{});
    }

    /// Safety valve for a report larger than `report_buffer_size` (unreachable
    /// in practice): flush what is staged and continue in a fresh buffer. The
    /// chunk boundary may interleave with another task, but no text is dropped.
    fn spillOut(self: *Report, comptime fmt: []const u8, args: anytype) void {
        self.output.writeBlock(self.out.buffered(), &.{});
        self.out = .fixed(self.out_buffer);
        self.out.print(fmt, args) catch {};
    }

    fn spillErr(self: *Report, comptime fmt: []const u8, args: anytype) void {
        self.output.writeBlock(&.{}, self.err.buffered());
        self.err = .fixed(self.err_buffer);
        self.err.print(fmt, args) catch {};
    }
};

// ---------------------------------------------------------------------------
// Formatting
// ---------------------------------------------------------------------------

/// Format a 16-byte GUID as the canonical `8-4-4-4-12` hex string. The first
/// three fields are little-endian, the last eight bytes are big-endian — the
/// mixed layout C `uuid2StringLE` reproduces.
fn formatGuid(guid: *const kms.Guid, buf: []u8) []const u8 {
    const data1 = std.mem.readInt(u32, guid[0..4], .little);
    const data2 = std.mem.readInt(u16, guid[4..6], .little);
    const data3 = std.mem.readInt(u16, guid[6..8], .little);
    const data4 = std.mem.readInt(u64, guid[8..16], .big);
    return std.fmt.bufPrint(buf, "{X:0>8}-{X:0>4}-{X:0>4}-{X:0>4}-{X:0>12}", .{
        data1,
        data2,
        data3,
        data4 >> 48,
        data4 & 0xffff_ffff_ffff,
    }) catch unreachable;
}

/// Human-readable license status (C `LicenseStatusText`).
fn licenseStatusText(status: u32) []const u8 {
    return switch (status) {
        0 => "Unlicensed",
        1 => "Licensed",
        2 => "OOB grace",
        3 => "OOT grace",
        4 => "Non-Genuine",
        5 => "Notification",
        6 => "Extended grace",
        else => "Unknown",
    };
}

/// Human-readable reason for a server rejection HRESULT (C `displayRequestError`).
fn rejectionReason(status: u32) ?[]const u8 {
    return switch (status) {
        0xC004F042 => "the KMS server has declined to activate the requested product",
        0x8007000D => "the KMS host cannot handle this product (it only supports legacy protocol versions)",
        0xC004F06C => "the time stamp differs too much from the KMS server time",
        0xC004D104 => "the security processor reported that invalid data was used",
        1 => "an RPC protocol error occurred",
        else => null,
    };
}

/// Format a Unix timestamp as `YYYY-MM-DD HH:MM:SS` in UTC.
fn formatUtc(unix: i64, buf: []u8) []const u8 {
    // A FILETIME before 1970 yields a negative second count; print the epoch
    // instead of trapping.
    const secs: u64 = std.math.cast(u64, unix) orelse 0;
    const epoch = std.time.epoch.EpochSeconds{ .secs = secs };
    const yad = epoch.getEpochDay().calculateYearDay();
    const mad = yad.calculateMonthDay();
    const day_secs: u64 = secs % 86400;
    // A four-digit year is what the fixed-width format holds; clamp a broken
    // clock instead of overflowing the caller's buffer.
    return std.fmt.bufPrint(buf, "{d:0>4}-{d:0>2}-{d:0>2} {d:0>2}:{d:0>2}:{d:0>2}", .{
        @as(u32, @min(yad.year, 9999)),
        @as(u32, mad.month.numeric()),
        @as(u32, mad.day_index) + 1,
        @as(u32, @intCast(day_secs / 3600)),
        @as(u32, @intCast((day_secs % 3600) / 60)),
        @as(u32, @intCast(day_secs % 60)),
    }) catch unreachable;
}

// ---------------------------------------------------------------------------
// CLI surface
// ---------------------------------------------------------------------------

/// Data-driven option table for `vlmzs` (docs/cli.md §6). Single source of
/// truth: drives parsing, `--help` rendering, and validation alike.
const vlmzs_opts = [_]cli_helper.Opt{
    .{ .name = "help", .short = 'h', .group = "General", .desc = "Display this help and exit" },
    .{ .name = "version", .short = 'V', .group = "General", .desc = "Output version information and exit" },
    .{ .name = "product", .kind = .str, .hint = "name", .group = "General", .desc = "Product name or 1-based number (default: first SKU)" },
    .{ .name = "list-products", .short = 'x', .group = "General", .desc = "Print available products and exit" },
    .{ .name = "data", .kind = .str, .hint = "file", .group = "General", .desc = "External .kmd data file (default embedded)" },
    .{ .name = "protocol", .kind = .int, .hint = "u16", .group = "Request", .desc = "KMS protocol version 4/5/6" },
    .{ .name = "app-id", .kind = .guid, .group = "Request", .desc = "Override AppID (GUID)" },
    .{ .name = "sku-id", .kind = .guid, .group = "Request", .desc = "Override SKUID (GUID)" },
    .{ .name = "kms-id", .kind = .guid, .group = "Request", .desc = "Override KMSID (GUID)" },
    .{ .name = "cmid", .short = 'c', .kind = .guid, .group = "Request", .desc = "Client machine ID (GUID, default random)" },
    .{ .name = "prev-cmid", .short = 'o', .kind = .guid, .group = "Request", .desc = "Previous client machine ID (GUID)" },
    .{ .name = "workstation", .short = 'w', .kind = .str, .hint = "name", .group = "Request", .desc = "Workstation name (UTF-8, sent as UTF-16)" },
    .{ .name = "vm", .short = 'm', .group = "Request", .desc = "Present as a virtual machine" },
    .{ .name = "count", .short = 'n', .kind = .int, .hint = "u32", .group = "Request", .desc = "Number of requests (default 1)" },
    .{ .name = "virtual-clients", .short = 'r', .kind = .int, .hint = "u32", .group = "Request", .desc = "NCountPolicy override" },
    .{ .name = "grace", .short = 'g', .kind = .int, .hint = "u32", .group = "Request", .desc = "Grace period minutes" },
    .{ .name = "address-family", .kind = .int, .hint = "u8", .group = "Request", .desc = "IPv4/IPv6 selection (4/6)" },
    .{ .name = "license-status", .short = 't', .kind = .int, .hint = "u32", .group = "Request", .desc = "LicenseStatus field (0-6, default 1)" },
    .{ .name = "reconnect-per-request", .short = 'T', .group = "Connection", .desc = "Reconnect for each request" },
    .{ .name = "timeout", .kind = .str, .hint = "dur", .group = "Connection", .desc = "Idle timeout (default 30s, 0 disables)" },
    .{ .name = "no-multiplexed", .group = "Connection", .desc = "Disable multiplexed RPC" },
    .{ .name = "no-ndr64", .group = "Connection", .desc = "Disable NDR64 transfer syntax" },
    .{ .name = "no-btfn", .group = "Connection", .desc = "Disable bind-time feature negotiation" },
    .{ .name = "verbose", .short = 'v', .group = "Output", .desc = "Verbose logging" },
};

const ClientOptions = struct {
    host: ?[]const u8 = null,
    port: u16 = default_port,
    product: ?[]const u8 = null,
    data_file: ?[]const u8 = null,
    protocol: u16 = 0, // 0 = derive from the selected SKU
    app_id: ?[16]u8 = null,
    sku_id: ?[16]u8 = null,
    kms_id: ?[16]u8 = null,
    cmid: ?[16]u8 = null,
    prev_cmid: ?[16]u8 = null,
    workstation: ?[]const u8 = null,
    vm: bool = false,
    count: u32 = 1,
    virtual_clients: u32 = 0, // 0 = derive from the selected SKU
    grace: u32 = default_grace_minutes,
    address_family: u8 = 0,
    list_products: bool = false,
    license_status: u32 = 1,
    reconnect_per_request: bool = false,
    timeout_seconds: u32 = default_timeout_seconds,
    multiplexed: bool = true,
    ndr64: bool = true,
    btfn: bool = true,
    verbose: bool = false,
};

// ---------------------------------------------------------------------------
// Option resolution
// ---------------------------------------------------------------------------

/// The `HOST[:PORT]` positional, split.
const HostPort = struct {
    host: []const u8,
    port: u16,
};

fn parseHostPort(host_arg: []const u8) !HostPort {
    // "[addr]:port" form (IPv6 with an explicit port).
    if (host_arg.len > 0 and host_arg[0] == '[') {
        const close = std.mem.indexOfScalar(u8, host_arg, ']') orelse return error.InvalidHost;
        const host = host_arg[1..close];
        const rest = host_arg[close + 1 ..];
        const port: u16 = if (rest.len > 1 and rest[0] == ':')
            try std.fmt.parseInt(u16, rest[1..], 10)
        else
            default_port;
        return .{ .host = host, .port = port };
    }
    // "host:port" — a single colon separates host and port (an IPv6 literal has
    // several colons and is treated as host-only).
    const first = std.mem.indexOfScalar(u8, host_arg, ':');
    const last = std.mem.lastIndexOfScalar(u8, host_arg, ':');
    if (first != null and first == last) {
        const host = host_arg[0..first.?];
        const port = try std.fmt.parseInt(u16, host_arg[first.? + 1 ..], 10);
        return .{ .host = host, .port = port };
    }
    return .{ .host = host_arg, .port = default_port };
}

/// Parse an integer option, recording which option and value failed so the
/// caller can name them (`--count: invalid value "abc"`).
fn intValue(comptime T: type, res: *const cli_helper.Result, spelling: []const u8, diag: *cli_helper.Diag) !?T {
    const text = res.get(spelling[2..]) orelse return null;
    return std.fmt.parseInt(T, text, 10) catch |e| {
        diag.* = .{ .spelling = spelling, .value = text };
        return e;
    };
}

fn guidValue(res: *const cli_helper.Result, spelling: []const u8, diag: *cli_helper.Diag) !?[16]u8 {
    const text = res.get(spelling[2..]) orelse return null;
    return cli_helper.parseGuid(text) catch |e| {
        diag.* = .{ .spelling = spelling, .value = text };
        return e;
    };
}

fn resolveOptions(res: *const cli_helper.Result, diag: *cli_helper.Diag) !ClientOptions {
    var opts = ClientOptions{};

    // Positional HOST[:PORT]; a second word is a mistyped flag value.
    if (res.positionals.items.len > 1) return error.UnexpectedPositional;
    if (res.positionals.items.len > 0) {
        const hp = parseHostPort(res.positionals.items[0]) catch |e| {
            diag.* = .{ .spelling = "HOST[:PORT]", .value = res.positionals.items[0] };
            return e;
        };
        opts.host = hp.host;
        opts.port = hp.port;
    }

    opts.product = res.get("product");
    opts.data_file = res.get("data");
    opts.protocol = if (try intValue(u16, res, "--protocol", diag)) |version| blk: {
        if (version != 4 and version != 5 and version != 6) return error.InvalidProtocol;
        break :blk version;
    } else 0;
    opts.app_id = try guidValue(res, "--app-id", diag);
    opts.sku_id = try guidValue(res, "--sku-id", diag);
    opts.kms_id = try guidValue(res, "--kms-id", diag);
    opts.cmid = try guidValue(res, "--cmid", diag);
    opts.prev_cmid = try guidValue(res, "--prev-cmid", diag);
    opts.workstation = res.get("workstation");
    if (opts.workstation) |name| {
        // The request field is UTF-16; the option is UTF-8. Reject a name that
        // cannot be decoded instead of sending replacement bytes.
        if (!std.unicode.utf8ValidateSlice(name)) return error.InvalidWorkstation;
    }
    opts.vm = res.hasFlag("vm");
    opts.count = (try intValue(u32, res, "--count", diag)) orelse 1;
    opts.virtual_clients = (try intValue(u32, res, "--virtual-clients", diag)) orelse 0;
    opts.grace = (try intValue(u32, res, "--grace", diag)) orelse default_grace_minutes;
    opts.address_family = (try intValue(u8, res, "--address-family", diag)) orelse 0;
    if (opts.address_family != 0 and opts.address_family != 4 and opts.address_family != 6) {
        return error.InvalidAddressFamily;
    }
    opts.list_products = res.hasFlag("list-products");
    opts.license_status = (try intValue(u32, res, "--license-status", diag)) orelse 1;
    if (opts.license_status > max_license_status) return error.InvalidLicenseStatus;
    opts.reconnect_per_request = res.hasFlag("reconnect-per-request");
    opts.timeout_seconds = if (res.get("timeout")) |s|
        std.math.cast(u32, cli_helper.parseDurationSeconds(s) catch |e| {
            diag.* = .{ .spelling = "--timeout", .value = s };
            return e;
        }) orelse return error.InvalidTimeout
    else
        default_timeout_seconds;
    opts.multiplexed = !res.hasFlag("no-multiplexed");
    opts.ndr64 = !res.hasFlag("no-ndr64");
    opts.btfn = !res.hasFlag("no-btfn");
    opts.verbose = res.hasFlag("verbose");

    return opts;
}

/// Report a configuration error and exit. One wording per `resolveOptions`
/// failure, so `main` stays a sequence of phases.
fn reportOptionError(out: *Output, diag: *const cli_helper.Diag, err: anyerror) noreturn {
    switch (err) {
        error.UnexpectedPositional => fatal(out, "error: at most one HOST[:PORT] argument is accepted\n", .{}),
        error.InvalidProtocol => fatal(out, "error: --protocol must be 4, 5, or 6\n", .{}),
        error.InvalidLicenseStatus => fatal(out, "error: --license-status must be 0..{d}\n", .{max_license_status}),
        error.InvalidWorkstation => fatal(out, "error: --workstation must be valid UTF-8\n", .{}),
        error.InvalidAddressFamily => fatal(out, "error: --address-family must be 4 or 6\n", .{}),
        error.InvalidTimeout => fatal(out, "error: --timeout must be at most {d} seconds\n", .{std.math.maxInt(u32)}),
        else => {
            var vbuf: [cli_helper.diag_buffer_size]u8 = undefined;
            fatal(out, "error: {s}\n", .{cli_helper.describeValueError(diag.*, err, &vbuf)});
        },
    }
}

// ---------------------------------------------------------------------------
// Data selection
// ---------------------------------------------------------------------------

/// Resolve the product selector (name or 1-based number) to a SKU index.
fn findSku(data: *const kmsdata.KmsData, product: ?[]const u8) !usize {
    const skus = data.skus();
    const sel = product orelse return 0;
    if (std.fmt.parseInt(u32, sel, 10)) |n| {
        if (n >= 1 and n <= skus.len) return n - 1;
        return error.InvalidProduct;
    } else |_| {
        var i = skus.len;
        while (i > 0) {
            i -= 1;
            if (std.ascii.eqlIgnoreCase(skus[i].name, sel)) return i;
        }
        return error.InvalidProduct;
    }
}

/// The client needs an App/KMS/SKU entry for every activation request.
/// `kmsdata.parse` already rejects empty arrays; this keeps the client's
/// contract explicit.
fn validateKmsData(data: *const kmsdata.KmsData) error{IncompleteKmsData}!void {
    if (data.app_count == 0 or data.kms_count == 0 or data.sku_count == 0) {
        return error.IncompleteKmsData;
    }
}

// ---------------------------------------------------------------------------
// Request construction
// ---------------------------------------------------------------------------

fn randomCmid(rng: std.Random) [16]u8 {
    var g: [16]u8 = undefined;
    rng.bytes(&g);
    // Serialized order: Data3 is bytes 6..8 little-endian, so its high byte —
    // where the version nibble lives — is byte 7 (docs/migration.md §3.3).
    g[7] = (g[7] & 0x0F) | 0x40; // UUID version 4
    g[8] = (g[8] & 0x3F) | 0x80; // RFC 4122 variant
    return g;
}

/// Fill the request's workstation name, a 64-code-unit UTF-16 field that must
/// end with a NUL when it fits (C `utf8_to_ucs2`).
///
/// The option value is UTF-8, so it is decoded rather than copied byte by byte:
/// a non-ASCII name would otherwise be sent as mojibake. Names longer than 63
/// code units are truncated, never splitting a surrogate pair.
fn setWorkstationName(base: *kms.Request, name: ?[]const u8, rng: std.Random) void {
    const dst = base.workstation_name[0 .. kms.workstation_name_buffer - 1];
    if (name) |n| {
        // `resolveOptions` rejected invalid UTF-8, so the view cannot fail here.
        var view = std.unicode.Utf8View.initUnchecked(n);
        var it = view.iterator();
        var len: usize = 0;
        while (it.nextCodepoint()) |codepoint| {
            if (codepoint < 0x10000) {
                if (len == dst.len) break;
                dst[len] = @intCast(codepoint);
                len += 1;
            } else {
                // Surrogate pairs take two code units, or none.
                if (dst.len - len < 2) break;
                const offset = codepoint - 0x10000;
                dst[len] = 0xD800 + @as(u16, @intCast(offset >> 10));
                dst[len + 1] = 0xDC00 + @as(u16, @intCast(offset & 0x3FF));
                len += 2;
            }
        }
        base.workstation_name[len] = 0;
    } else {
        const len: usize = 1 + rng.uintLessThan(u8, 14);
        for (0..len) |i| dst[i] = 'A' + rng.uintLessThan(u8, 26);
        base.workstation_name[len] = 0;
    }
}

fn buildRequestBase(
    opts: *const ClientOptions,
    data: *const kmsdata.KmsData,
    sku_index: usize,
    rng: std.Random,
    io: Io,
) kms.Request {
    const sku = data.skus()[sku_index];
    const kms_item = data.kms()[sku.kms_index];
    const app_item = data.apps()[sku.app_index];

    var base = std.mem.zeroes(kms.Request);
    const proto: u16 = if (opts.protocol != 0) opts.protocol else blk: {
        const p = sku.protocol_version;
        break :blk if (p != 0) @as(u16, p) else 6;
    };
    base.version = @as(u32, proto) << 16;
    base.vm_info = if (opts.vm) 1 else 0;
    base.license_status = opts.license_status;
    base.binding_expiration = opts.grace;
    base.app_id = opts.app_id orelse app_item.guid;
    base.act_id = opts.sku_id orelse sku.guid;
    base.kms_id = opts.kms_id orelse kms_item.guid;
    base.n_policy = if (opts.virtual_clients != 0) opts.virtual_clients else @max(@as(u32, sku.n_count_policy), 1);
    base.client_time = kms.u64ToFileTime(kms.unixTimeToFileTime(cli_helper.nowUnix(io)));
    base.cmid = opts.cmid orelse randomCmid(rng);
    base.cmid_prev = opts.prev_cmid orelse kms.zeroGuid();
    setWorkstationName(&base, opts.workstation, rng);
    return base;
}

/// Narrow a NUL-terminated UTF-16 field to ASCII bytes. Valid for the ePID,
/// whose characters are ASCII by construction.
fn ucs2ToAscii(pid: *const [64]u16, out: []u8) []const u8 {
    var i: usize = 0;
    while (i < pid.len and pid[i] != 0 and i < out.len) : (i += 1) {
        out[i] = @truncate(pid[i]);
    }
    return out[0..i];
}

/// Decode a NUL-terminated UTF-16 field (`workstation_name`) as UTF-8. `out`
/// must hold three bytes per code unit. An unpaired surrogate has no UTF-8
/// form, so such a field prints as empty rather than as mojibake.
fn utf16FieldToUtf8(field: *const [64]u16, out: []u8) []const u8 {
    var len: usize = 0;
    while (len < field.len and field[len] != 0) len += 1;
    const written = std.unicode.utf16LeToUtf8(out, field[0..len]) catch return out[0..0];
    return out[0..written];
}

// ---------------------------------------------------------------------------
// Response reporting
// ---------------------------------------------------------------------------

/// Report each failed response-verification check to stderr (C `displayResponse`).
fn reportVerificationErrors(result: kms.ResponseResult, out: *Report) void {
    out.print("\n", .{}); // end the in-progress "Sending ..." line on stdout
    if (!result.rpc_ok) out.eprint("ERROR: non-zero RPC result code\n", .{});
    if (!result.decrypt_success) out.eprint("ERROR: decryption of the V5/V6 response failed\n", .{});
    if (!result.ivs_ok) out.eprint("ERROR: AES CBC initialization vectors of request and response do not match\n", .{});
    if (!result.pid_length_ok) out.eprint("ERROR: the length of the PID is not valid\n", .{});
    if (!result.hash_ok) out.eprint("ERROR: computed hash does not match the hash in the response\n", .{});
    if (!result.client_machine_id_ok) out.eprint("ERROR: client machine GUIDs of request and response do not match\n", .{});
    if (!result.timestamp_ok) out.eprint("ERROR: time stamps of request and response do not match\n", .{});
    if (!result.version_ok) out.eprint("ERROR: protocol versions of request and response do not match\n", .{});
    if (!result.hmac_sha256_ok) out.eprint("ERROR: keyed-hash message authentication code (HMAC) is incorrect\n", .{});
    if (!result.iv_not_suspicious) out.eprint("WARNING: the KMS server is an emulator (response uses a KMSv5-style IV in KMSv6)\n", .{});
    if (result.effective_response_size != result.correct_response_size) {
        out.eprint("WARNING: RPC payload size should be {d} but is {d}\n", .{
            result.correct_response_size,
            result.effective_response_size,
        });
    }
}

/// Report a server rejection to stderr with a human-readable reason when known
/// (C `displayRequestError`).
fn printRejection(status: i32, out: *Report) void {
    out.print("\n", .{}); // end the in-progress "Sending ..." line on stdout
    const hr: u32 = @bitCast(status);
    if (rejectionReason(hr)) |reason| {
        out.eprint("Error 0x{X:0>8}: {s}\n", .{ hr, reason });
    } else {
        out.eprint("Error 0x{X:0>8}\n", .{hr});
    }
}

/// Print the activation answer to stdout (C `displayResponse`, non-verbose).
/// `hwid` is only present for v6 responses.
fn printResultSummary(base: *const kms.Response, hwid: ?*const [8]u8, out: *Report) void {
    var epid_buf: [64]u8 = undefined;
    const epid = ucs2ToAscii(&base.kms_pid, &epid_buf);
    out.print(" -> {s}", .{epid});
    if (hwid) |h| out.print(" ({X:0>16})", .{std.mem.readInt(u64, h, .big)});
    out.print("\n", .{});
}

/// One aligned GUID line with the product name when the GUID is in `list`.
fn printGuidLine(out: *Report, label: []const u8, guid: *const kms.Guid, list: []const kmsdata.VlmcsdData) void {
    var buf: [64]u8 = undefined;
    if (kms.getProductIndex(guid, list)) |idx| {
        out.print("{s:<32}: {s} ({s})\n", .{ label, formatGuid(guid, &buf), list[idx].name });
    } else {
        out.print("{s:<32}: {s}\n", .{ label, formatGuid(guid, &buf) });
    }
}

/// Verbose per-field request dump (C `logRequestVerbose`).
fn printRequestVerbose(req: *const kms.Request, data: *const kmsdata.KmsData, out: *Report) void {
    const major: u16 = @truncate(req.version >> 16);
    const minor: u16 = @truncate(req.version);
    var guid_buf: [64]u8 = undefined;
    var time_buf: [64]u8 = undefined;
    // Three UTF-8 bytes per UTF-16 code unit (63 units at most).
    var ws_buf: [3 * kms.workstation_name_buffer]u8 = undefined;

    out.print("\nRequest Parameters\n==================\n\n", .{});
    out.print("Protocol version                : {d}.{d}\n", .{ major, minor });
    out.print("Client is a virtual machine     : {s}\n", .{if (req.vm_info != 0) "Yes" else "No"});
    out.print("Licensing status                : {d} ({s})\n", .{ req.license_status, licenseStatusText(req.license_status) });
    out.print("Remaining time (0 = forever)    : {d} minutes\n", .{req.binding_expiration});
    printGuidLine(out, "Application ID", &req.app_id, data.apps());
    printGuidLine(out, "SKU ID (aka Activation ID)", &req.act_id, data.skus());
    printGuidLine(out, "KMS ID (aka KMS counted ID)", &req.kms_id, data.kms());
    out.print("Client machine ID               : {s}\n", .{formatGuid(&req.cmid, &guid_buf)});
    out.print("Previous client machine ID      : {s}\n", .{formatGuid(&req.cmid_prev, &guid_buf)});
    out.print("Client request timestamp (UTC)  : {s}\n", .{formatUtc(kms.fileTimeToUnixTime(kms.fileTimeToU64(req.client_time)), &time_buf)});
    out.print("Workstation name                : {s}\n", .{utf16FieldToUtf8(&req.workstation_name, &ws_buf)});
    out.print("N count policy (minimum clients): {d}\n", .{req.n_policy});
    out.print("\n", .{});
}

/// Verbose per-field response dump (C `logResponseVerbose`).
fn printResponseVerbose(base: *const kms.Response, hwid: ?*const [8]u8, result: kms.ResponseResult, out: *Report) void {
    const major: u16 = @truncate(base.version >> 16);
    const minor: u16 = @truncate(base.version);
    var epid_buf: [64]u8 = undefined;
    var guid_buf: [64]u8 = undefined;
    var time_buf: [64]u8 = undefined;

    out.print("\n\nResponse from KMS server\n========================\n\n", .{});
    out.print("Size of KMS Response            : {d} (0x{x})\n", .{ result.effective_response_size, result.effective_response_size });
    out.print("Protocol version                : {d}.{d}\n", .{ major, minor });
    out.print("KMS host extended PID           : {s}\n", .{ucs2ToAscii(&base.kms_pid, &epid_buf)});
    if (hwid) |h| out.print("KMS host Hardware ID            : {X:0>16}\n", .{std.mem.readInt(u64, h, .big)});
    out.print("Client machine ID               : {s}\n", .{formatGuid(&base.cmid, &guid_buf)});
    out.print("Client request timestamp (UTC)  : {s}\n", .{formatUtc(kms.fileTimeToUnixTime(kms.fileTimeToU64(base.client_time)), &time_buf)});
    out.print("KMS host current active clients : {d}\n", .{base.count});
    out.print("Renewal interval policy         : {d}\n", .{base.vl_renewal_interval});
    out.print("Activation interval policy      : {d}\n", .{base.vl_activation_interval});
    out.print("\n", .{});
}

/// The server's answer: the per-field dump under `--verbose`, else the one-line
/// summary. `hwid` is present only for v6 responses.
fn printResponse(out: *Report, base: *const kms.Response, hwid: ?*const [8]u8, result: kms.ResponseResult, verbose: bool) void {
    if (verbose) {
        printResponseVerbose(base, hwid, result, out);
    } else {
        printResultSummary(base, hwid, out);
    }
}

// ---------------------------------------------------------------------------
// Transport
// ---------------------------------------------------------------------------

/// Transfer syntax for a request: the reference client sends the first request
/// after BIND as NDR32 and later ones as NDR64 (`firstPacketSent` in
/// `rpcSendRequest`) — the Windows KMS client behaves the same way. NDR64 is an
/// option only when the server accepted it.
fn requestUseNdr64(bind: rpc.BindResult, first: bool, ndr64_allowed: bool) bool {
    const ndr64_ok = ndr64_allowed and bind.has_ndr64;
    return if (first) !bind.has_ndr32 and ndr64_ok else ndr64_ok;
}

/// One client connection that outlives a single request: the socket, its
/// buffers, and the negotiation outcome.
///
/// The packet reader holds pointers into this struct, so a session must never be
/// copied after `open` — it stays in the caller's frame as a single `var`, which
/// is also what lets `reopen` re-address `conn` after a reconnection.
/// Everything one run borrows: the allocator, the process handles, the resolved
/// options and the loaded data. Grouped so the send path passes one pointer
/// rather than five, and so a test can build one without a whole `main`.
const Client = struct {
    gpa: Allocator,
    io: Io,
    opts: *const ClientOptions,
    out: *Output,
    data: *const kmsdata.KmsData,
};

/// The window `--reconnect-per-request` runs in: one permit per pooled thread,
/// and the failure counter the exit status is built from.
const Window = struct {
    permits: *Io.Semaphore,
    failures: *std.atomic.Value(u32),
};

/// Whether a failed exchange may be resent on a fresh connection. A one-shot
/// connection (`--reconnect-per-request`) has nothing to retry; a reused one
/// meets a closed socket whenever the server disconnects per request.
const Retry = enum { never, once };

/// One client connection that outlives a single request: the socket, its
/// buffers, and the negotiation outcome.
///
/// The packet reader holds pointers into this struct, so a session must never be
/// copied after `open` — it stays in the caller's frame as a single `var`, which
/// is also what lets `reopen` re-address `conn` after a reconnection.
const Session = struct {
    io: Io,
    stream: Io.net.Stream = undefined,
    /// Fallback source for the packet reader; socket reads go through
    /// `conn.packet_reader`, so this stays empty.
    reader: Io.Reader = undefined,
    writer: Io.net.Stream.Writer = undefined,
    conn: network.ClientSession = undefined,
    /// BIND/ALTER-CONTEXT outcome, kept so later requests can widen to NDR64.
    bind: rpc.BindResult = undefined,
    /// True until the first REQUEST went out: the reference sends that one as
    /// NDR32 when the server accepted both syntaxes (`firstPacketSent` in
    /// `rpcSendRequest`).
    first_packet: bool = true,
    /// Read-ahead for the packet reader: a header and its body arrive together.
    rbuf: [io_buffer_size]u8 = undefined,
    wbuf: [io_buffer_size]u8 = undefined,
    /// The owner reconnects and resends when the peer closed the connection, so
    /// this attempt's report is dropped instead of printing its header again.
    retry_on_close: bool = false,

    fn init(io: Io) Session {
        return .{ .io = io };
    }

    /// Connect and BIND, leaving `conn` ready to carry one REQUEST.
    fn open(self: *Session, client: *const Client) !void {
        const io = self.io;
        const opts = client.opts;
        self.stream = try network.connect(io, opts.host.?, opts.port, opts.address_family);
        self.reader = Io.Reader.fixed("");
        self.writer = self.stream.writer(io, &self.wbuf);
        self.conn = .{
            .allocator = client.gpa,
            .packet_reader = .init(.{ .peer = .{
                .io = io,
                .handle = self.stream.socket.handle,
                .timeout = network.timeoutSeconds(opts.timeout_seconds),
            } }, &self.reader, &self.rbuf),
            .writer = &self.writer.interface,
            .call_id = 2,
            .use_btfn = opts.btfn,
            .multiplexed = opts.multiplexed,
        };
        // A reused session reconnects when the peer closed; a one-shot
        // connection (`--reconnect-per-request`) has nothing to retry.
        self.retry_on_close = true;
        self.first_packet = true;
        self.bind = try self.bindContexts();
        // The transfer syntax is the request's, not the connection's: `exchange`
        // picks it from `bind` and `first_packet` before every send.
    }

    /// BIND, plus the ALTER-CONTEXT that binds NDR32 when the server NACKed it.
    /// Mirrors the reference `rpcBindClient`: a server NACKs NDR32 while NDR64
    /// is available (Microsoft behavior), so this is also the path a Windows KMS
    /// client takes. Without it the first request would have to go out as NDR64,
    /// and a server without NDR64 could not be served at all.
    fn bindContexts(self: *Session) !rpc.BindResult {
        var bind = try self.conn.bind();
        if (!bind.has_ndr32) {
            const alter = try self.conn.alterContext();
            if (alter.has_ndr32) bind.has_ndr32 = true;
        }
        // The reference reports `RPC_S_NO_PROTSEQS` here; fail before sending a
        // request that no negotiated context could carry.
        if (!bind.has_ndr32 and !bind.has_ndr64) return error.NoTransferSyntax;
        return bind;
    }

    fn close(self: *Session) void {
        self.stream.close(self.io);
    }

    /// Replace a connection the peer closed (`--disconnect-per-request` on the
    /// server, or any keep-alive timeout) with a fresh one.
    fn reopen(self: *Session, client: *const Client) !void {
        self.close();
        try self.open(client);
    }

    /// True when this send failure means "the peer closed, the owner will resend
    /// on a fresh connection", so this attempt's staged report is dropped instead
    /// of printing a header the retry prints again.
    fn willRetry(self: *const Session, err: anyerror) bool {
        if (!self.retry_on_close) return false;
        return switch (err) {
            error.EndOfStream, error.ConnectionResetByPeer, error.SocketUnconnected => true,
            else => false,
        };
    }

    /// Send one KMS request, verify and report the answer. Everything is staged in
    /// a `Report` and flushed as one block, so a concurrent request cannot splice
    /// its output into this one's.
    fn exchange(self: *Session, client: *const Client, base: kms.Request, rng: std.Random) !Outcome {
        // One request = one lock acquisition: stage the report here and flush it
        // on every exit path, including the early rejection/verification returns.
        var report_out_buffer: [report_buffer_size]u8 = undefined;
        var report_err_buffer: [report_buffer_size]u8 = undefined;
        var report = Report.init(client.out, &report_out_buffer, &report_err_buffer);
        // Set when the connection turns out to be closed and the caller will
        // resend on a fresh one: the nothing-happened attempt leaves no output.
        var discard_report = false;
        defer if (!discard_report) client.out.writeBlock(report.out.buffered(), report.err.buffered());
        // A network failure below returns with the request prefix still unline-
        // terminated; close the line before the flush above, so the caller's
        // stderr diagnostic does not continue it.
        errdefer if (!discard_report) report.endLine();

        // The transfer syntax is this request's, and the first REQUEST after BIND
        // is the one that goes out as NDR32 (see `requestUseNdr64`).
        self.conn.use_ndr64 = requestUseNdr64(self.bind, self.first_packet, client.opts.ndr64);
        self.first_packet = false;

        const proto: u16 = @intCast(base.version >> 16);
        if (client.opts.verbose) printRequestVerbose(&base, client.data, &report);
        report.print("Sending activation request (KMS V{d}) ", .{proto});

        if (proto == 4) {
            var req: kms.RequestV4 = undefined;
            kms.createRequestV4(&req, &base);
            const sent = self.conn.sendRequest(std.mem.asBytes(&req)) catch |err| {
                discard_report = self.willRetry(err);
                return err;
            };
            defer client.gpa.free(sent.data);
            if (sent.status != 0) {
                printRejection(sent.status, &report);
                return .failed;
            }
            var resp: kms.ResponseV4 = undefined;
            const result = kms.decryptResponseV4(&resp, sent.data.len, sent.data, &req);
            if (!result.ok()) {
                reportVerificationErrors(result, &report);
                return .failed;
            }
            printResponse(&report, &resp.base, null, result, client.opts.verbose);
        } else {
            var req: kms.RequestV6 = undefined;
            kms.createRequestV6(&req, &base, rng);
            const sent = self.conn.sendRequest(std.mem.asBytes(&req)) catch |err| {
                discard_report = self.willRetry(err);
                return err;
            };
            defer client.gpa.free(sent.data);
            if (sent.status != 0) {
                printRejection(sent.status, &report);
                return .failed;
            }
            var resp: kms.ResponseV6 = undefined;
            // Only a v6 response carries a HwId, and only then does the decrypt
            // copy one out; a v5 response has no field to print.
            const is_v6 = proto > 5;
            var hwid: [8]u8 = @splat(0);
            const result = kms.decryptResponseV6(&resp, sent.data.len, sent.data, &req, if (is_v6) &hwid else null);
            if (!result.ok()) {
                reportVerificationErrors(result, &report);
                return .failed;
            }
            const hwid_or_null: ?*const [8]u8 = if (is_v6) &hwid else null;
            printResponse(&report, &resp.base, hwid_or_null, result, client.opts.verbose);
        }
        return .activated;
    }

    /// `exchange`, plus the one reconnect-and-resend a reused connection needs.
    /// The failed attempt never reached a live connection, so resending is safe:
    /// one reopen per request, no retry loop.
    fn transact(self: *Session, client: *const Client, base: kms.Request, rng: std.Random, retry: Retry) !Outcome {
        return self.exchange(client, base, rng) catch |err| switch (err) {
            error.EndOfStream, error.ConnectionResetByPeer, error.SocketUnconnected => {
                if (retry == .never) return err;
                try self.reopen(client);
                return self.exchange(client, base, rng);
            },
            else => |e| return e,
        };
    }
};

/// What one activation attempt produced. A server rejection and a failed
/// response verification are both `failed`: the client did reach the server, but
/// the activation did not succeed, which is what the exit status reports.
/// Transport failures stay Zig errors and propagate to the caller.
const Outcome = enum { activated, failed };

/// Send one request over its own connection (`--reconnect-per-request`).
fn sendRequest(client: *const Client, base: kms.Request, rng: std.Random) !Outcome {
    var session: Session = .init(client.io);
    try session.open(client);
    defer session.close();
    return session.transact(client, base, rng, .never);
}

/// Exit non-zero when any request did not activate. The per-request diagnostics
/// are already on stderr; this is the summary the exit status refers to.
fn exitOnFailures(out: *Output, failures: u32, total: u32) void {
    if (failures == 0) return;
    out.eprint("{d} of {d} request(s) failed\n", .{ failures, total });
    std.process.exit(1);
}

/// A dispatch failure is fatal for a one-shot client, but the requests already
/// in flight are joined before exiting: `Group.cancel` asks them to stop — every
/// wait inside `sendRequest` (connect, BIND, response) is a cancelation point —
/// and waits for them, so the process never leaves a task mid-write. Never
/// returns.
fn dispatchFailed(out: *Output, io: Io, group: *Io.Group, err: anyerror) noreturn {
    group.cancel(io);
    out.eprint("failed to dispatch request: {s}\n", .{@errorName(err)});
    std.process.exit(1);
}

// ---------------------------------------------------------------------------
// Dispatch
// ---------------------------------------------------------------------------

/// One activation request dispatched as a pooled task (via `Group.concurrent`).
/// Derives its own PRNG from `seed` so concurrent requests never share PRNG
/// state; failures are reported here rather than propagated. `permits` is the
/// dispatcher's window: the slot is returned on *every* exit path, so a task
/// that fails or is dropped cannot starve later dispatches.
fn sendRequestTask(client: *const Client, base: kms.Request, seed: u64, window: *const Window) void {
    defer window.permits.post(client.io);
    var prng: std.Random.DefaultPrng = .init(seed);
    const outcome = sendRequest(client, base, prng.random()) catch |e| switch (e) {
        // Aborted, not failed: this is `dispatchFailed`'s cancel, and the
        // dispatch error it is already reporting says why.
        error.Canceled => return,
        else => {
            client.out.eprint("request failed: {s}\n", .{@errorName(e)});
            _ = window.failures.fetchAdd(1, .monotonic);
            return;
        },
    };
    if (outcome == .failed) _ = window.failures.fetchAdd(1, .monotonic);
}

/// How many `--reconnect-per-request` requests may be in flight at once.
///
/// One request parked in a read owns one pooled thread and the pool never
/// reclaims a worker, so this is a thread bound, not a tuning knob: thread count
/// settles at `min(--count, parallelism()) + 1`, and a larger `--count`
/// completes in waves instead of one thread per request. The rule is the one
/// `Io.Threaded` uses to size its own `async_limit` (the logical CPU count) —
/// `std.process.Init` does not expose that option, so the bound has to be ours.
/// Window used when the platform cannot report a CPU count.
const fallback_parallelism: usize = 8;

fn parallelism() usize {
    const count = std.Thread.getCpuCount() catch fallback_parallelism;
    // A zero here would park the dispatcher on a semaphore nothing can post.
    std.debug.assert(count >= 1);
    return count;
}

/// Send `--count` requests over a single reused connection (keep-alive).
/// Requests are sequential because one connection carries one in-flight RPC.
/// Returns how many of them did not activate.
fn sendRequestsReused(client: *const Client, sku_index: usize, rng: std.Random) !u32 {
    var session: Session = .init(client.io);
    try session.open(client);
    defer session.close();

    var failures: u32 = 0;
    var i: usize = 0;
    while (i < client.opts.count) : (i += 1) {
        const base = buildRequestBase(client.opts, client.data, sku_index, rng, client.io);
        if (try session.transact(client, base, rng, .once) == .failed) failures += 1;
    }
    return failures;
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

fn listProducts(data: *const kmsdata.KmsData, out: *Output) void {
    out.print("You may use these product names or numbers:\n", .{});
    for (data.skus(), 0..) |sku, i| {
        out.print("{d:>3} = {s}\n", .{ i + 1, sku.name });
    }
}

pub fn main(init: std.process.Init) !void {
    const prog: cli_helper.Program = .{
        .name = "vlmzs",
        .version_display = version_display,
        .positional_hint = "[HOST[:PORT]]",
    };
    var res = (try cli_helper.parseProcess(init, &vlmzs_opts, prog, null)) orelse return;
    defer res.deinit();
    var diag: cli_helper.Diag = .{};

    var out_buf: [io_buffer_size]u8 = undefined;
    var err_buf: [io_buffer_size]u8 = undefined;
    var out: Output = .init(init.io, &out_buf, &err_buf);

    var opts = resolveOptions(&res, &diag) catch |e| reportOptionError(&out, &diag, e);

    // `--data` → FHS/XDG search → embedded default; the order is the helper's,
    // the wording and the exit are this binary's.
    var loaded = switch (cli_helper.loadKmsData(init.io, init.gpa, init.environ_map, opts.data_file, embedded_kmd)) {
        .loaded => |l| l,
        .failed => |why| switch (why) {
            .data_file => |d| fatal(&out, "error: failed to read data file {s}: {s}\n", .{ d.path, @errorName(d.err) }),
            .fhs => |e| fatal(&out, "error: failed to read FHS data file: {s}\n", .{@errorName(e)}),
            .no_data => fatal(&out, "error: no KMS data found; specify --data <file>\n", .{}),
        },
    };
    defer loaded.deinit(init.gpa);

    var data = kmsdata.parse(init.gpa, loaded.raw) catch |e| {
        out.eprint("error: invalid KMS data: {s}\n", .{@errorName(e)});
        std.process.exit(1);
    };
    defer data.deinit(init.gpa);

    validateKmsData(&data) catch {
        out.eprint("error: incomplete KMS data file\n", .{});
        std.process.exit(1);
    };

    if (opts.list_products) {
        listProducts(&data, &out);
        return;
    }

    if (opts.host == null) {
        // Default host (mirrors the C `useDefaultHost`): "::1" for IPv6-only,
        // otherwise "127.0.0.1".
        opts.host = if (opts.address_family == 6) "::1" else "127.0.0.1";
    }

    const sku_index = findSku(&data, opts.product) catch {
        out.eprint("error: invalid product selector\n", .{});
        std.process.exit(1);
    };

    const client: Client = .{ .gpa = init.gpa, .io = init.io, .opts = &opts, .out = &out, .data = &data };
    var prng: std.Random.DefaultPrng = .init(cli_helper.makeSeed(init.io));

    if (opts.reconnect_per_request) {
        // Each request gets its own connection; dispatch them in parallel onto
        // the Io.Threaded pool. Each request builds its base and derives its own
        // PRNG before submission, so concurrent tasks never share PRNG state.
        //
        // `--count` must not decide the thread count: a request parked in a
        // read owns one pool thread, the pool never reclaims one, and
        // `std.process.Init` does not expose `concurrent_limit` — so `-T -n 600`
        // against a silent peer would be 600 threads. `permits` is the window
        // (one slot per core, the same rule the backend uses for its own
        // `async_limit`); the dispatcher blocks on it, so the bound is ours.
        var group: Io.Group = .init;
        var permits: Io.Semaphore = .{ .permits = parallelism() };
        var failures: std.atomic.Value(u32) = .init(0);
        const window: Window = .{ .permits = &permits, .failures = &failures };
        var i: usize = 0;
        while (i < opts.count) : (i += 1) {
            const seed = prng.random().int(u64);
            var req_prng: std.Random.DefaultPrng = .init(seed);
            const base = buildRequestBase(&opts, &data, sku_index, req_prng.random(), init.io);
            permits.wait(init.io) catch |e| {
                dispatchFailed(&out, init.io, &group, e);
            };
            group.concurrent(init.io, sendRequestTask, .{ &client, base, seed, &window }) catch |e| {
                permits.post(init.io);
                dispatchFailed(&out, init.io, &group, e);
            };
        }
        group.await(init.io) catch |e| {
            out.eprint("request failed: {s}\n", .{@errorName(e)});
            std.process.exit(1);
        };
        exitOnFailures(&out, failures.load(.monotonic), opts.count);
    } else {
        // Reuse one connection for all requests (keep-alive), sent sequentially.
        const failures = sendRequestsReused(&client, sku_index, prng.random()) catch |e| {
            out.eprint("request failed: {s}\n", .{@errorName(e)});
            std.process.exit(1);
        };
        exitOnFailures(&out, failures, opts.count);
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "request syntax follows the reference first-packet policy" {
    const both: rpc.BindResult = .{ .has_ndr32 = true, .has_ndr64 = true };
    try std.testing.expect(!requestUseNdr64(both, true, true)); // first: NDR32
    try std.testing.expect(requestUseNdr64(both, false, true)); // later: NDR64

    // NDR32-only server: both requests go out as NDR32. This is the regression
    // that made `vlmzs` fail against `vlmzsd --no-ndr64` with NCA 0x1C010003.
    const ndr32_only: rpc.BindResult = .{ .has_ndr32 = true, .has_ndr64 = false };
    try std.testing.expect(!requestUseNdr64(ndr32_only, true, true));
    try std.testing.expect(!requestUseNdr64(ndr32_only, false, true));

    // NDR64-only server: the first request cannot be NDR32.
    const ndr64_only: rpc.BindResult = .{ .has_ndr32 = false, .has_ndr64 = true };
    try std.testing.expect(requestUseNdr64(ndr64_only, true, true));
    try std.testing.expect(requestUseNdr64(ndr64_only, false, true));

    // `--no-ndr64` on the client: NDR64 is never used, not even later on.
    try std.testing.expect(!requestUseNdr64(both, false, false));
}

test "buildRequestBase binding expiration" {
    const alloc = std.testing.allocator;
    var data = try kmsdata.parse(alloc, @embedFile("vlmcsd.kmd"));
    defer data.deinit(alloc);

    var prng: std.Random.DefaultPrng = .init(0);
    const rng = prng.random();

    var threaded: std.Io.Threaded = .init(alloc, .{});
    defer threaded.deinit();
    const io = threaded.io();

    // Default is 30 days (43200 minutes), matching the C `BindingExpiration`.
    const opts_default = ClientOptions{};
    const base_default = buildRequestBase(&opts_default, &data, 0, rng, io);
    try std.testing.expectEqual(@as(u32, 43200), base_default.binding_expiration);

    // An explicit `--grace` overrides it.
    var opts_custom = ClientOptions{};
    opts_custom.grace = 60;
    const base_custom = buildRequestBase(&opts_custom, &data, 0, rng, io);
    try std.testing.expectEqual(@as(u32, 60), base_custom.binding_expiration);
}

// The client's output staging is pinned here: one request must reach the sink as
// one contiguous block, because its fragments are mid-line (the "Sending
// activation request" prefix has no newline) and `--reconnect-per-request` runs
// requests in parallel. The sink is injectable for the same reason the server's
// logger is: `zig build test` runs this binary with `--listen=-`, so a test must
// never write to the real stdout (see AGENTS.md → Pitfalls).
test "a staged report reaches the sink as one block" {
    const io = std.testing.io;
    var unused_out: [64]u8 = undefined;
    var unused_err: [64]u8 = undefined;
    var output = Output.init(io, &unused_out, &unused_err);
    var sink_buffer: [256]u8 = undefined;
    var sink: std.Io.Writer = .fixed(&sink_buffer);
    output.test_out = &sink;
    var err_sink_buffer: [256]u8 = undefined;
    var err_sink: std.Io.Writer = .fixed(&err_sink_buffer);
    output.test_err = &err_sink;

    var report_out_buffer: [report_buffer_size]u8 = undefined;
    var report_err_buffer: [report_buffer_size]u8 = undefined;
    var report = Report.init(&output, &report_out_buffer, &report_err_buffer);
    report.print("BEGIN ", .{});
    report.print("middle ", .{});
    report.eprint("to-stderr\n", .{});
    report.print("END\n", .{});
    output.writeBlock(report.out.buffered(), report.err.buffered());

    try std.testing.expectEqualStrings("BEGIN middle END\n", sink.buffered());
    try std.testing.expectEqualStrings("to-stderr\n", err_sink.buffered());
}

test "concurrent requests do not interleave inside a report" {
    if (@import("builtin").single_threaded) return error.SkipZigTest;
    const alloc = std.testing.allocator;

    var threaded: std.Io.Threaded = .init(alloc, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var unused_out: [64]u8 = undefined;
    var unused_err: [64]u8 = undefined;
    var output = Output.init(io, &unused_out, &unused_err);
    var sink_buffer: [64 * 1024]u8 = undefined;
    var sink: std.Io.Writer = .fixed(&sink_buffer);
    output.test_out = &sink;

    const requests = 8;
    const Task = struct {
        output: *Output,
        id: usize,

        fn run(self: *@This()) void {
            var report_out_buffer: [report_buffer_size]u8 = undefined;
            var report_err_buffer: [report_buffer_size]u8 = undefined;
            var report = Report.init(self.output, &report_out_buffer, &report_err_buffer);
            report.print("<{d}", .{self.id});
            var i: usize = 0;
            while (i < 8) : (i += 1) report.print("-{d}", .{i});
            report.print(">\n", .{});
            self.output.writeBlock(report.out.buffered(), report.err.buffered());
        }
    };

    var group: Io.Group = .init;
    var tasks: [requests]Task = undefined;
    for (&tasks, 0..) |*task, id| {
        task.* = .{ .output = &output, .id = id };
        try group.concurrent(io, Task.run, .{task});
    }
    try group.await(io);

    // Each report must appear as one uninterrupted block: before staging, the
    // fragments of these parallel requests were spliced together.
    const text = sink.buffered();
    var found: usize = 0;
    var id: usize = 0;
    while (id < requests) : (id += 1) {
        var expected_buffer: [64]u8 = undefined;
        const expected = try std.fmt.bufPrint(&expected_buffer, "<{d}-0-1-2-3-4-5-6-7>\n", .{id});
        if (std.mem.indexOf(u8, text, expected) != null) found += 1;
    }
    try std.testing.expectEqual(requests, found);
}

// Pins the failure path: a request that dies on the wire returns after the
// prefix was staged, and the staged line must still be terminated — otherwise
// the caller's stderr diagnostic is written straight into the middle of that
// stdout line. Exercises the real `Session.exchange` with an at-EOF reader, which
// is what a peer that vanished mid-exchange looks like (see `expectError`).
test "a request that fails on the wire still emits a complete line" {
    const alloc = std.testing.allocator;
    var data = try kmsdata.parse(alloc, @embedFile("vlmcsd.kmd"));
    defer data.deinit(alloc);

    var threaded: std.Io.Threaded = .init(alloc, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var unused_out: [64]u8 = undefined;
    var unused_err: [64]u8 = undefined;
    var output = Output.init(io, &unused_out, &unused_err);
    var sink_buffer: [1024]u8 = undefined;
    var sink: std.Io.Writer = .fixed(&sink_buffer);
    output.test_out = &sink;

    const opts = ClientOptions{};
    var prng: std.Random.DefaultPrng = .init(0);
    const base = buildRequestBase(&opts, &data, 0, prng.random(), io);

    // The peer is already gone: the fixed reader is at EOF, and the request
    // goes out into a buffer that goes nowhere.
    var no_bytes: [0]u8 = .{};
    var reader: std.Io.Reader = .fixed(&no_bytes);
    var sent: [4096]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&sent);
    // Only `conn` is touched by a send, so the socket fields of the session stay
    // undefined here.
    var session: Session = .init(io);
    session.conn = .{
        .allocator = alloc,
        .packet_reader = .init(.{}, &reader, &.{}),
        .writer = &writer,
        .use_ndr64 = true,
        // No socket behind these buffers, so the timeout stays off.
    };
    // The exchange asks the negotiation outcome which syntax to use; with both
    // accepted and `first_packet` still set, it picks NDR32.
    session.bind = .{ .has_ndr32 = true, .has_ndr64 = true };
    const client: Client = .{ .gpa = alloc, .io = io, .opts = &opts, .out = &output, .data = &data };

    try std.testing.expectError(error.EndOfStream, session.exchange(&client, base, prng.random()));

    try std.testing.expectEqualStrings("Sending activation request (KMS V6) \n", sink.buffered());
}

// A peer that completes the TCP handshake and then says nothing is the failure
// mode `--timeout` exists for: without the deadline, the client blocks in
// `read(2)` forever. Uses the real `ClientSession.bind` against a listening socket
// nobody accepts from, so the timeout is exercised on the actual packet read.
test "--timeout bounds a peer that never answers" {
    const alloc = std.testing.allocator;

    var threaded: std.Io.Threaded = .init(alloc, .{});
    defer threaded.deinit();
    const io = threaded.io();

    // Port 0 → the kernel picks a free port, reported back in `socket.address`.
    const addr = try Io.net.IpAddress.parse("127.0.0.1", 0);
    var server = try Io.net.IpAddress.listen(&addr, io, .{ .mode = .stream });
    defer server.deinit(io);

    const stream = try Io.net.IpAddress.connect(&server.socket.address, io, .{ .mode = .stream });
    defer stream.close(io);

    var rbuf: [4096]u8 = undefined;
    var wbuf: [4096]u8 = undefined;
    var reader = Io.Reader.fixed("");
    var writer = stream.writer(io, &wbuf);

    // One second is the smallest `--timeout` (seconds are the unit), so this
    // test is as fast as the option itself allows.
    var session: network.ClientSession = .{
        .allocator = alloc,
        .packet_reader = .init(.{ .peer = .{
            .io = io,
            .handle = stream.socket.handle,
            .timeout = network.timeoutSeconds(1),
        } }, &reader, &rbuf),
        .writer = &writer.interface,
        .use_ndr64 = false,
    };
    try std.testing.expectError(error.Timeout, session.bind());
    _ = &wbuf;
}

test "incomplete KMS data is rejected by the client" {
    const alloc = std.testing.allocator;
    var data = try kmsdata.parse(alloc, @embedFile("vlmcsd.kmd"));
    defer data.deinit(alloc);

    try validateKmsData(&data);
    data.app_count = 0;
    try std.testing.expectError(error.IncompleteKmsData, validateKmsData(&data));
}

test "resolveOptions rejects out-of-range selections" {
    const gpa = std.testing.allocator;

    const Case = struct { args: []const []const u8, expected: anyerror };
    const cases = [_]Case{
        // `--protocol` selects the wire struct set; only 4/5/6 exist, and an
        // explicit `0` must not fall back to "derive from the product".
        .{ .args = &.{ "--protocol", "0" }, .expected = error.InvalidProtocol },
        .{ .args = &.{ "--protocol", "3" }, .expected = error.InvalidProtocol },
        .{ .args = &.{ "--protocol", "7" }, .expected = error.InvalidProtocol },
        .{ .args = &.{ "--license-status", "7" }, .expected = error.InvalidLicenseStatus },
        .{ .args = &.{ "127.0.0.1", "127.0.0.2" }, .expected = error.UnexpectedPositional },
    };
    for (cases) |case| {
        var res = try cli_helper.parse(gpa, &vlmzs_opts, case.args);
        defer res.deinit();
        var diag: cli_helper.Diag = .{};
        try std.testing.expectError(case.expected, resolveOptions(&res, &diag));
    }
}

test "resolveOptions accepts the documented selection limits" {
    const gpa = std.testing.allocator;

    const accepted = [_][]const u8{ "4", "5", "6" };
    for (accepted) |version| {
        var res = try cli_helper.parse(gpa, &vlmzs_opts, &.{ "--protocol", version });
        defer res.deinit();
        var diag: cli_helper.Diag = .{};
        const opts = try resolveOptions(&res, &diag);
        try std.testing.expectEqual(try std.fmt.parseInt(u16, version, 10), opts.protocol);
    }

    var res = try cli_helper.parse(gpa, &vlmzs_opts, &.{
        "--protocol", "6", "--license-status", "6", "127.0.0.1:1689",
    });
    defer res.deinit();
    var diag: cli_helper.Diag = .{};
    const opts = try resolveOptions(&res, &diag);
    try std.testing.expectEqual(@as(u32, 6), opts.license_status);
    try std.testing.expectEqual(@as(u16, 1689), opts.port);
}

test "GUID text parses to the serialized order and formats back" {
    // `--app-id`/`--kms-id`/`--cmid` are compared against `.kmd` GUIDs, which
    // are stored in serialized order (docs/migration.md §3.3). Parsing must
    // therefore reverse Data1..Data3, and `formatGuid` (what the request dump
    // prints) must undo it.
    const text = "51C82175-844E-4750-B0D8-EC255555BC06";
    const wire = try cli_helper.parseGuid(text);
    try std.testing.expectEqualSlices(u8, &.{
        0x75, 0x21, 0xc8, 0x51, 0x4e, 0x84, 0x50, 0x47,
        0xb0, 0xd8, 0xec, 0x25, 0x55, 0x55, 0xbc, 0x06,
    }, &wire);

    var buf: [64]u8 = undefined;
    try std.testing.expectEqualStrings(text, formatGuid(&wire, &buf));
}

test "the random CMID carries the version and variant bits" {
    var prng: std.Random.DefaultPrng = .init(0x5eed);
    const rng = prng.random();
    for (0..32) |_| {
        const cmid = randomCmid(rng);
        // Serialized order: the Data3 high byte is byte 7 and the variant bits
        // start the 8-byte tail at byte 8 (docs/migration.md §3.3).
        try std.testing.expectEqual(@as(u8, 0x4), cmid[7] >> 4);
        try std.testing.expectEqual(@as(u8, 0b10), cmid[8] >> 6);
    }
}

test "the answer line carries the HwId only for v6" {
    const io = std.testing.io;

    const printOne = struct {
        fn call(io_: Io, hwid: ?*const [8]u8, sink_buffer: []u8) []const u8 {
            var unused_out: [64]u8 = undefined;
            var unused_err: [64]u8 = undefined;
            var output = Output.init(io_, &unused_out, &unused_err);
            var sink: std.Io.Writer = .fixed(sink_buffer);
            output.test_out = &sink;

            var report_out_buffer: [report_buffer_size]u8 = undefined;
            var report_err_buffer: [report_buffer_size]u8 = undefined;
            var report = Report.init(&output, &report_out_buffer, &report_err_buffer);
            var base: kms.Response = std.mem.zeroes(kms.Response);
            printResultSummary(&base, hwid, &report);
            output.writeBlock(report.out.buffered(), report.err.buffered());
            return sink.buffered();
        }
    }.call;

    var v6_buffer: [128]u8 = undefined;
    const v6_line = printOne(io, &kms.default_hwid, &v6_buffer);
    try std.testing.expect(std.mem.indexOf(u8, v6_line, "(3A1C049600B60076)") != null);

    var v5_buffer: [128]u8 = undefined;
    const v5_line = printOne(io, null, &v5_buffer);
    try std.testing.expect(std.mem.indexOf(u8, v5_line, "(") == null);
}

test "a server that closes after each request is reconnected" {
    const alloc = std.testing.allocator;
    const io = std.testing.io;

    var data = try kmsdata.parse(alloc, @embedFile("vlmcsd.kmd"));
    defer data.deinit(alloc);

    // A real loopback server, so `sendRequestsReused` exercises its actual
    // socket path instead of a stub.
    const addr = try Io.net.IpAddress.parse("127.0.0.1", 0);
    var listener = try Io.net.IpAddress.listen(&addr, io, .{ .mode = .stream });
    defer listener.deinit(io);

    var cfg = kms.ServerConfig{ .data = &data };

    const Server = struct {
        fn nowUnix(context: ?*anyopaque) i64 {
            _ = context;
            return 1_700_000_000;
        }

        /// Serve every connection until the group is canceled. Each one answers
        /// BIND plus one request and then closes — the `--disconnect-per-request`
        /// shape the client has to reconnect through.
        fn run(
            io_: Io,
            listener_: *Io.net.Server,
            alloc_: Allocator,
            cfg_: *const kms.ServerConfig,
        ) void {
            var prng: std.Random.DefaultPrng = .init(0x9e37_79b9);
            while (true) {
                const stream = listener_.accept(io_) catch return;
                defer stream.close(io_);
                var rbuf: [4096]u8 = undefined;
                var wbuf: [4096]u8 = undefined;
                var reader = Io.Reader.fixed("");
                var writer = stream.writer(io_, &wbuf);
                var packet_reader: network.PacketReader = .init(.{ .peer = .{
                    .io = io_,
                    .handle = stream.socket.handle,
                    .timeout = network.timeoutSeconds(5),
                } }, &reader, &rbuf);
                _ = network.serveRpc(.{
                    .allocator = alloc_,
                    .packet_reader = &packet_reader,
                    .writer = &writer.interface,
                    .rng = prng.random(),
                }, .{
                    .cfg = cfg_,
                    .clock = .{ .now_unix = nowUnix },
                    .disconnect_per_request = true,
                }) catch {};
            }
        }
    };

    var group: Io.Group = .init;
    group.concurrent(io, Server.run, .{ io, &listener, alloc, &cfg }) catch |e| return e;
    defer group.cancel(io);

    var opts = ClientOptions{};
    opts.host = "127.0.0.1";
    opts.port = listener.socket.address.getPort();
    opts.count = 3;
    opts.timeout_seconds = default_timeout_seconds;

    var unused_out: [64]u8 = undefined;
    var unused_err: [64]u8 = undefined;
    var output = Output.init(io, &unused_out, &unused_err);
    var sink_buffer: [4096]u8 = undefined;
    var sink: std.Io.Writer = .fixed(&sink_buffer);
    output.test_out = &sink;

    var prng: std.Random.DefaultPrng = .init(0x1234_5678);
    const client: Client = .{ .gpa = alloc, .io = io, .opts = &opts, .out = &output, .data = &data };
    const failures = try sendRequestsReused(&client, 0, prng.random());

    // Every request activated, on its own connection: no failure, and one
    // answer line per request (the dropped attempt leaves no output behind).
    try std.testing.expectEqual(@as(u32, 0), failures);
    try std.testing.expectEqual(@as(usize, 3), std.mem.count(u8, sink.buffered(), "\n"));
}

test "the UTC timestamp uses the calendar month" {
    // `std.time.epoch.Month` is backed by its calendar number (jan = 1), so a
    // stray `+ 1` prints December for November.
    var buf: [32]u8 = undefined;
    try std.testing.expectEqualStrings("2026-11-07 13:57:17", formatUtc(1_794_059_837, &buf));
    try std.testing.expectEqualStrings("1970-01-01 00:00:00", formatUtc(0, &buf));
    try std.testing.expectEqualStrings("2024-02-29 00:00:00", formatUtc(1_709_164_800, &buf));
    try std.testing.expectEqualStrings("2038-01-19 03:14:07", formatUtc(std.math.maxInt(i32), &buf));
}

test "the workstation name is UTF-16, not raw UTF-8 bytes" {
    const gpa = std.testing.allocator;
    var data = try kmsdata.parse(gpa, @embedFile("vlmcsd.kmd"));
    defer data.deinit(gpa);

    var prng: std.Random.DefaultPrng = .init(0xabc);
    const rng = prng.random();
    var out_buf: [8192]u8 = undefined;
    var err_buf: [64]u8 = undefined;
    var output = Output.init(std.testing.io, &out_buf, &err_buf);

    // ASCII: one code unit per byte.
    {
        var opts = ClientOptions{};
        opts.workstation = "wks-01";
        const base = buildRequestBase(&opts, &data, 0, rng, std.testing.io);
        try std.testing.expectEqual(@as(u16, 'w'), base.workstation_name[0]);
        try std.testing.expectEqual(@as(u16, 0), base.workstation_name[6]);
    }

    // BMP text: two bytes in UTF-8 ("中") become one code unit.
    {
        var opts = ClientOptions{};
        opts.workstation = "中文";
        const base = buildRequestBase(&opts, &data, 0, rng, std.testing.io);
        try std.testing.expectEqual(@as(u16, 0x4E2D), base.workstation_name[0]);
        try std.testing.expectEqual(@as(u16, 0x6587), base.workstation_name[1]);
        try std.testing.expectEqual(@as(u16, 0), base.workstation_name[2]);

        // ... and the verbose dump prints it back as UTF-8.
        var report_out: [4096]u8 = undefined;
        var report_err: [64]u8 = undefined;
        var report = Report.init(&output, &report_out, &report_err);
        printRequestVerbose(&base, &data, &report);
        try std.testing.expect(std.mem.indexOf(u8, report.out.buffered(), "Workstation name                : 中文") != null);
    }

    // Astral text: one code point, two UTF-16 code units.
    {
        var opts = ClientOptions{};
        opts.workstation = "𐐷";
        const base = buildRequestBase(&opts, &data, 0, rng, std.testing.io);
        try std.testing.expectEqual(@as(u16, 0xD801), base.workstation_name[0]);
        try std.testing.expectEqual(@as(u16, 0xDC37), base.workstation_name[1]);
        try std.testing.expectEqual(@as(u16, 0), base.workstation_name[2]);
    }

    // Truncation keeps whole code points: 40 astral characters are 80 units,
    // but the field holds 63 plus the terminator.
    {
        var name_buffer: [40 * 4]u8 = undefined;
        var len: usize = 0;
        for (0..40) |_| {
            @memcpy(name_buffer[len..][0..4], "𐐷");
            len += 4;
        }
        var opts = ClientOptions{};
        opts.workstation = name_buffer[0..len];
        const base = buildRequestBase(&opts, &data, 0, rng, std.testing.io);
        try std.testing.expectEqual(@as(u16, 0xD801), base.workstation_name[60]);
        try std.testing.expectEqual(@as(u16, 0xDC37), base.workstation_name[61]);
        try std.testing.expectEqual(@as(u16, 0), base.workstation_name[62]);
    }
}

test "a bad option value names the option it came from" {
    const gpa = std.testing.allocator;
    const Case = struct {
        args: []const []const u8,
        expected: anyerror,
        spelling: []const u8,
        value: []const u8,
    };
    const cases = [_]Case{
        .{ .args = &.{ "--count", "abc" }, .expected = error.InvalidCharacter, .spelling = "--count", .value = "abc" },
        .{ .args = &.{ "--grace", "-1" }, .expected = error.Overflow, .spelling = "--grace", .value = "-1" },
        .{ .args = &.{ "--cmid", "zz" }, .expected = error.InvalidGuid, .spelling = "--cmid", .value = "zz" },
        .{ .args = &.{ "--timeout", "9q" }, .expected = error.InvalidDuration, .spelling = "--timeout", .value = "9q" },
    };
    for (cases) |case| {
        var res = try cli_helper.parse(gpa, &vlmzs_opts, case.args);
        defer res.deinit();
        var diag: cli_helper.Diag = .{};
        try std.testing.expectError(case.expected, resolveOptions(&res, &diag));
        try std.testing.expectEqualStrings(case.spelling, diag.spelling);
        try std.testing.expectEqualStrings(case.value, diag.value);
    }
}

test "an invalid UTF-8 workstation name is a configuration error" {
    const gpa = std.testing.allocator;
    var res = try cli_helper.parse(gpa, &vlmzs_opts, &.{ "--workstation", "\xff\xfe" });
    defer res.deinit();
    var diag: cli_helper.Diag = .{};
    try std.testing.expectError(error.InvalidWorkstation, resolveOptions(&res, &diag));
}

test "a timestamp before the Unix epoch prints as the epoch" {
    // `formatUtc` takes a FILETIME-derived second count, which a response can
    // put before 1970; the narrowing cast must not trap.
    var buf: [32]u8 = undefined;
    try std.testing.expectEqualStrings("1970-01-01 00:00:00", formatUtc(-1, &buf));
    try std.testing.expectEqualStrings("1970-01-01 00:00:00", formatUtc(-11_644_473_600, &buf));
}

test "the transfer syntax follows the first-packet rule" {
    // The reference client sends the first request after BIND as NDR32 whenever
    // the server accepted both syntaxes; later ones use NDR64 when available.
    const both: rpc.BindResult = .{ .has_ndr32 = true, .has_ndr64 = true };
    const ndr64_only: rpc.BindResult = .{ .has_ndr64 = true };
    const ndr32_only: rpc.BindResult = .{ .has_ndr32 = true };

    try std.testing.expect(!requestUseNdr64(both, true, true));
    try std.testing.expect(requestUseNdr64(both, false, true));
    try std.testing.expect(requestUseNdr64(ndr64_only, true, true));
    try std.testing.expect(requestUseNdr64(ndr64_only, false, true));
    try std.testing.expect(!requestUseNdr64(ndr32_only, true, true));
    try std.testing.expect(!requestUseNdr64(ndr32_only, false, true));

    // `--no-ndr64` wins over whatever the server accepted.
    try std.testing.expect(!requestUseNdr64(both, true, false));
    try std.testing.expect(!requestUseNdr64(both, false, false));
    try std.testing.expect(!requestUseNdr64(ndr64_only, false, false));
}

test "a closed connection is resendable only when the owner will reopen it" {
    var session: Session = .init(std.testing.io);
    session.retry_on_close = true;
    try std.testing.expect(session.willRetry(error.EndOfStream));
    try std.testing.expect(session.willRetry(error.ConnectionResetByPeer));
    try std.testing.expect(session.willRetry(error.SocketUnconnected));
    // A negotiation failure is not a closed socket: resending would repeat it.
    try std.testing.expect(!session.willRetry(error.NoTransferSyntax));

    // A one-shot connection has nothing to resend, so its report is kept.
    session.retry_on_close = false;
    try std.testing.expect(!session.willRetry(error.EndOfStream));
}

test "the dispatch window admits at least one request" {
    // Zero would park the dispatcher on a semaphore nothing can post.
    try std.testing.expect(parallelism() >= 1);
}

test "a report with nothing staged writes nothing" {
    var out_buf: [64]u8 = undefined;
    var err_buf: [64]u8 = undefined;
    var output = Output.init(std.testing.io, &out_buf, &err_buf);
    var out_sink: [64]u8 = undefined;
    var err_sink: [64]u8 = undefined;
    var out_writer: std.Io.Writer = .fixed(&out_sink);
    var err_writer: std.Io.Writer = .fixed(&err_sink);
    output.test_out = &out_writer;
    output.test_err = &err_writer;

    output.writeBlock(&.{}, &.{});
    try std.testing.expectEqual(@as(usize, 0), out_writer.buffered().len);
    try std.testing.expectEqual(@as(usize, 0), err_writer.buffered().len);

    // Only the stream that has text is written.
    output.writeBlock("answer", &.{});
    try std.testing.expectEqualStrings("answer", out_writer.buffered());
    try std.testing.expectEqual(@as(usize, 0), err_writer.buffered().len);
}

test "the HOST[:PORT] positional splits at one colon" {
    {
        const hp = try parseHostPort("127.0.0.1:1688");
        try std.testing.expectEqualStrings("127.0.0.1", hp.host);
        try std.testing.expectEqual(@as(u16, 1688), hp.port);
    }
    {
        const hp = try parseHostPort("kms.example");
        try std.testing.expectEqualStrings("kms.example", hp.host);
        try std.testing.expectEqual(default_port, hp.port);
    }
    {
        // IPv6 with an explicit port needs the bracket form.
        const hp = try parseHostPort("[::1]:1688");
        try std.testing.expectEqualStrings("::1", hp.host);
        try std.testing.expectEqual(@as(u16, 1688), hp.port);
    }
    {
        // A bare IPv6 literal has several colons, so it is host-only.
        const hp = try parseHostPort("::1");
        try std.testing.expectEqualStrings("::1", hp.host);
        try std.testing.expectEqual(default_port, hp.port);
    }

    try std.testing.expectError(error.InvalidHost, parseHostPort("[::1"));
    try std.testing.expectError(error.InvalidCharacter, parseHostPort("host:port"));
}
