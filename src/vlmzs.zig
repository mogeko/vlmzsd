//! `vlmzs` — the KMS activation client binary (for testing).
//!
//! Implements the `vlmzs` CLI surface from `docs/cli.md`: sends one or more
//! activation requests to an existing KMS server and prints the result.

const std = @import("std");
const clap = @import("clap");
const vlmzsd = @import("vlmzsd");
const cli_helper = vlmzsd.cli_helper;

const kms = vlmzsd.kms;
const kmsdata = vlmzsd.kmsdata;
const network = vlmzsd.network;

const Io = std.Io;
const Allocator = std.mem.Allocator;

const build_options = @import("build_options");
const version = build_options.version;
const default_port: u16 = 1688;
const default_grace_minutes: u32 = 43200;
const embedded_kmd: []const u8 = @embedFile("vlmcsd.kmd");

/// Bare stdout/stderr writers for the client. The client is a CLI debugging
/// tool, not a service: its answer (ePID) and `--verbose` protocol dumps go to
/// stdout, errors go to stderr — no timestamp, no level, matching the C
/// `vlmcs` client (`printf`/`errorout`). The server-side `cli_helper.Logger`
/// is deliberately not used here.
const Output = struct {
    io: Io,
    out: std.Io.File.Writer,
    err: std.Io.File.Writer,
    /// Guards concurrent `print`/`eprint` calls (the client dispatches
    /// `--reconnect-per-request` tasks in parallel onto the thread pool).
    mutex: Io.Mutex = .init,

    fn init(io: Io, out_buf: []u8, err_buf: []u8) Output {
        return .{
            .io = io,
            .out = std.Io.File.writer(std.Io.File.stdout(), io, out_buf),
            .err = std.Io.File.writer(std.Io.File.stderr(), io, err_buf),
        };
    }

    /// Write to stdout and flush (the answer/progress stream).
    fn print(self: *Output, comptime fmt: []const u8, args: anytype) void {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        self.out.interface.print(fmt, args) catch {};
        self.out.interface.flush() catch {};
    }

    /// Write to stderr and flush (the error stream).
    fn eprint(self: *Output, comptime fmt: []const u8, args: anytype) void {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        self.err.interface.print(fmt, args) catch {};
        self.err.interface.flush() catch {};
    }
};

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

/// Format a Unix timestamp as UTC `YYYY-MM-DD HH:MM:SS` (C verbose dumps use
/// `strftime("%Y-%m-%d %X", gmtime(...))`).
fn formatUtc(unix: i64, buf: []u8) []const u8 {
    const secs: u64 = @intCast(unix);
    const epoch = std.time.epoch.EpochSeconds{ .secs = secs };
    const yad = epoch.getEpochDay().calculateYearDay();
    const mad = yad.calculateMonthDay();
    const day_secs: u64 = secs % 86400;
    return std.fmt.bufPrint(buf, "{d:0>4}-{d:0>2}-{d:0>2} {d:0>2}:{d:0>2}:{d:0>2}", .{
        @as(u32, yad.year),
        @as(u32, @intFromEnum(mad.month)) + 1,
        @as(u32, mad.day_index) + 1,
        @as(u32, @intCast(day_secs / 3600)),
        @as(u32, @intCast((day_secs % 3600) / 60)),
        @as(u32, @intCast(day_secs % 60)),
    }) catch unreachable;
}

const params = clap.parseParamsComptime(
    \\-h, --help                  Display this help and exit.
    \\-V, --version               Output version information and exit.
    \\    --product <str>         Product name or number (default: first SKU).
    \\    --protocol <u16>        KMS protocol version 4/5/6.
    \\    --app-id <str>          Override AppID (GUID).
    \\    --sku-id <str>          Override SKUID (GUID).
    \\    --kms-id <str>          Override KMSID (GUID).
    \\-c, --cmid <str>            Client machine ID (GUID, default random).
    \\-o, --prev-cmid <str>       Previous client machine ID (GUID).
    \\-w, --workstation <str>     Workstation name.
    \\-m, --vm                    Present as a virtual machine.
    \\-n, --count <u32>           Number of requests (default 1).
    \\-r, --virtual-clients <u32> NCountPolicy override.
    \\-g, --grace <u32>           Grace period minutes.
    \\    --address-family <u8>   IPv4/IPv6 selection (4/6).
    \\-x, --list-products         Print available products and exit.
    \\-t, --license-status <u32>  LicenseStatus field (0-6, default 1).
    \\-T, --reconnect-per-request Reconnect for each request.
    \\    --no-multiplexed        Disable multiplexed RPC (default on).
    \\    --no-ndr64              Disable NDR64 (default on).
    \\    --no-btfn               Disable bind-time feature negotiation (default on).
    \\-v, --verbose               Verbose logging.
    \\<str>                       KMS server host[:port].
    \\
);

const ClientOptions = struct {
    host: ?[]const u8 = null,
    port: u16 = default_port,
    product: ?[]const u8 = null,
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
    multiplexed: bool = true,
    ndr64: bool = true,
    btfn: bool = true,
    verbose: bool = false,
};

fn parseHostPort(host_arg: []const u8) !struct { host: []const u8, port: u16 } {
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

fn resolveOptions(args: anytype, positionals: anytype, out: *Output) !ClientOptions {
    // zig-clap names hyphenated long options verbatim; access via @field.
    const virtual_clients = @field(args, "virtual-clients");
    const license_status = @field(args, "license-status");
    const address_family = @field(args, "address-family");
    const prev_cmid = @field(args, "prev-cmid");
    const list_products = @field(args, "list-products");
    const reconnect_per_request = @field(args, "reconnect-per-request");
    const no_multiplexed = @field(args, "no-multiplexed");
    const no_ndr64 = @field(args, "no-ndr64");
    const no_btfn = @field(args, "no-btfn");
    const app_id = @field(args, "app-id");
    const sku_id = @field(args, "sku-id");
    const kms_id = @field(args, "kms-id");

    const host_arg = positionals[0];

    var opts = ClientOptions{};
    if (host_arg) |ha| {
        const hp = try parseHostPort(ha);
        opts.host = hp.host;
        opts.port = hp.port;
    }
    opts.product = args.product;
    opts.protocol = args.protocol orelse 0;
    if (app_id) |s| opts.app_id = try cli_helper.parseGuid(s);
    if (sku_id) |s| opts.sku_id = try cli_helper.parseGuid(s);
    if (kms_id) |s| opts.kms_id = try cli_helper.parseGuid(s);
    if (args.cmid) |s| opts.cmid = try cli_helper.parseGuid(s);
    if (prev_cmid) |s| opts.prev_cmid = try cli_helper.parseGuid(s);
    opts.workstation = args.workstation;
    opts.vm = args.vm != 0;
    opts.count = args.count orelse 1;
    opts.virtual_clients = virtual_clients orelse 0;
    opts.grace = args.grace orelse default_grace_minutes;
    opts.address_family = address_family orelse 0;
    if (opts.address_family != 0 and opts.address_family != 4 and opts.address_family != 6) {
        out.eprint("error: --address-family must be 4 or 6\n", .{});
        return error.InvalidAddressFamily;
    }
    opts.list_products = list_products != 0;
    opts.license_status = license_status orelse 1;
    opts.reconnect_per_request = reconnect_per_request != 0;
    opts.multiplexed = no_multiplexed == 0;
    opts.ndr64 = no_ndr64 == 0;
    opts.btfn = no_btfn == 0;
    opts.verbose = args.verbose != 0;

    return opts;
}

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

fn randomCmid(rng: std.Random) [16]u8 {
    var g: [16]u8 = undefined;
    rng.bytes(&g);
    g[6] = (g[6] & 0x0F) | 0x40; // UUID version 4
    g[8] = (g[8] & 0x3F) | 0x80; // RFC 4122 variant
    return g;
}

fn setWorkstationName(base: *kms.Request, name: ?[]const u8, rng: std.Random) void {
    if (name) |n| {
        var i: usize = 0;
        while (i < n.len and i < 63) : (i += 1) base.workstation_name[i] = n[i];
        base.workstation_name[i] = 0;
    } else {
        const len: usize = 1 + rng.uintLessThan(u8, 14);
        for (0..len) |i| base.workstation_name[i] = 'A' + rng.uintLessThan(u8, 26);
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

fn ucs2ToAscii(pid: *const [64]u16, out: []u8) []const u8 {
    var i: usize = 0;
    while (i < pid.len and pid[i] != 0 and i < out.len) : (i += 1) {
        out[i] = @truncate(pid[i]);
    }
    return out[0..i];
}

/// Report each failed response-verification check to stderr (C `displayResponse`).
fn reportVerificationErrors(result: kms.ResponseResult, out: *Output) void {
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
fn printRejection(status: i32, out: *Output) void {
    out.print("\n", .{}); // end the in-progress "Sending ..." line on stdout
    const hr: u32 = @bitCast(status);
    if (rejectionReason(hr)) |reason| {
        out.eprint("Error 0x{X:0>8}: {s}\n", .{ hr, reason });
    } else {
        out.eprint("Error 0x{X:0>8}\n", .{hr});
    }
}

/// Print the activation answer to stdout (C `displayResponse`, non-verbose).
/// `hwid` is only present for v5+ responses.
fn printResultSummary(base: *const kms.Response, hwid: ?*const [8]u8, out: *Output) void {
    var epid_buf: [64]u8 = undefined;
    const epid = ucs2ToAscii(&base.kms_pid, &epid_buf);
    out.print(" -> {s}", .{epid});
    if (hwid) |h| out.print(" ({X:0>16})", .{std.mem.readInt(u64, h, .big)});
    out.print("\n", .{});
}

/// One aligned GUID line with the product name when the GUID is in `list`.
fn printGuidLine(out: *Output, label: []const u8, guid: *const kms.Guid, list: []const kmsdata.VlmcsdData, buf: []u8) void {
    if (kms.getProductIndex(guid, list)) |idx| {
        out.print("{s:<32}: {s} ({s})\n", .{ label, formatGuid(guid, buf), list[idx].name });
    } else {
        out.print("{s:<32}: {s}\n", .{ label, formatGuid(guid, buf) });
    }
}

/// Verbose per-field request dump (C `logRequestVerbose`).
fn printRequestVerbose(req: *const kms.Request, data: *const kmsdata.KmsData, out: *Output) void {
    const major: u16 = @truncate(req.version >> 16);
    const minor: u16 = @truncate(req.version);
    var guid_buf: [64]u8 = undefined;
    var time_buf: [64]u8 = undefined;
    var ws_buf: [64]u8 = undefined;

    out.print("\nRequest Parameters\n==================\n\n", .{});
    out.print("Protocol version                : {d}.{d}\n", .{ major, minor });
    out.print("Client is a virtual machine     : {s}\n", .{if (req.vm_info != 0) "Yes" else "No"});
    out.print("Licensing status                : {d} ({s})\n", .{ req.license_status, licenseStatusText(req.license_status) });
    out.print("Remaining time (0 = forever)    : {d} minutes\n", .{req.binding_expiration});
    printGuidLine(out, "Application ID", &req.app_id, data.apps(), &guid_buf);
    printGuidLine(out, "SKU ID (aka Activation ID)", &req.act_id, data.skus(), &guid_buf);
    printGuidLine(out, "KMS ID (aka KMS counted ID)", &req.kms_id, data.kms(), &guid_buf);
    out.print("Client machine ID               : {s}\n", .{formatGuid(&req.cmid, &guid_buf)});
    out.print("Previous client machine ID      : {s}\n", .{formatGuid(&req.cmid_prev, &guid_buf)});
    out.print("Client request timestamp (UTC)  : {s}\n", .{formatUtc(kms.fileTimeToUnixTime(kms.fileTimeToU64(req.client_time)), &time_buf)});
    out.print("Workstation name                : {s}\n", .{ucs2ToAscii(&req.workstation_name, &ws_buf)});
    out.print("N count policy (minimum clients): {d}\n", .{req.n_policy});
    out.print("\n", .{});
}

/// Verbose per-field response dump (C `logResponseVerbose`).
fn printResponseVerbose(base: *const kms.Response, hwid: ?*const [8]u8, result: kms.ResponseResult, out: *Output) void {
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

fn sendRequest(
    gpa: Allocator,
    io: Io,
    opts: *const ClientOptions,
    base: kms.Request,
    rng: std.Random,
    out: *Output,
    data: *const kmsdata.KmsData,
) !void {
    var stream = try network.connect(io, opts.host.?, opts.port, opts.address_family);
    defer stream.close(io);

    var rbuf: [4096]u8 = undefined;
    var wbuf: [4096]u8 = undefined;
    var reader = stream.reader(io, &rbuf);
    var writer = stream.writer(io, &wbuf);

    var call_id: u32 = 2;
    const bind = try network.clientBind(gpa, &reader.interface, &writer.interface, &call_id, .{
        .use_ndr64 = opts.ndr64,
        .use_btfn = opts.btfn,
        .multiplexed = opts.multiplexed,
    });

    const use_ndr64 = if (opts.ndr64 and bind.has_ndr64) true else bind.has_ndr32;

    try sendRequestOn(gpa, &reader.interface, &writer.interface, &call_id, use_ndr64, base, rng, out, data, opts.verbose);
}

/// Send one KMS request over an already-established connection (BIND done).
fn sendRequestOn(
    gpa: Allocator,
    reader: *std.Io.Reader,
    writer: *std.Io.Writer,
    call_id: *u32,
    use_ndr64: bool,
    base: kms.Request,
    rng: std.Random,
    out: *Output,
    data: *const kmsdata.KmsData,
    verbose: bool,
) !void {
    const proto: u16 = @intCast(base.version >> 16);
    if (verbose) printRequestVerbose(&base, data, out);
    out.print("Sending activation request (KMS V{d}) ", .{proto});

    if (proto == 4) {
        var req: kms.RequestV4 = undefined;
        kms.createRequestV4(&req, &base);
        const sent = try network.clientSendRequest(gpa, reader, writer, call_id, std.mem.asBytes(&req), use_ndr64);
        defer gpa.free(sent.data);
        if (sent.status != 0) {
            printRejection(sent.status, out);
            return;
        }
        var resp: kms.ResponseV4 = undefined;
        const result = kms.decryptResponseV4(&resp, sent.data.len, sent.data, &req);
        if (!result.ok()) {
            reportVerificationErrors(result, out);
            return;
        }
        if (verbose) printResponseVerbose(&resp.base, null, result, out) else printResultSummary(&resp.base, null, out);
    } else {
        var req: kms.RequestV6 = undefined;
        kms.createRequestV6(&req, &base, rng);
        const sent = try network.clientSendRequest(gpa, reader, writer, call_id, std.mem.asBytes(&req), use_ndr64);
        defer gpa.free(sent.data);
        if (sent.status != 0) {
            printRejection(sent.status, out);
            return;
        }
        var resp: kms.ResponseV6 = undefined;
        const result = kms.decryptResponseV6(&resp, sent.data.len, sent.data, &req, null);
        if (!result.ok()) {
            reportVerificationErrors(result, out);
            return;
        }
        if (verbose) printResponseVerbose(&resp.base, &resp.hwid, result, out) else printResultSummary(&resp.base, &resp.hwid, out);
    }
}

/// One activation request dispatched as a pooled task (via `Group.concurrent`).
/// Derives its own PRNG from `seed` so concurrent requests never share PRNG
/// state; failures are reported here rather than propagated.
fn sendRequestTask(
    gpa: Allocator,
    io: Io,
    opts: *const ClientOptions,
    base: kms.Request,
    seed: u64,
    out: *Output,
    data: *const kmsdata.KmsData,
) void {
    var prng = std.Random.DefaultPrng.init(seed);
    sendRequest(gpa, io, opts, base, prng.random(), out, data) catch |e| {
        out.eprint("request failed: {s}\n", .{@errorName(e)});
    };
}

/// Send `--count` requests over a single reused connection (keep-alive).
/// Requests are sequential because one connection carries one in-flight RPC.
fn sendRequestsReused(
    gpa: Allocator,
    io: Io,
    opts: *const ClientOptions,
    data: *const kmsdata.KmsData,
    sku_index: usize,
    rng: std.Random,
    out: *Output,
) !void {
    var stream = try network.connect(io, opts.host.?, opts.port, opts.address_family);
    defer stream.close(io);

    var rbuf: [4096]u8 = undefined;
    var wbuf: [4096]u8 = undefined;
    var reader = stream.reader(io, &rbuf);
    var writer = stream.writer(io, &wbuf);

    var call_id: u32 = 2;
    const bind = try network.clientBind(gpa, &reader.interface, &writer.interface, &call_id, .{
        .use_ndr64 = opts.ndr64,
        .use_btfn = opts.btfn,
        .multiplexed = opts.multiplexed,
    });

    const use_ndr64 = if (opts.ndr64 and bind.has_ndr64) true else bind.has_ndr32;

    var i: usize = 0;
    while (i < opts.count) : (i += 1) {
        const base = buildRequestBase(opts, data, sku_index, rng, io);
        try sendRequestOn(gpa, &reader.interface, &writer.interface, &call_id, use_ndr64, base, rng, out, data, opts.verbose);
    }
}

fn listProducts(data: *const kmsdata.KmsData, out: *Output) void {
    out.print("You may use these product names or numbers:\n", .{});
    for (data.skus(), 0..) |sku, i| {
        out.print("{d:>3} = {s}\n", .{ i + 1, sku.name });
    }
}

pub fn main(init: std.process.Init) !void {
    var diag = clap.Diagnostic{};
    var res = clap.parse(clap.Help, &params, clap.parsers.default, init.minimal.args, .{
        .diagnostic = &diag,
        .allocator = init.gpa,
    }) catch |err| {
        try diag.reportToFile(init.io, .stderr(), err);
        return err;
    };
    defer res.deinit();

    if (res.args.help != 0) {
        try clap.helpToFile(init.io, .stderr(), clap.Help, &params, .{});
        return;
    }
    if (res.args.version != 0) {
        var buf: [64]u8 = undefined;
        var fw = std.Io.File.writer(std.Io.File.stdout(), init.io, &buf);
        try fw.interface.print("vlmzs {s}\n", .{version});
        try fw.interface.flush();
        return;
    }

    var out_buf: [4096]u8 = undefined;
    var err_buf: [4096]u8 = undefined;
    var out = Output.init(init.io, &out_buf, &err_buf);

    var opts = try resolveOptions(&res.args, res.positionals, &out);

    var data = try kmsdata.parse(init.gpa, embedded_kmd);
    defer data.deinit(init.gpa);

    if (opts.list_products) {
        listProducts(&data, &out);
        return;
    }

    if (opts.host == null) {
        // Default host (mirrors the C `useDefaultHost`): "::1" for IPv6-only,
        // otherwise "127.0.0.1".
        opts.host = if (opts.address_family == 6) "::1" else "127.0.0.1";
    }

    const sku_index = findSku(&data, opts.product) catch |e| {
        out.eprint("error: invalid product selector\n", .{});
        return e;
    };

    var prng = std.Random.DefaultPrng.init(cli_helper.makeSeed(init.io));

    if (opts.reconnect_per_request) {
        // Each request gets its own connection; dispatch them in parallel onto
        // the Io.Threaded pool. Each request builds its base and derives its own
        // PRNG before submission, so concurrent tasks never share PRNG state.
        var group = Io.Group.init;
        var i: usize = 0;
        while (i < opts.count) : (i += 1) {
            const seed = prng.random().int(u64);
            var req_prng = std.Random.DefaultPrng.init(seed);
            const base = buildRequestBase(&opts, &data, sku_index, req_prng.random(), init.io);
            group.concurrent(init.io, sendRequestTask, .{
                init.gpa, init.io, &opts, base, seed, &out, &data,
            }) catch |e| {
                out.eprint("failed to dispatch request: {s}\n", .{@errorName(e)});
                return e;
            };
        }
        try group.await(init.io);
    } else {
        // Reuse one connection for all requests (keep-alive), sent sequentially.
        sendRequestsReused(init.gpa, init.io, &opts, &data, sku_index, prng.random(), &out) catch |e| {
            out.eprint("request failed: {s}\n", .{@errorName(e)});
            return e;
        };
    }
}

test "buildRequestBase binding expiration" {
    const alloc = std.testing.allocator;
    var data = try kmsdata.parse(alloc, embedded_kmd);
    defer data.deinit(alloc);

    var prng = std.Random.DefaultPrng.init(0);
    const rng = prng.random();

    var threaded = std.Io.Threaded.init(alloc, .{});
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
