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

fn resolveOptions(args: anytype, positionals: anytype, log: *cli_helper.Logger) !ClientOptions {
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
        log.err("--address-family must be 4 or 6", .{});
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

fn printResponse(result: kms.ResponseResult, base: *const kms.Response, log: *cli_helper.Logger) void {
    if (!result.ok()) {
        log.err("response verification failed", .{});
        return;
    }
    var epid_buf: [64]u8 = undefined;
    const epid = ucs2ToAscii(&base.kms_pid, &epid_buf);
    log.info("ePID: {s}", .{epid});
    log.info("count: {d}  activation interval: {d} min  renewal interval: {d} min", .{
        base.count, base.vl_activation_interval, base.vl_renewal_interval,
    });
}

fn sendRequest(
    gpa: Allocator,
    io: Io,
    opts: *const ClientOptions,
    base: kms.Request,
    rng: std.Random,
    log: *cli_helper.Logger,
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

    try sendRequestOn(gpa, &reader.interface, &writer.interface, &call_id, use_ndr64, base, rng, log);
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
    log: *cli_helper.Logger,
) !void {
    const proto: u16 = @intCast(base.version >> 16);
    if (proto == 4) {
        var req: kms.RequestV4 = undefined;
        kms.createRequestV4(&req, &base);
        const sent = try network.clientSendRequest(gpa, reader, writer, call_id, std.mem.asBytes(&req), use_ndr64);
        defer gpa.free(sent.data);
        if (sent.status != 0) {
            log.err("server rejected request (status 0x{X:0>8})", .{@as(u32, @bitCast(sent.status))});
            return;
        }
        var resp: kms.ResponseV4 = undefined;
        const result = kms.decryptResponseV4(&resp, sent.data.len, sent.data, &req);
        printResponse(result, &resp.base, log);
    } else {
        var req: kms.RequestV6 = undefined;
        kms.createRequestV6(&req, &base, rng);
        const sent = try network.clientSendRequest(gpa, reader, writer, call_id, std.mem.asBytes(&req), use_ndr64);
        defer gpa.free(sent.data);
        if (sent.status != 0) {
            log.err("server rejected request (status 0x{X:0>8})", .{@as(u32, @bitCast(sent.status))});
            return;
        }
        var resp: kms.ResponseV6 = undefined;
        const result = kms.decryptResponseV6(&resp, sent.data.len, sent.data, &req, null);
        printResponse(result, &resp.base, log);
    }
}

/// One activation request dispatched as a pooled task (via `Group.concurrent`).
/// Derives its own PRNG from `seed` so concurrent requests never share PRNG
/// state; failures are logged here rather than propagated.
fn sendRequestTask(
    gpa: Allocator,
    io: Io,
    opts: *const ClientOptions,
    base: kms.Request,
    seed: u64,
    log: *cli_helper.Logger,
) void {
    var prng = std.Random.DefaultPrng.init(seed);
    sendRequest(gpa, io, opts, base, prng.random(), log) catch |e| {
        log.err("request failed: {s}", .{@errorName(e)});
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
    log: *cli_helper.Logger,
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
        try sendRequestOn(gpa, &reader.interface, &writer.interface, &call_id, use_ndr64, base, rng, log);
    }
}

fn listProducts(data: *const kmsdata.KmsData, log: *cli_helper.Logger) void {
    log.info("You may use these product names or numbers:", .{});
    for (data.skus(), 0..) |sku, i| {
        log.info("{d:>3} = {s}", .{ i + 1, sku.name });
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
    var log = cli_helper.Logger.init(init.io, &out_buf, &err_buf);

    var opts = try resolveOptions(&res.args, res.positionals, &log);
    if (opts.verbose) log.min_level = .debug;

    var data = try kmsdata.parse(init.gpa, embedded_kmd);
    defer data.deinit(init.gpa);

    if (opts.list_products) {
        listProducts(&data, &log);
        return;
    }

    if (opts.host == null) {
        // Default host (mirrors the C `useDefaultHost`): "::1" for IPv6-only,
        // otherwise "127.0.0.1".
        opts.host = if (opts.address_family == 6) "::1" else "127.0.0.1";
    }

    const sku_index = findSku(&data, opts.product) catch |e| {
        log.err("invalid product selector", .{});
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
                init.gpa, init.io, &opts, base, seed, &log,
            }) catch |e| {
                log.err("failed to dispatch request: {s}", .{@errorName(e)});
                return e;
            };
        }
        try group.await(init.io);
    } else {
        // Reuse one connection for all requests (keep-alive), sent sequentially.
        sendRequestsReused(init.gpa, init.io, &opts, &data, sku_index, prng.random(), &log) catch |e| {
            log.err("request failed: {s}", .{@errorName(e)});
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
