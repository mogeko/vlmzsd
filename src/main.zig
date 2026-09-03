//! `vlmzsd` — the KMS server binary (Phase 6).
//!
//! Implements the `vlmzsd` CLI surface from `docs/cli.md`: no config file,
//! three-tier precedence (default < `VLMZSD_*` env var < CLI flag), fixed-format
//! stdout logging, and a foreground accept/serve loop over `network.serveRpc`.

const std = @import("std");
const clap = @import("clap");
const vlmzsd = @import("vlmzsd");
const cli_helper = vlmzsd.cli_helper;

const kms = vlmzsd.kms;
const kmsdata = vlmzsd.kmsdata;
const network = vlmzsd.network;

const Allocator = std.mem.Allocator;
const Io = std.Io;
const EnvironMap = std.process.Environ.Map;

const build_options = @import("build_options");
const version = build_options.version;
const default_port: u16 = 1688;

/// Embedded default `.kmd` data (mirrors `reference/vlmcsd.kmd`).
const embedded_kmd: []const u8 = @embedFile("vlmcsd.kmd");

const params = clap.parseParamsComptime(
    \\-h, --help                       Display this help and exit.
    \\-V, --version                    Output version information and exit.
    \\-p, --port <u16>                 TCP listen port (default 1688).
    \\-L, --listen <str>...            Listen address, repeatable (default 0.0.0.0).
    \\    --timeout <str>              Idle timeout (default 30s, 0 disables).
    \\-m, --max-clients <u32>          Concurrent client cap (default unlimited).
    \\    --data <str>                 External .kmd data file (default embedded).
    \\    --epid <str>...              ePID override name=epid, repeatable.
    \\    --randomize <u8>             ePID randomization level 0/1/2 (default 1).
    \\    --lcid <u32>                 Fixed LCID for randomized ePIDs.
    \\    --build <u32>                Fixed build number for randomized ePIDs.
    \\    --activation-interval <str>  VL activation interval (default 2h).
    \\    --renewal-interval <str>     VL renewal interval (default 7d).
    \\    --whitelist <u32>            Whitelisting level 0-3 (default 0).
    \\    --ip-protection <u8>         Public-IP protection level 0-3 (default 0).
    \\    --check-client-time          Validate client timestamp.
    \\    --maintain-clients           Keep client list across requests.
    \\    --start-empty                Start with empty client list.
    \\    --no-ndr64                   Disable NDR64 transfer syntax (default on).
    \\    --no-btfn                    Disable bind-time feature negotiation (default on).
    \\    --disconnect-per-request     Disconnect after each request.
    \\    --pid-file <str>             Write PID to file.
    \\-v, --verbose                    Verbose logging.
    \\-q, --quiet                      Quiet logging (warnings/errors only).
    \\
);

/// Resolved server configuration (post three-tier precedence merge).
const ServerOptions = struct {
    port: u16 = default_port,
    listen: []const []const u8 = &.{"0.0.0.0"},
    timeout_seconds: u64 = 30,
    max_clients: u32 = 0,
    data_file: ?[]const u8 = null,
    epids: []const []const u8 = &.{},
    randomize: u8 = 1,
    lcid: u32 = 0,
    build: u32 = 0,
    activation_interval_minutes: u32 = 120,
    renewal_interval_minutes: u32 = 10080,
    whitelist: u32 = 0,
    ip_protection: u8 = 0,
    check_client_time: bool = false,
    maintain_clients: bool = false,
    start_empty: bool = false,
    ndr64: bool = true,
    btfn: bool = true,
    disconnect_per_request: bool = false,
    pid_file: ?[]const u8 = null,
    verbose: bool = false,
    quiet: bool = false,

    /// gpa-allocated backing for `listen`/`epids` (only when split from env).
    listen_backing: ?[]const []const u8 = null,
    epid_backing: ?[]const []const u8 = null,

    fn deinit(self: *ServerOptions, gpa: Allocator) void {
        if (self.listen_backing) |b| gpa.free(b);
        if (self.epid_backing) |b| gpa.free(b);
    }
};

fn envGet(env: *const EnvironMap, name: []const u8) ?[]const u8 {
    return env.get(name);
}

/// Resolve a single boolean flag: the flag flips the default; the env var
/// supplies an explicit value.
fn resolveFlag(
    cli_flag: usize,
    env: *const EnvironMap,
    env_name: []const u8,
    default: bool,
) !bool {
    if (cli_flag != 0) return !default;
    if (envGet(env, env_name)) |s| return cli_helper.parseBool(s);
    return default;
}

fn resolveInt(
    comptime T: type,
    cli_val: ?T,
    env: *const EnvironMap,
    env_name: []const u8,
    default: T,
) !T {
    if (cli_val) |v| return v;
    if (envGet(env, env_name)) |s| return std.fmt.parseInt(T, s, 10);
    return default;
}

fn resolveStr(
    cli_val: ?[]const u8,
    env: *const EnvironMap,
    env_name: []const u8,
    default: ?[]const u8,
) ?[]const u8 {
    if (cli_val) |v| return v;
    if (envGet(env, env_name)) |s| return s;
    return default;
}

/// Resolve a duration option into minutes (the KMS protocol's native unit).
fn resolveDurationMinutes(
    cli_val: ?[]const u8,
    env: *const EnvironMap,
    env_name: []const u8,
    default_str: []const u8,
) !u32 {
    const raw = cli_val orelse envGet(env, env_name) orelse default_str;
    const seconds = try cli_helper.parseDurationSeconds(raw);
    return @intCast(seconds / 60);
}

/// Split a comma-separated env-var value into a trimmed list (gpa-allocated).
fn splitList(gpa: Allocator, s: []const u8) ![]const []const u8 {
    var count: usize = 1;
    for (s) |c| {
        if (c == ',') count += 1;
    }
    const out = try gpa.alloc([]const u8, count);
    errdefer gpa.free(out);
    var it = std.mem.splitScalar(u8, s, ',');
    var i: usize = 0;
    while (it.next()) |item| {
        const trimmed = std.mem.trim(u8, item, " \t");
        if (trimmed.len > 0) {
            out[i] = trimmed;
            i += 1;
        }
    }
    return out[0..i];
}

fn resolveOptions(gpa: Allocator, env: *const EnvironMap, args: anytype) !ServerOptions {
    // zig-clap names each argument field after its longest (long) name,
    // preserving hyphens; pull them out via `@field` into snake_case locals.
    const max_clients = @field(args, "max-clients");
    const activation_interval = @field(args, "activation-interval");
    const renewal_interval = @field(args, "renewal-interval");
    const ip_protection = @field(args, "ip-protection");
    const check_client_time = @field(args, "check-client-time");
    const maintain_clients = @field(args, "maintain-clients");
    const start_empty = @field(args, "start-empty");
    const no_ndr64 = @field(args, "no-ndr64");
    const no_btfn = @field(args, "no-btfn");
    const disconnect_per_request = @field(args, "disconnect-per-request");
    const pid_file = @field(args, "pid-file");

    var opts = ServerOptions{};

    opts.port = try resolveInt(u16, args.port, env, "VLMZSD_PORT", default_port);

    // --listen (repeatable) > VLMZSD_LISTEN (comma-separated) > default.
    if (args.listen.len > 0) {
        opts.listen = args.listen;
    } else if (envGet(env, "VLMZSD_LISTEN")) |s| {
        opts.listen_backing = try splitList(gpa, s);
        opts.listen = opts.listen_backing.?;
    }

    opts.timeout_seconds = blk: {
        const raw = args.timeout orelse envGet(env, "VLMZSD_TIMEOUT") orelse "30s";
        break :blk try cli_helper.parseDurationSeconds(raw);
    };

    opts.max_clients = try resolveInt(u32, max_clients, env, "VLMZSD_MAX_CLIENTS", 0);
    opts.data_file = resolveStr(args.data, env, "VLMZSD_DATA", null);

    if (args.epid.len > 0) {
        opts.epids = args.epid;
    } else if (envGet(env, "VLMZSD_EPID")) |s| {
        opts.epid_backing = try splitList(gpa, s);
        opts.epids = opts.epid_backing.?;
    }

    opts.randomize = try resolveInt(u8, args.randomize, env, "VLMZSD_RANDOMIZE", 1);
    opts.lcid = try resolveInt(u32, args.lcid, env, "VLMZSD_LCID", 0);
    opts.build = try resolveInt(u32, args.build, env, "VLMZSD_BUILD", 0);

    opts.activation_interval_minutes = try resolveDurationMinutes(activation_interval, env, "VLMZSD_ACTIVATION_INTERVAL", "2h");
    opts.renewal_interval_minutes = try resolveDurationMinutes(renewal_interval, env, "VLMZSD_RENEWAL_INTERVAL", "7d");
    opts.whitelist = try resolveInt(u32, args.whitelist, env, "VLMZSD_WHITELIST", 0);
    opts.ip_protection = try resolveInt(u8, ip_protection, env, "VLMZSD_IP_PROTECTION", 0);

    opts.check_client_time = try resolveFlag(check_client_time, env, "VLMZSD_CHECK_CLIENT_TIME", false);
    opts.maintain_clients = try resolveFlag(maintain_clients, env, "VLMZSD_MAINTAIN_CLIENTS", false);
    opts.start_empty = try resolveFlag(start_empty, env, "VLMZSD_START_EMPTY", false);

    opts.ndr64 = try resolveFlag(no_ndr64, env, "VLMZSD_NDR64", true);
    opts.btfn = try resolveFlag(no_btfn, env, "VLMZSD_BTFN", true);
    opts.disconnect_per_request = try resolveFlag(disconnect_per_request, env, "VLMZSD_DISCONNECT_PER_REQUEST", false);

    opts.pid_file = resolveStr(pid_file, env, "VLMZSD_PID_FILE", null);
    opts.verbose = args.verbose != 0;
    opts.quiet = args.quiet != 0;

    return opts;
}

/// Find a CSVLC index by its human-readable name (used by `--epid name=epid`).
fn findCsvlkByName(data: *const kmsdata.KmsData, name: []const u8) ?usize {
    for (data.csvlk, 0..) |csvlk, i| {
        if (std.mem.eql(u8, csvlk.name, name)) return i;
    }
    return null;
}

/// Build the per-CSVLC ePID override table: `--epid` entries win, then level-1
/// pre-randomization fills the remaining slots (mirrors C `randomPidInit`).
fn buildEpidOverrides(
    gpa: Allocator,
    data: *const kmsdata.KmsData,
    opts: *const ServerOptions,
    rng: std.Random,
    now_unix: i64,
    log: *cli_helper.Logger,
) ![]const ?[]const u8 {
    const n = data.csvlk.len;
    const overrides = try gpa.alloc(?[]const u8, n);
    errdefer gpa.free(overrides);
    @memset(overrides, null);

    // 1. `--epid <name>=<epid>` overrides.
    for (opts.epids) |entry| {
        const eq = std.mem.indexOfScalar(u8, entry, '=') orelse {
            log.warn("ignoring malformed --epid entry (expected name=epid): {s}", .{entry});
            continue;
        };
        const name = entry[0..eq];
        const epid = entry[eq + 1 ..];
        const idx = findCsvlkByName(data, name) orelse {
            log.warn("ignoring --epid for unknown CSVLC name: {s}", .{name});
            continue;
        };
        overrides[idx] = try gpa.dupe(u8, epid);
    }

    // 2. Level-1 pre-randomization: one shared random build, random LCID,
    //    per-CSVLC random key ID (only when the CSVLC has no --epid override).
    if (opts.randomize == 1) {
        const lang: i16 = if (opts.lcid != 0) @intCast(opts.lcid) else 0;
        var host_build: i32 = if (opts.build != 0) @intCast(opts.build) else 0;
        for (overrides, 0..) |*slot, i| {
            if (slot.* != null) continue;
            if (host_build == 0) host_build = kms.randomHostBuild(data, rng, opts.ndr64);
            var buf: [kms.pid_buffer_size]u8 = undefined;
            const pid = kms.generateRandomPid(data, i, &buf, lang, host_build, rng, opts.ndr64, now_unix);
            slot.* = try gpa.dupe(u8, pid);
        }
    }

    return overrides;
}

/// Per-connection worker context. Allocated per accepted client and owned by
/// the worker thread, which destroys it on exit.
const ClientContext = struct {
    stream: Io.net.Stream,
    io: Io,
    gpa: Allocator,
    cfg: *const kms.ServerConfig,
    prng: std.Random.DefaultPrng,
    port_str: []const u8,
    use_ndr64: bool,
    use_btfn: bool,
    disconnect_per_request: bool,
    timeout_seconds: u32,
    verbose: bool,
    sem: ?*Io.Semaphore,
    log: *cli_helper.Logger,
};

/// Serve one connection on its own thread (thread-per-connection, mirroring the
/// C `serveClientThreadProc`). Releases the semaphore and frees the context on
/// exit.
fn serveClientThread(ctx: *ClientContext) void {
    defer {
        ctx.stream.close(ctx.io);
        if (ctx.sem) |sem| sem.post(ctx.io);
        ctx.gpa.destroy(ctx);
    }

    if (ctx.verbose) ctx.log.info("connection accepted", .{});

    const now_unix = cli_helper.nowUnix(ctx.io);

    var rbuf: [4096]u8 = undefined;
    var wbuf: [4096]u8 = undefined;
    var reader = ctx.stream.reader(ctx.io, &rbuf);
    var writer = ctx.stream.writer(ctx.io, &wbuf);

    network.serveRpc(ctx.gpa, &reader.interface, &writer.interface, ctx.prng.random(), now_unix, .{
        .cfg = ctx.cfg,
        .secondary_address = ctx.port_str,
        .use_ndr64 = ctx.use_ndr64,
        .use_btfn = ctx.use_btfn,
        .disconnect_per_request = ctx.disconnect_per_request,
        .timeout_seconds = ctx.timeout_seconds,
        .socket_fd = ctx.stream.socket.handle,
    }) catch |e| switch (e) {
        error.EndOfStream, error.Timeout => {},
        else => ctx.log.warn("connection error: {s}", .{@errorName(e)}),
    };
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
        try fw.interface.print("vlmzsd {s}\n", .{version});
        try fw.interface.flush();
        return;
    }

    var log_buf: [4096]u8 = undefined;
    var log = cli_helper.Logger.init(init.io, &log_buf);

    var opts = try resolveOptions(init.gpa, init.environ_map, &res.args);
    defer opts.deinit(init.gpa);

    // Load the KMS data: external file overrides the embedded default.
    var kmd_owned = false;
    var kmd_raw: []const u8 = undefined;
    if (opts.data_file) |path| {
        kmd_raw = try std.Io.Dir.readFileAlloc(std.Io.Dir.cwd(), init.io, path, init.gpa, .unlimited);
        kmd_owned = true;
    } else {
        kmd_raw = embedded_kmd;
    }
    defer if (kmd_owned) init.gpa.free(@constCast(kmd_raw));

    var data = try kmsdata.parse(init.gpa, kmd_raw);
    defer data.deinit(init.gpa);

    var prng = std.Random.DefaultPrng.init(cli_helper.makeSeed(init.io));
    const rng = prng.random();

    const epid_overrides = try buildEpidOverrides(init.gpa, &data, &opts, rng, cli_helper.nowUnix(init.io), &log);
    defer {
        for (epid_overrides) |slot| {
            if (slot) |s| init.gpa.free(s);
        }
        init.gpa.free(epid_overrides);
    }

    // Client lists (strict mode): one per app, pre-filled unless --start-empty.
    var client_lists: kms.ClientLists = undefined;
    var client_lists_storage: ?[]kms.ClientList = null;
    if (opts.maintain_clients) {
        client_lists_storage = try init.gpa.alloc(kms.ClientList, data.apps().len);
        client_lists = .{ .lists = client_lists_storage.? };
        kms.initClientLists(&client_lists, &data, opts.start_empty, rng);
    }
    defer if (client_lists_storage) |s| init.gpa.free(s);

    const cfg = kms.ServerConfig{
        .data = &data,
        .vl_activation_interval = opts.activation_interval_minutes,
        .vl_renewal_interval = opts.renewal_interval_minutes,
        .check_client_time = opts.check_client_time,
        .whitelisting_level = opts.whitelist,
        .randomization_level = opts.randomize,
        .lcid = @truncate(opts.lcid),
        .build = opts.build,
        .epid_overrides = epid_overrides,
        .use_ndr64 = opts.ndr64,
        .maintain_clients = opts.maintain_clients,
        .client_lists = if (client_lists_storage != null) &client_lists else null,
    };

    var port_str_buf: [6]u8 = undefined;
    const port_str = try std.fmt.bufPrint(&port_str_buf, "{d}", .{opts.port});

    // Create the listening sockets. ip-protection level 1 listens only on the
    // host's private addresses; otherwise `--listen` (default 0.0.0.0).
    var servers = std.ArrayList(Io.net.Server).empty;
    defer {
        for (servers.items) |*s| s.deinit(init.io);
        servers.deinit(init.gpa);
    }

    if (opts.ip_protection & 1 != 0) {
        const privates = try network.getPrivateIPAddresses(init.gpa);
        defer init.gpa.free(privates);
        if (privates.len == 0) log.warn("ip-protection level 1: no private IP addresses found", .{});
        for (privates) |ip0| {
            var ip = ip0;
            ip.setPort(opts.port);
            const s = Io.net.IpAddress.listen(&ip, init.io, .{ .reuse_address = true }) catch |e| {
                log.warn("failed to listen on a private address: {s}", .{@errorName(e)});
                continue;
            };
            try servers.append(init.gpa, s);
        }
    } else {
        for (opts.listen) |addr| {
            const s = network.listen(init.io, addr, opts.port) catch |e| {
                log.err("failed to listen on {s}:{d}: {s}", .{ addr, opts.port, @errorName(e) });
                return e;
            };
            try servers.append(init.gpa, s);
        }
    }

    if (servers.items.len == 0) {
        log.err("could not listen on any socket", .{});
        return error.NoListenSocket;
    }

    log.info("vlmzsd {s} listening on port {d} ({d} socket{s})", .{
        version,
        opts.port,
        servers.items.len,
        if (servers.items.len == 1) "" else "s",
    });

    // Write the PID file (best effort; mirrors the C `writePidFile`, which
    // only logs on failure).
    if (opts.pid_file) |path| {
        var pid_buf: [16]u8 = undefined;
        const pid_str = try std.fmt.bufPrint(&pid_buf, "{d}", .{std.c.getpid()});
        std.Io.Dir.writeFile(std.Io.Dir.cwd(), init.io, .{
            .sub_path = path,
            .data = pid_str,
        }) catch |e| log.warn("failed to write pid file {s}: {s}", .{ path, @errorName(e) });
    }

    // Concurrency limit: a counting semaphore gates the worker threads
    // (mirrors the C `MaxTaskSemaphore`). 0 = unlimited.
    const sem_active = opts.max_clients != 0;
    var sem = Io.Semaphore{ .permits = if (sem_active) opts.max_clients else 0 };

    var poll_fds: [64]std.posix.pollfd = undefined;
    if (servers.items.len > poll_fds.len) return error.TooManyListenSockets;

    while (true) {
        const fds = poll_fds[0..servers.items.len];
        for (servers.items, 0..) |*s, i| {
            fds[i] = .{ .fd = s.socket.handle, .events = std.posix.POLL.IN, .revents = 0 };
        }
        const nready = std.posix.poll(fds, -1) catch |e| {
            log.err("poll failed: {s}", .{@errorName(e)});
            return e;
        };
        if (nready == 0) continue;

        for (fds, 0..) |f, i| {
            if (f.revents & std.posix.POLL.IN == 0) continue;
            const stream = servers.items[i].accept(init.io) catch |e| {
                log.warn("accept failed: {s}", .{@errorName(e)});
                continue;
            };

            // ip-protection level 2: reject clients with a public IP address.
            if (opts.ip_protection & 2 != 0) {
                if (!network.isClientPrivate(stream.socket.handle)) {
                    stream.close(init.io);
                    if (opts.verbose) log.info("client with public IP address rejected", .{});
                    continue;
                }
            }

            // Block until a worker slot is available (if the cap is enabled).
            if (sem_active) sem.waitUncancelable(init.io);

            const ctx = init.gpa.create(ClientContext) catch |e| {
                stream.close(init.io);
                if (sem_active) sem.post(init.io);
                log.warn("out of memory accepting client: {s}", .{@errorName(e)});
                continue;
            };
            ctx.* = .{
                .stream = stream,
                .io = init.io,
                .gpa = init.gpa,
                .cfg = &cfg,
                .prng = std.Random.DefaultPrng.init(prng.random().int(u64)),
                .port_str = port_str,
                .use_ndr64 = opts.ndr64,
                .use_btfn = opts.btfn,
                .disconnect_per_request = opts.disconnect_per_request,
                .timeout_seconds = @intCast(opts.timeout_seconds),
                .verbose = opts.verbose,
                .sem = if (sem_active) &sem else null,
                .log = &log,
            };

            const th = std.Thread.spawn(.{}, serveClientThread, .{ctx}) catch |e| {
                ctx.stream.close(init.io);
                if (sem_active) sem.post(init.io);
                init.gpa.destroy(ctx);
                log.warn("failed to spawn client thread: {s}", .{@errorName(e)});
                continue;
            };
            th.detach();
        }
    }
}
