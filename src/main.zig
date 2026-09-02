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

const Io = std.Io;
const Allocator = std.mem.Allocator;
const EnvironMap = std.process.Environ.Map;

const version = "0.0.0";
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
    \\    --no-check-client-time       Do not validate client timestamp.
    \\    --maintain-clients           Keep client list across requests.
    \\    --no-maintain-clients        Do not keep client list.
    \\    --start-empty                Start with empty client list.
    \\    --ndr64                      Use NDR64 transfer syntax (default on).
    \\    --no-ndr64                   Do not use NDR64.
    \\    --btfn                       Use bind-time feature negotiation.
    \\    --no-btfn                    Do not use BTFN.
    \\    --disconnect-per-request     Disconnect after each request.
    \\    --foreground                 Run in the foreground (default).
    \\    --no-foreground              Run in the background.
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
    btfn: bool = false,
    disconnect_per_request: bool = false,
    foreground: bool = true,
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

fn resolveBool(
    cli_flag: usize,
    cli_no_flag: usize,
    env: *const EnvironMap,
    env_name: []const u8,
    default: bool,
) !bool {
    if (cli_flag != 0) return true;
    if (cli_no_flag != 0) return false;
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

fn resolveOptions(gpa: Allocator, env: *const EnvironMap, args: anytype, log: *cli_helper.Logger) !ServerOptions {
    // zig-clap names each argument field after its longest (long) name,
    // preserving hyphens; pull them out via `@field` into snake_case locals.
    const max_clients = @field(args, "max-clients");
    const activation_interval = @field(args, "activation-interval");
    const renewal_interval = @field(args, "renewal-interval");
    const ip_protection = @field(args, "ip-protection");
    const check_client_time = @field(args, "check-client-time");
    const no_check_client_time = @field(args, "no-check-client-time");
    const maintain_clients = @field(args, "maintain-clients");
    const no_maintain_clients = @field(args, "no-maintain-clients");
    const start_empty = @field(args, "start-empty");
    const no_ndr64 = @field(args, "no-ndr64");
    const no_btfn = @field(args, "no-btfn");
    const disconnect_per_request = @field(args, "disconnect-per-request");
    const no_foreground = @field(args, "no-foreground");
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

    opts.check_client_time = try resolveBool(check_client_time, no_check_client_time, env, "VLMZSD_CHECK_CLIENT_TIME", false);
    opts.maintain_clients = try resolveBool(maintain_clients, no_maintain_clients, env, "VLMZSD_MAINTAIN_CLIENTS", false);
    opts.start_empty = try resolveBool(start_empty, 0, env, "VLMZSD_START_EMPTY", false);

    opts.ndr64 = try resolveBool(args.ndr64, no_ndr64, env, "VLMZSD_NDR64", true);
    opts.btfn = try resolveBool(args.btfn, no_btfn, env, "VLMZSD_BTFN", false);
    opts.disconnect_per_request = try resolveBool(disconnect_per_request, 0, env, "VLMZSD_DISCONNECT_PER_REQUEST", false);

    opts.foreground = try resolveBool(args.foreground, no_foreground, env, "VLMZSD_FOREGROUND", true);
    opts.pid_file = resolveStr(pid_file, env, "VLMZSD_PID_FILE", null);
    opts.verbose = args.verbose != 0;
    opts.quiet = args.quiet != 0;

    // Warn about options whose semantics land in a later phase.
    if (opts.epids.len > 0) log.warn("--epid overrides are not yet applied", .{});
    if (opts.randomize != 1) log.warn("--randomize is not yet applied", .{});
    if (opts.lcid != 0) log.warn("--lcid is not yet applied", .{});
    if (opts.build != 0) log.warn("--build is not yet applied", .{});
    if (opts.ip_protection != 0) log.warn("--ip-protection is not yet applied", .{});
    if (opts.max_clients != 0) log.warn("--max-clients is not yet enforced", .{});
    if (opts.maintain_clients) log.warn("--maintain-clients is not yet implemented", .{});
    if (opts.start_empty) log.warn("--start-empty is not yet implemented", .{});
    if (opts.btfn) log.warn("--btfn is not yet implemented", .{});
    if (opts.disconnect_per_request) log.warn("--disconnect-per-request is not yet implemented", .{});
    if (opts.timeout_seconds != 30) log.warn("--timeout is not yet enforced", .{});
    if (!opts.foreground) log.warn("background mode is not supported; daemonization is the supervisor's job", .{});
    if (opts.pid_file != null) log.warn("--pid-file is not yet implemented", .{});

    return opts;
}

fn nowUnix(io: Io) i64 {
    const now = Io.Clock.now(.real, io);
    return @intCast(@divTrunc(now.nanoseconds, std.time.ns_per_s));
}

fn makeSeed(io: Io) u64 {
    const now = Io.Clock.now(.real, io);
    const nanos: u128 = @intCast(now.nanoseconds);
    const ptr_entropy: u64 = @truncate(@as(u128, @intCast(@intFromPtr(&now))));
    return @as(u64, @truncate(nanos)) ^ ptr_entropy;
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

    var opts = try resolveOptions(init.gpa, init.environ_map, &res.args, &log);
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

    const cfg = kms.ServerConfig{
        .data = &data,
        .vl_activation_interval = opts.activation_interval_minutes,
        .vl_renewal_interval = opts.renewal_interval_minutes,
        .check_client_time = opts.check_client_time,
        .whitelisting_level = opts.whitelist,
    };

    var prng = std.Random.DefaultPrng.init(makeSeed(init.io));
    const rng = prng.random();

    // Single-address MVP: serve the first listen address.
    const addr = opts.listen[0];
    if (opts.listen.len > 1) log.warn("multiple --listen addresses are not yet served concurrently; using {s}", .{addr});

    var port_str_buf: [6]u8 = undefined;
    const port_str = try std.fmt.bufPrint(&port_str_buf, "{d}", .{opts.port});

    var server = network.listen(init.io, addr, opts.port) catch |e| {
        log.err("failed to listen on {s}:{d}: {s}", .{ addr, opts.port, @errorName(e) });
        return e;
    };

    log.info("vlmzsd {s} listening on {s}:{d}", .{ version, addr, opts.port });

    while (true) {
        const stream = server.accept(init.io) catch |e| {
            log.err("accept failed: {s}", .{@errorName(e)});
            return e;
        };
        defer stream.close(init.io);

        if (opts.verbose) log.info("connection accepted", .{});

        const now_unix = nowUnix(init.io);

        var rbuf: [4096]u8 = undefined;
        var wbuf: [4096]u8 = undefined;
        var reader = stream.reader(init.io, &rbuf);
        var writer = stream.writer(init.io, &wbuf);

        network.serveRpc(init.gpa, &reader.interface, &writer.interface, rng, now_unix, .{
            .cfg = &cfg,
            .secondary_address = port_str,
            .use_ndr64 = opts.ndr64,
        }) catch |e| switch (e) {
            error.EndOfStream => {},
            else => log.warn("connection error: {s}", .{@errorName(e)}),
        };
    }
}
