//! `vlmzsd` — the KMS server binary (Phase 6).
//!
//! Implements the `vlmzsd` CLI surface from `docs/cli.md`: no config file,
//! three-tier precedence (default < `VLMZSD_*` env var < CLI flag), fixed-format
//! stdout logging, and a foreground accept/serve loop over `network.serveRpc`.

const std = @import("std");
const vlmzsd = @import("vlmzsd");
const cli_helper = @import("cli_helper.zig");
const network = @import("network.zig");
const kms = vlmzsd.kms;
const kmsdata = vlmzsd.kmsdata;

const Allocator = std.mem.Allocator;
const Io = std.Io;
const EnvironMap = std.process.Environ.Map;

const build_options = @import("build_options");
const version = build_options.version;
const git_hash = build_options.git_hash;
const build_date = build_options.build_date;
const default_port: u16 = 1688;

/// `--ip-protection` bit masks (docs/cli.md §5).
const ip_protect_private_listen: u8 = 1; // listen only on private addresses
const ip_protect_reject_public: u8 = 2; // reject clients with public IPs

/// Maximum listen sockets (plus one shutdown-pipe slot in the poll set).
const max_listen_sockets = 64;
/// Longest decimal PID string (generous upper bound).
const pid_str_buffer_size = 16;

/// Default `--max-clients` cap. Bounds the concurrent client tasks, and with
/// them the pooled threads: `std.Io.Threaded` neither reclaims idle workers nor
/// reports its options (see `ServerContext.in_flight`). `0` still means
/// "unlimited" (docs/cli.md §5).
const default_client_cap: u32 = 1024;
/// Poll timeout in milliseconds while the client cap is reached. Nothing else
/// would wake the accept loop when a slot frees, so the loop re-checks the gate
/// on this interval instead of blocking indefinitely.
const saturated_poll_ms: i32 = 100;

/// Embedded default `.kmd` data, unless built with `-Dno-embedded-data`
/// (then `--data <file>` is required at runtime).
const embedded_kmd: []const u8 = if (build_options.embedded_data) @embedFile("vlmcsd.kmd") else &.{};

/// Data-driven option table for `vlmzsd` (docs/cli.md §5). Single source of
/// truth: drives parsing, `--help` rendering, and validation alike. The
/// groups mirror the "Grouped by concern" spec in `docs/cli.md`.
const vlmzsd_opts = [_]cli_helper.Opt{
    .{ .name = "help", .short = 'h', .group = "General", .desc = "Display this help and exit" },
    .{ .name = "version", .short = 'V', .group = "General", .desc = "Output version information and exit" },
    .{ .name = "port", .short = 'p', .kind = .int, .hint = "u16", .group = "Network", .desc = "TCP listen port (default 1688)" },
    .{ .name = "listen", .short = 'L', .kind = .str, .hint = "addr", .group = "Network", .desc = "Listen address, repeatable (default ::, dual-stack)", .repeatable = true },
    .{ .name = "timeout", .kind = .str, .hint = "dur", .group = "Network", .desc = "Idle timeout (default 30s, 0 disables)" },
    .{ .name = "max-clients", .short = 'm', .kind = .int, .hint = "u32", .group = "Network", .desc = "Concurrent client cap (default 1024, 0 = unlimited)" },
    .{ .name = "data", .kind = .str, .hint = "file", .group = "Data", .desc = "External .kmd data file (default embedded)" },
    .{ .name = "epid", .kind = .str, .hint = "name=epid", .group = "ePID", .desc = "ePID override name=epid, repeatable", .repeatable = true },
    .{ .name = "randomize", .kind = .int, .hint = "u8", .group = "ePID", .desc = "ePID randomization level 0/1/2 (default 1)" },
    .{ .name = "lcid", .kind = .int, .hint = "u32", .group = "ePID", .desc = "Fixed LCID for randomized ePIDs" },
    .{ .name = "build", .kind = .int, .hint = "u32", .group = "ePID", .desc = "Fixed build number for randomized ePIDs" },
    .{ .name = "activation-interval", .kind = .str, .hint = "dur", .group = "Activation policy", .desc = "VL activation interval (default 2h)" },
    .{ .name = "renewal-interval", .kind = .str, .hint = "dur", .group = "Activation policy", .desc = "VL renewal interval (default 7d)" },
    .{ .name = "whitelist", .kind = .int, .hint = "u32", .group = "Activation policy", .desc = "Whitelisting level 0-3 (default 0)" },
    .{ .name = "ip-protection", .kind = .int, .hint = "u8", .group = "Activation policy", .desc = "Public-IP protection level 0-3 (default 0)" },
    .{ .name = "check-client-time", .group = "Activation policy", .desc = "Validate client timestamp" },
    .{ .name = "maintain-clients", .group = "Activation policy", .desc = "Keep client list across requests" },
    .{ .name = "start-empty", .group = "Activation policy", .desc = "Start with empty client list" },
    .{ .name = "no-ndr64", .group = "Protocol", .desc = "Disable NDR64 transfer syntax (default on)" },
    .{ .name = "no-btfn", .group = "Protocol", .desc = "Disable bind-time feature negotiation (default on)" },
    .{ .name = "disconnect-per-request", .group = "Protocol", .desc = "Disconnect after each request" },
    .{ .name = "pid-file", .kind = .str, .hint = "file", .group = "Process", .desc = "Write PID to file" },
    .{ .name = "verbose", .short = 'v', .group = "Process", .desc = "Verbose logging" },
    .{ .name = "quiet", .short = 'q', .group = "Process", .desc = "Quiet logging (warnings/errors only)" },
    .{ .name = "quiet-loopback", .group = "Process", .desc = "Suppress debug logs for loopback (localhost) clients" },
};

/// Resolved server configuration (post three-tier precedence merge).
const ServerOptions = struct {
    port: u16 = default_port,
    listen: []const []const u8 = &.{"::"},
    timeout_seconds: u64 = 30,
    max_clients: u32 = default_client_cap,
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
    quiet_loopback: bool = false,

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
    cli_flag: bool,
    env: *const EnvironMap,
    env_name: []const u8,
    default: bool,
) !bool {
    if (cli_flag) return !default;
    if (envGet(env, env_name)) |s| return cli_helper.parseBool(s);
    return default;
}

fn resolveInt(
    comptime T: type,
    cli_val: ?[]const u8,
    env: *const EnvironMap,
    env_name: []const u8,
    default: T,
) !T {
    if (cli_val) |v| return std.fmt.parseInt(T, v, 10);
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

fn resolveOptions(gpa: Allocator, env: *const EnvironMap, res: *const cli_helper.Result) !ServerOptions {
    var opts = ServerOptions{};

    opts.port = try resolveInt(u16, res.get("port"), env, "VLMZSD_PORT", default_port);

    // --listen (repeatable) > VLMZSD_LISTEN (comma-separated) > default.
    const listen = res.getAll("listen");
    if (listen.len > 0) {
        opts.listen = listen;
    } else if (envGet(env, "VLMZSD_LISTEN")) |s| {
        opts.listen_backing = try splitList(gpa, s);
        opts.listen = opts.listen_backing.?;
    }

    opts.timeout_seconds = blk: {
        const raw = res.get("timeout") orelse envGet(env, "VLMZSD_TIMEOUT") orelse "30s";
        break :blk try cli_helper.parseDurationSeconds(raw);
    };

    opts.max_clients = try resolveInt(u32, res.get("max-clients"), env, "VLMZSD_MAX_CLIENTS", default_client_cap);
    opts.data_file = resolveStr(res.get("data"), env, "VLMZSD_DATA", null);

    const epids = res.getAll("epid");
    if (epids.len > 0) {
        opts.epids = epids;
    } else if (envGet(env, "VLMZSD_EPID")) |s| {
        opts.epid_backing = try splitList(gpa, s);
        opts.epids = opts.epid_backing.?;
    }

    opts.randomize = try resolveInt(u8, res.get("randomize"), env, "VLMZSD_RANDOMIZE", 1);
    opts.lcid = try resolveInt(u32, res.get("lcid"), env, "VLMZSD_LCID", 0);
    opts.build = try resolveInt(u32, res.get("build"), env, "VLMZSD_BUILD", 0);

    opts.activation_interval_minutes = try resolveDurationMinutes(res.get("activation-interval"), env, "VLMZSD_ACTIVATION_INTERVAL", "2h");
    opts.renewal_interval_minutes = try resolveDurationMinutes(res.get("renewal-interval"), env, "VLMZSD_RENEWAL_INTERVAL", "7d");
    opts.whitelist = try resolveInt(u32, res.get("whitelist"), env, "VLMZSD_WHITELIST", 0);
    opts.ip_protection = try resolveInt(u8, res.get("ip-protection"), env, "VLMZSD_IP_PROTECTION", 0);

    opts.check_client_time = try resolveFlag(res.hasFlag("check-client-time"), env, "VLMZSD_CHECK_CLIENT_TIME", false);
    opts.maintain_clients = try resolveFlag(res.hasFlag("maintain-clients"), env, "VLMZSD_MAINTAIN_CLIENTS", false);
    opts.start_empty = try resolveFlag(res.hasFlag("start-empty"), env, "VLMZSD_START_EMPTY", false);

    opts.ndr64 = try resolveFlag(res.hasFlag("no-ndr64"), env, "VLMZSD_NDR64", true);
    opts.btfn = try resolveFlag(res.hasFlag("no-btfn"), env, "VLMZSD_BTFN", true);
    opts.disconnect_per_request = try resolveFlag(res.hasFlag("disconnect-per-request"), env, "VLMZSD_DISCONNECT_PER_REQUEST", false);

    opts.pid_file = resolveStr(res.get("pid-file"), env, "VLMZSD_PID_FILE", null);
    opts.verbose = try resolveFlag(res.hasFlag("verbose"), env, "VLMZSD_VERBOSE", false);
    opts.quiet = try resolveFlag(res.hasFlag("quiet"), env, "VLMZSD_QUIET", false);
    opts.quiet_loopback = try resolveFlag(res.hasFlag("quiet-loopback"), env, "VLMZSD_QUIET_LOOPBACK", false);

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

/// Admission gate for concurrent client tasks, replacing a blocking
/// `Io.Semaphore` wait: `Io.Semaphore` offers no non-blocking query, so the
/// accept loop could not ask "is there room?" *before* accepting, and would sit
/// in `waitUncancelable` (not a cancelation point) after every extra `accept`.
///
/// Invariant: the accept loop is the sole acquirer, which is what lets `peak`
/// be a plain counter. A second acceptor would also need a CAS loop for it (and
/// could race the cap check in `acceptOne`).
const InFlight = struct {
    count: std.atomic.Value(u32) = .init(0),
    /// Maximum concurrent client tasks; `0` means unlimited.
    cap: u32,
    /// High-water mark of `count`; written only by the accept loop.
    peak: u32 = 0,

    /// Take a slot, or report that the gate is closed. Never blocks.
    fn tryAcquire(self: *InFlight) bool {
        if (self.cap != 0) {
            if (self.count.load(.acquire) >= self.cap) return false;
        }
        const n = self.count.fetchAdd(1, .acq_rel) + 1;
        self.peak = @max(self.peak, n);
        std.debug.assert(n <= self.cap or self.cap == 0);
        return true;
    }

    /// Return a slot taken by `tryAcquire`; must be called exactly once per
    /// successful acquire.
    fn release(self: *InFlight) void {
        const previous = self.count.fetchSub(1, .acq_rel);
        std.debug.assert(previous > 0);
    }

    /// True while no slot is free. Always false when the cap is `0`.
    fn atCap(self: *const InFlight) bool {
        if (self.cap == 0) return false;
        return self.count.load(.acquire) >= self.cap;
    }
};

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
    in_flight: *InFlight,
    log: *cli_helper.Logger,
    /// Mirror of `ServerOptions.quiet_loopback` (the opt-in).
    quiet_loopback: bool = false,
    /// Computed per connection: `quiet_loopback` AND the peer is loopback.
    quiet: bool = false,
};

/// Translate a `network.Event` into a log line. This is the logger boundary:
/// `network.serveRpc` reports what happened, and this function decides the
/// level, wording, and destination.
fn logProtocolEvent(context: ?*anyopaque, event: network.Event) void {
    const ctx: *ClientContext = @ptrCast(@alignCast(context orelse return));
    switch (event) {
        .bind_negotiated => |ndr64| {
            if (!ctx.quiet) ctx.log.debug("BIND: negotiated {s}", .{if (ndr64) "NDR64" else "NDR32"});
        },
        .fault => |nca| ctx.log.warn("RPC fault (NCA 0x{X:0>8})", .{nca}),
        .request_rejected => |r| {
            if (r.major != 0) {
                ctx.log.warn("KMS v{d} request rejected (HRESULT 0x{X:0>8})", .{ r.major, r.hr });
            } else {
                ctx.log.warn("invalid KMS request rejected (HRESULT 0x{X:0>8})", .{r.hr});
            }
        },
        .response => |r| {
            if (!ctx.quiet) ctx.log.debug("KMS v{d} request → {d}-byte response", .{ r.major, r.size });
        },
    }
}

/// Serve one connection as a pooled task (dispatched via `Group.concurrent`).
/// Releases its admission slot and frees the context on exit.
fn serveClientThread(ctx: *ClientContext) void {
    defer {
        ctx.stream.close(ctx.io);
        // Copy the gate out before `destroy` invalidates `ctx`, and release
        // last: the count must never lag behind the resources it accounts for,
        // or the accept loop could admit a client over the cap.
        const in_flight = ctx.in_flight;
        ctx.gpa.destroy(ctx);
        in_flight.release();
    }

    // Only when --quiet-loopback is on, and only for loopback peers (the
    // container HEALTHCHECK): suppress debug chatter; warn/err still logs.
    ctx.quiet = ctx.quiet_loopback and network.isLoopbackPeer(ctx.stream.socket.handle);

    var peer_buf: [64]u8 = undefined;
    const peer = network.formatPeer(ctx.stream.socket.handle, &peer_buf);
    if (!ctx.quiet) ctx.log.debug("connection from {s} accepted", .{peer});

    const now_unix = cli_helper.nowUnix(ctx.io);

    var rbuf: [4096]u8 = undefined;
    var wbuf: [4096]u8 = undefined;
    var reader = ctx.stream.reader(ctx.io, &rbuf);
    var writer = ctx.stream.writer(ctx.io, &wbuf);

    network.serveRpc(ctx.gpa, &reader.interface, &writer.interface, ctx.prng.random(), now_unix, .{
        .cfg = ctx.cfg,
        .on_event = logProtocolEvent,
        .event_context = ctx,
        .secondary_address = ctx.port_str,
        .use_ndr64 = ctx.use_ndr64,
        .use_btfn = ctx.use_btfn,
        .disconnect_per_request = ctx.disconnect_per_request,
        // Reads go through `Io.operateTimeout(.net_receive)`: the backend owns
        // the deadline and the cancelation point, so SIGINT/SIGTERM ends every
        // parked read at once (no self-pipe needed).
        .idle = .{ .peer = .{
            .io = ctx.io,
            .handle = ctx.stream.socket.handle,
            .timeout = network.timeoutSeconds(ctx.timeout_seconds),
        } },
    }) catch |e| switch (e) {
        error.EndOfStream => {
            if (!ctx.quiet) ctx.log.debug("connection from {s} closed", .{peer});
        },
        error.Timeout => {
            if (!ctx.quiet) ctx.log.debug("connection from {s} timed out", .{peer});
        },
        error.Canceled => {
            // The read wait is a backend cancelation point, so a cancelation
            // request (shutdown) ends it directly: a clean exit, not a failure.
            if (!ctx.quiet) ctx.log.debug("connection from {s} closed at shutdown", .{peer});
        },
        else => ctx.log.warn("connection from {s} error: {s}", .{ peer, @errorName(e) }),
    };
}

/// Self-pipe write end (`[1]`): the SIGINT/SIGTERM handler writes one byte here
/// (async-signal-safe) to wake the poll loop; the read end (`[0]`) is polled
/// like a listen socket. This is the classic self-pipe trick — the handler does
/// no cleanup itself, so the normal control flow (and its defers) runs the
/// shutdown. The pipe is the one piece of unavoidable global state: a signal
/// handler cannot take a context pointer.
var shutdown_pipe: [2]std.posix.fd_t = .{ -1, -1 };

fn handleShutdown(sig: std.posix.SIG) callconv(.c) void {
    _ = sig;
    // The only async-signal-safe work: write one byte to wake poll(). A flag
    // alone would not work — std.posix.poll swallows EINTR and keeps blocking.
    const byte: [1]u8 = .{1};
    _ = std.c.write(shutdown_pipe[1], &byte, 1);
}

/// Create the self-pipe and install handlers so Ctrl-C / `docker stop` shut the
/// server down cleanly.
fn installSignalHandlers(io: Io, log: *cli_helper.Logger) void {
    if (std.c.pipe(&shutdown_pipe) != 0) {
        fatal(log, io, "failed to create shutdown pipe", .{});
    }
    // Make the write end non-blocking so the handler never blocks when the
    // pipe is full (it only writes one byte, but correctness first). The
    // O_NONBLOCK bit lives at a platform-dependent offset — derive it instead
    // of hard-coding a value.
    const nonblock_mask: i32 = @as(i32, 1) << @intCast(@bitOffsetOf(std.posix.O, "NONBLOCK"));
    const flags = std.c.fcntl(shutdown_pipe[1], std.c.F.GETFL, @as(i32, 0));
    if (flags < 0 or std.c.fcntl(shutdown_pipe[1], std.c.F.SETFL, flags | nonblock_mask) < 0) {
        fatal(log, io, "failed to make shutdown pipe non-blocking", .{});
    }

    const act = std.posix.Sigaction{
        .handler = .{ .handler = handleShutdown },
        .mask = std.posix.sigemptyset(),
        .flags = 0,
    };
    std.posix.sigaction(std.posix.SIG.INT, &act, null);
    std.posix.sigaction(std.posix.SIG.TERM, &act, null);
}

/// Create the listening sockets. ip-protection level 1 listens only on the
/// host's private addresses; otherwise `--listen` (default ::, a dual-stack
/// socket covering both IPv4 and IPv6).
fn createListenSockets(
    gpa: Allocator,
    io: Io,
    opts: *const ServerOptions,
    log: *cli_helper.Logger,
    servers: *std.ArrayList(Io.net.Server),
) !void {
    if (opts.ip_protection & ip_protect_private_listen != 0) {
        const privates = try network.getPrivateIPAddresses(gpa);
        defer gpa.free(privates);
        if (privates.len == 0) log.warn("ip-protection level 1: no private IP addresses found", .{});
        for (privates) |ip0| {
            var ip = ip0;
            ip.setPort(opts.port);
            const s = Io.net.IpAddress.listen(&ip, io, .{ .reuse_address = true }) catch |e| {
                log.warn("failed to listen on a private address: {s}", .{@errorName(e)});
                continue;
            };
            try servers.append(gpa, s);
        }
    } else {
        for (opts.listen) |addr| {
            const s = network.listen(io, addr, opts.port) catch |e| {
                // Fallback: a default dual-stack "::" listen fails when the
                // host has no IPv6 stack; retry on IPv4 only.
                if (std.mem.eql(u8, addr, "::") and e == error.AddressFamilyUnsupported) {
                    const s4 = network.listen(io, "0.0.0.0", opts.port) catch |e4| {
                        fatal(log, io, "failed to listen on 0.0.0.0:{d}: {s}", .{ opts.port, @errorName(e4) });
                    };
                    try servers.append(gpa, s4);
                    continue;
                }
                fatal(log, io, "failed to listen on {s}:{d}: {s}", .{ addr, opts.port, @errorName(e) });
            };
            try servers.append(gpa, s);
        }
    }

    if (servers.items.len == 0) {
        fatal(log, io, "could not listen on any socket", .{});
    }
}

/// State shared by the accept loop: everything it needs to poll the listen
/// sockets, gate accepted clients on `in_flight`, and dispatch them onto the
/// worker pool.
const ServerContext = struct {
    gpa: Allocator,
    io: Io,
    opts: *const ServerOptions,
    log: *cli_helper.Logger,
    cfg: *const kms.ServerConfig,
    servers: []Io.net.Server,
    in_flight: InFlight,
    conn_group: *Io.Group,
    port_str: []const u8,
    prng: std.Random,

    /// Poll the listen sockets and the shutdown pipe, accepting and
    /// dispatching clients until SIGINT/SIGTERM arrives.
    fn run(self: *ServerContext) !void {
        var poll_fds: [max_listen_sockets + 1]std.posix.pollfd = undefined;
        const pipe_index = self.servers.len; // the shutdown pipe's slot in `fds`
        // One warn per saturation period: saturation is a property of the
        // period, not of each poll iteration.
        var saturated_logged = false;

        while (true) {
            // Admission control runs *before* `accept`: while the cap is
            // reached, the listen sockets stay out of the poll set, so excess
            // connections wait in the kernel backlog (TCP backpressure) instead
            // of being accepted into a worker that has nowhere to go.
            const saturated = self.in_flight.atCap();
            if (saturated and !saturated_logged) {
                saturated_logged = true;
                self.log.warn("client cap reached ({d}), deferring accept", .{self.in_flight.cap});
            }
            if (!saturated) saturated_logged = false;

            // While saturated only the shutdown pipe is polled, so SIGINT is
            // still handled promptly; the pipe sits last in `poll_fds`, so it
            // is at `fds[pipe_slot]` in either case.
            const first: usize = if (saturated) pipe_index else 0;
            const fds = poll_fds[first .. pipe_index + 1];
            const pipe_slot: usize = pipe_index - first;
            if (!saturated) {
                for (self.servers, 0..) |*s, i| {
                    fds[i] = .{ .fd = s.socket.handle, .events = std.posix.POLL.IN, .revents = 0 };
                }
            }
            fds[pipe_slot] = .{ .fd = shutdown_pipe[0], .events = std.posix.POLL.IN, .revents = 0 };

            // Blocking indefinitely is only safe while unsaturated: at the cap
            // a slot can free at any moment, and nothing else would wake us.
            const timeout_ms: i32 = if (saturated) saturated_poll_ms else -1;
            const nready = std.posix.poll(fds, timeout_ms) catch |e| {
                self.log.err("poll failed: {s}", .{@errorName(e)});
                return e;
            };
            if (nready == 0) continue;

            // A byte on the shutdown pipe means SIGINT/SIGTERM arrived: return
            // so the defers run their cleanup.
            if (fds[pipe_slot].revents & std.posix.POLL.IN != 0) {
                self.log.info("shutdown signal received, exiting", .{});
                self.log.info("peak concurrent clients: {d}", .{self.in_flight.peak});
                return;
            }

            // No listen socket is in the poll set while saturated, so no
            // server slot can be ready.
            if (!saturated) {
                for (self.servers, 0..) |*s, i| {
                    if (fds[i].revents & std.posix.POLL.IN == 0) continue;
                    self.acceptOne(s);
                }
            }
        }
    }

    /// Accept one client from `server`, apply ip-protection, take an admission
    /// slot, and dispatch the connection onto the pool. Every early return
    /// closes the stream and leaves the slot count unchanged.
    fn acceptOne(self: *ServerContext, server: *Io.net.Server) void {
        const stream = server.accept(self.io) catch |e| {
            self.log.warn("accept failed: {s}", .{@errorName(e)});
            return;
        };

        // ip-protection level 2: reject clients with a public IP.
        if (self.opts.ip_protection & ip_protect_reject_public != 0) {
            if (!network.isClientPrivate(stream.socket.handle)) {
                stream.close(self.io);
                self.log.debug("client with public IP address rejected", .{});
                return;
            }
        }

        // The loop checked `atCap` just before polling and is the only
        // acquirer, so this can only fail if a second acceptor appears (which
        // would also invalidate `InFlight.peak`). Drop the connection rather
        // than exceed the cap.
        if (!self.in_flight.tryAcquire()) {
            stream.close(self.io);
            self.log.warn("admission gate refused an accepted client, dropping connection", .{});
            return;
        }

        const ctx = self.gpa.create(ClientContext) catch |e| {
            stream.close(self.io);
            self.in_flight.release();
            self.log.warn("out of memory accepting client: {s}", .{@errorName(e)});
            return;
        };
        ctx.* = .{
            .stream = stream,
            .io = self.io,
            .gpa = self.gpa,
            .cfg = self.cfg,
            .prng = std.Random.DefaultPrng.init(self.prng.int(u64)),
            .port_str = self.port_str,
            .use_ndr64 = self.opts.ndr64,
            .use_btfn = self.opts.btfn,
            .disconnect_per_request = self.opts.disconnect_per_request,
            .timeout_seconds = @intCast(self.opts.timeout_seconds),
            .in_flight = &self.in_flight,
            .log = self.log,
            .quiet_loopback = self.opts.quiet_loopback,
        };

        self.conn_group.concurrent(self.io, serveClientThread, .{ctx}) catch |e| {
            ctx.stream.close(self.io);
            self.gpa.destroy(ctx);
            self.in_flight.release();
            self.log.warn("failed to dispatch client task: {s}", .{@errorName(e)});
        };
    }
};

/// Report a fatal startup error and exit. `std.process.exit` skips the deferred
/// cleanup, so the log queue is drained explicitly — otherwise the message the
/// operator needs would still be sitting in the queue.
fn fatal(log: *cli_helper.Logger, io: Io, comptime fmt: []const u8, args: anytype) noreturn {
    log.err(fmt, args);
    log.shutdown(io);
    std.process.exit(1);
}

pub fn main(init: std.process.Init) !void {
    // Collect the raw arguments (skip argv[0]).
    var args_list: std.ArrayList([]const u8) = .empty;
    defer args_list.deinit(init.gpa);
    var args_iter: std.process.Args.Iterator = .init(init.minimal.args);
    _ = args_iter.skip();
    while (args_iter.next()) |arg| {
        try args_list.append(init.gpa, arg);
    }

    var res = cli_helper.parse(init.gpa, &vlmzsd_opts, args_list.items) catch |err| {
        // Short diagnostic; the full help is one `--help` away.
        var ebuf: [256]u8 = undefined;
        var ew = std.Io.File.writer(std.Io.File.stderr(), init.io, &ebuf);
        ew.interface.print("vlmzsd: error: {s}\n", .{@errorName(err)}) catch {};
        ew.interface.flush() catch {};
        std.process.exit(1);
    };
    defer res.deinit();

    if (res.hasFlag("help")) {
        var hbuf: [4096]u8 = undefined;
        var hw = std.Io.File.writer(std.Io.File.stderr(), init.io, &hbuf);
        try cli_helper.writeHelp(&hw.interface, "vlmzsd", &vlmzsd_opts, "");
        try hw.interface.flush();
        return;
    }
    if (res.hasFlag("version")) {
        var buf: [64]u8 = undefined;
        var fw = std.Io.File.writer(std.Io.File.stdout(), init.io, &buf);
        try fw.interface.print("vlmzsd {s} ({s} {s})\n", .{ version, git_hash, build_date });
        try fw.interface.flush();
        return;
    }

    var out_buf: [4096]u8 = undefined;
    var err_buf: [4096]u8 = undefined;
    var log: cli_helper.Logger = try cli_helper.Logger.init(init.gpa, init.io, &out_buf, &err_buf);
    defer log.deinit(init.gpa);

    // Start the log writer before anything can log: `fatal` drains the queue on
    // the way out, and a queue with no consumer would block that drain. The
    // separate group lets shutdown drain it *after* the connection tasks have
    // stopped, so lines they logged on the way out still reach the sink.
    var log_group: Io.Group = .init;
    defer log_group.cancel(init.io);
    defer log.shutdown(init.io);
    log_group.concurrent(init.io, cli_helper.Logger.writerLoop, .{&log}) catch |e| {
        // Degraded mode: the pool refused the task, so log synchronously.
        log.direct = true;
        log.warn("failed to start log writer task: {s}; logging synchronously", .{@errorName(e)});
    };

    var opts = resolveOptions(init.gpa, init.environ_map, &res) catch |e| {
        fatal(&log, init.io, "invalid configuration: {s}", .{@errorName(e)});
    };
    defer opts.deinit(init.gpa);
    log.min_level = if (opts.quiet) .warn else if (opts.verbose) .debug else .info;

    // Load the KMS data: explicit path (--data / VLMZSD_DATA) → FHS/XDG search
    // → embedded default.
    var kmd_owned = false;
    var kmd_raw: []const u8 = undefined;
    var loaded_from: ?[]const u8 = null; // null = embedded
    var fhs_loaded: ?cli_helper.FhsKmd = null;
    defer if (fhs_loaded) |*f| {
        init.gpa.free(f.path);
        init.gpa.free(f.data);
    };
    if (opts.data_file) |path| {
        kmd_raw = std.Io.Dir.readFileAlloc(std.Io.Dir.cwd(), init.io, path, init.gpa, .unlimited) catch |e| {
            fatal(&log, init.io, "failed to read data file {s}: {s}", .{ path, @errorName(e) });
        };
        kmd_owned = true;
        loaded_from = path;
    } else {
        fhs_loaded = cli_helper.loadFhsKmd(init.io, init.gpa, init.minimal.environ) catch |e| {
            fatal(&log, init.io, "failed to read FHS data file: {s}", .{@errorName(e)});
        };
        if (fhs_loaded) |*f| {
            kmd_raw = f.data;
            loaded_from = f.path;
        } else if (embedded_kmd.len > 0) {
            kmd_raw = embedded_kmd;
        } else {
            fatal(&log, init.io, "no KMS data found; specify --data <file>", .{});
        }
    }
    defer if (kmd_owned) init.gpa.free(@constCast(kmd_raw));

    var data = kmsdata.parse(init.gpa, kmd_raw) catch |e| {
        fatal(&log, init.io, "invalid KMS data: {s}", .{@errorName(e)});
    };
    defer data.deinit(init.gpa);

    if (loaded_from) |path| {
        log.info("loaded KMS data from {s}", .{path});
    } else {
        log.debug("using embedded KMS data", .{});
    }

    var prng: std.Random.DefaultPrng = .init(cli_helper.makeSeed(init.io));
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
    // host's private addresses; otherwise `--listen` (default ::, a dual-stack
    // socket covering both IPv4 and IPv6).
    var servers: std.ArrayList(Io.net.Server) = .empty;
    defer {
        for (servers.items) |*s| s.deinit(init.io);
        servers.deinit(init.gpa);
    }
    try createListenSockets(init.gpa, init.io, &opts, &log, &servers);

    log.info("vlmzsd {s} listening on port {d}", .{ version, opts.port });
    if (opts.max_clients == 0) {
        log.warn("client cap disabled: concurrent client tasks are unbounded", .{});
    } else {
        log.info("client cap: {d} concurrent clients", .{opts.max_clients});
    }

    // Write the PID file (best effort; mirrors the C `writePidFile`, which
    // only logs on failure).
    if (opts.pid_file) |path| {
        var pid_buf: [pid_str_buffer_size]u8 = undefined;
        const pid_str = try std.fmt.bufPrint(&pid_buf, "{d}", .{std.c.getpid()});
        std.Io.Dir.writeFile(std.Io.Dir.cwd(), init.io, .{
            .sub_path = path,
            .data = pid_str,
        }) catch |e| log.warn("failed to write pid file {s}: {s}", .{ path, @errorName(e) });
    }

    // The client cap is enforced by `ServerContext.in_flight`, an admission
    // gate checked *before* `accept`. It is not delegated to the pool:
    // `std.Io.Threaded` never reclaims an idle worker (they live until
    // `deinit`), and `std.process.Init` does not expose its options, so the
    // bound has to be our own invariant.

    if (servers.items.len > max_listen_sockets) {
        fatal(&log, init.io, "too many listen sockets (max {d})", .{max_listen_sockets});
    }

    // Signals first, so the shutdown pipe outlives its waiters and its close
    // runs after the connection group joins (defers run in reverse). Reads no
    // longer poll the pipe — they are canceled through `Io` — but the accept
    // loop does, and keeping the order rules out a close-before-join bug.
    installSignalHandlers(init.io, &log);
    defer {
        _ = std.c.close(shutdown_pipe[0]);
        _ = std.c.close(shutdown_pipe[1]);
    }

    // Long-lived group for the connection tasks. Each task's resources are
    // released when it returns; canceling the group on shutdown asks in-flight
    // tasks to stop and waits for their cleanup, which is also what lets the
    // log queue drain afterwards (see the `log_group` defers above).
    var conn_group: Io.Group = .init;
    defer conn_group.cancel(init.io);

    var server: ServerContext = .{
        .gpa = init.gpa,
        .io = init.io,
        .opts = &opts,
        .log = &log,
        .cfg = &cfg,
        .servers = servers.items,
        .in_flight = .{ .cap = opts.max_clients },
        .conn_group = &conn_group,
        .port_str = port_str,
        .prng = rng,
    };
    try server.run();
}

test "InFlight admits up to the cap, then refuses without leaking slots" {
    var gate: InFlight = .{ .cap = 2 };
    try std.testing.expectEqual(@as(u32, 0), gate.count.load(.acquire));
    try std.testing.expect(!gate.atCap());

    try std.testing.expect(gate.tryAcquire());
    try std.testing.expect(!gate.atCap());
    try std.testing.expect(gate.tryAcquire());
    try std.testing.expect(gate.atCap());

    // The refusal must not consume a slot: a third acquire still fails, and
    // the count still matches the two live tasks.
    try std.testing.expect(!gate.tryAcquire());
    try std.testing.expectEqual(@as(u32, 2), gate.count.load(.acquire));

    gate.release();
    try std.testing.expect(!gate.atCap());
    try std.testing.expect(gate.tryAcquire());
    try std.testing.expectEqual(@as(u32, 2), gate.count.load(.acquire));

    gate.release();
    gate.release();
    try std.testing.expectEqual(@as(u32, 0), gate.count.load(.acquire));
}

test "InFlight peak survives idle periods" {
    var gate: InFlight = .{ .cap = 8 };
    try std.testing.expectEqual(@as(u32, 0), gate.peak);

    var round: u32 = 0;
    while (round < 3) : (round += 1) {
        try std.testing.expect(gate.tryAcquire());
        try std.testing.expect(gate.tryAcquire());
        try std.testing.expect(gate.tryAcquire());
        try std.testing.expectEqual(@as(u32, 3), gate.peak);

        gate.release();
        gate.release();
        gate.release();
        // Idle again: the high-water mark is what shutdown reports, so it must
        // not be reset when the count drops.
        try std.testing.expectEqual(@as(u32, 0), gate.count.load(.acquire));
        try std.testing.expectEqual(@as(u32, 3), gate.peak);
    }

    // A wider burst advances the mark; the earlier 3 is not sticky.
    const four = [_]u32{ 1, 2, 3, 4 };
    for (four) |_| try std.testing.expect(gate.tryAcquire());
    try std.testing.expectEqual(@as(u32, 4), gate.peak);
    for (four) |_| gate.release();
    try std.testing.expectEqual(@as(u32, 0), gate.count.load(.acquire));
    try std.testing.expectEqual(@as(u32, 4), gate.peak);
}

test "InFlight cap of 0 is unlimited" {
    var gate: InFlight = .{ .cap = 0 };
    try std.testing.expect(!gate.atCap());

    var i: u32 = 0;
    while (i < 1000) : (i += 1) {
        try std.testing.expect(gate.tryAcquire());
        try std.testing.expect(!gate.atCap());
    }
    try std.testing.expectEqual(@as(u32, 1000), gate.count.load(.acquire));
    try std.testing.expectEqual(@as(u32, 1000), gate.peak);

    while (i > 0) : (i -= 1) gate.release();
    try std.testing.expectEqual(@as(u32, 0), gate.count.load(.acquire));
}
