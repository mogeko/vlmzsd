//! `vlmzsd` — the KMS server binary.
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
const version_display = build_options.version_display;
const default_port: u16 = 1688;

/// `--ip-protection` bit masks (docs/cli.md §5).
const ip_protect_private_listen: u8 = 1; // listen only on private addresses
const ip_protect_reject_public: u8 = 2; // reject clients with public IPs

/// Maximum listen sockets; also the width of the accept loop's armed-socket
/// bit set, which is why its select result buffer is `max_listen_sockets + 2`.
const max_listen_sockets = 64;
/// Longest decimal PID string (generous upper bound).
const pid_str_buffer_size = 16;

/// Default `--max-clients` cap. Bounds the concurrent client tasks, and with
/// them the pooled threads: `std.Io.Threaded` neither reclaims idle workers nor
/// reports its options (see `ServerContext.in_flight`). `0` still means
/// "unlimited" (docs/cli.md §5).
const default_client_cap: u32 = 1024;

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
    .{ .name = "lcid", .kind = .int, .hint = "u32", .group = "ePID", .desc = "Fixed LCID for randomized ePIDs, 0-32767 (0 = random)" },
    .{ .name = "build", .kind = .int, .hint = "u32", .group = "ePID", .desc = "Fixed build number for randomized ePIDs, 0-65535 (0 = random)" },
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
    .{ .name = "verbose", .short = 'v', .group = "Process", .desc = "Increase log verbosity, repeatable (-v debug, -vv trace)", .repeatable = true },
    .{ .name = "quiet", .short = 'q', .group = "Process", .desc = "Decrease log verbosity, repeatable (-q warn, -qq err)", .repeatable = true },
    .{ .name = "quiet-loopback", .group = "Process", .desc = "Suppress debug logs for loopback (localhost) clients" },
};

/// Resolved server configuration (post three-tier precedence merge).
const ServerOptions = struct {
    port: u16 = default_port,
    listen: []const []const u8 = &.{"::"},
    timeout_seconds: u32 = 30,
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
    log_level: cli_helper.Level = .info,
    /// Raw `VLMZSD_LOG_LEVEL` value when it is set but unrecognized, so `main`
    /// can warn; the level then stays at the default `info`.
    invalid_log_level: ?[]const u8 = null,
    /// Set when the deprecated `VLMZSD_VERBOSE`/`VLMZSD_QUIET` is present in
    /// the environment, so `main` can warn even when a higher-priority source
    /// overrides it.
    legacy_verbose_present: bool = false,
    legacy_quiet_present: bool = false,
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

/// One option's value across the three tiers: built-in default < `VLMZSD_*` <
/// CLI flag. Closes over the parsed CLI, the environment map and the
/// diagnostic, so `resolveOptions` reads as a list of option names and defaults
/// instead of a repeated lookup dance.
///
/// The names are `comptime`, which is what lets the environment variable be
/// derived from the flag (`max-clients` → `VLMZSD_MAX_CLIENTS`, the convention
/// `docs/cli.md` documents) rather than written twice and drifting apart. The
/// two "disable" flags invert the meaning and pass their variable explicitly.
const Resolver = struct {
    gpa: Allocator,
    env: *const EnvironMap,
    res: *const cli_helper.Result,
    diag: *cli_helper.Diag,

    /// `port` → `--port`.
    fn flagSpelling(comptime name: []const u8) []const u8 {
        return "--" ++ name;
    }

    /// `max-clients` → `VLMZSD_MAX_CLIENTS`.
    fn envSpelling(comptime name: []const u8) []const u8 {
        return comptime blk: {
            var out: []const u8 = "VLMZSD_";
            for (name) |c| out = out ++ .{if (c == '-') '_' else std.ascii.toUpper(c)};
            break :blk out;
        };
    }

    /// The value as given, CLI first. `null` when neither source has it.
    fn raw(self: Resolver, comptime name: []const u8, comptime env_name: []const u8) ?[]const u8 {
        return self.res.get(name) orelse envGet(self.env, env_name);
    }

    /// Record `value` as rejected, under the spelling that supplied it.
    fn reject(self: Resolver, comptime name: []const u8, comptime env_name: []const u8, value: []const u8) void {
        self.diag.* = .{
            .spelling = if (self.res.get(name) != null) flagSpelling(name) else env_name,
            .value = value,
        };
    }

    fn int(self: Resolver, comptime T: type, comptime name: []const u8, default: T) !T {
        const env_name = comptime envSpelling(name);
        const text = self.raw(name, env_name) orelse return default;
        return std.fmt.parseInt(T, text, 10) catch |e| {
            self.reject(name, env_name, text);
            return e;
        };
    }

    fn str(self: Resolver, comptime name: []const u8, default: ?[]const u8) ?[]const u8 {
        return self.raw(name, envSpelling(name)) orelse default;
    }

    /// A duration in whole minutes (the KMS protocol's native unit).
    fn minutes(self: Resolver, comptime name: []const u8, default: []const u8) !u32 {
        const env_name = comptime envSpelling(name);
        const text = self.raw(name, env_name) orelse default;
        const total = cli_helper.parseDurationSeconds(text) catch |e| {
            self.reject(name, env_name, text);
            return e;
        };
        return std.math.cast(u32, total / 60) orelse error.IntervalOutOfRange;
    }

    /// A duration in whole seconds (`--timeout`).
    fn seconds(self: Resolver, comptime name: []const u8, default: []const u8) !u32 {
        const env_name = comptime envSpelling(name);
        const text = self.raw(name, env_name) orelse default;
        const total = cli_helper.parseDurationSeconds(text) catch |e| {
            self.reject(name, env_name, text);
            return e;
        };
        return std.math.cast(u32, total) orelse error.TimeoutOutOfRange;
    }

    /// A boolean the presence of a flag turns on (`--maintain-clients`).
    fn enabled(self: Resolver, comptime name: []const u8) !bool {
        return self.flagValue(name, envSpelling(name), false);
    }

    /// A boolean the presence of a flag turns off (`--no-ndr64`). Its variable
    /// keeps the positive name, so the caller passes it.
    fn disabled(self: Resolver, comptime name: []const u8, comptime env_name: []const u8, default: bool) !bool {
        return self.flagValue(name, env_name, default);
    }

    fn flagValue(self: Resolver, comptime name: []const u8, comptime env_name: []const u8, default: bool) !bool {
        if (self.res.hasFlag(name)) return !default;
        const text = envGet(self.env, env_name) orelse return default;
        return cli_helper.parseBool(text) catch |e| {
            self.diag.* = .{ .spelling = env_name, .value = text };
            return e;
        };
    }

    /// A repeatable option: CLI occurrences win, else the environment variable
    /// split on commas, else `default`. `from_env` says which, so a rejected
    /// value can be attributed to the right spelling.
    fn list(self: Resolver, comptime name: []const u8, backing: *?[]const []const u8, default: []const []const u8) !List {
        const cli = self.res.getAll(name);
        if (cli.len > 0) return .{ .items = cli, .from_env = false };
        const text = envGet(self.env, envSpelling(name)) orelse
            return .{ .items = default, .from_env = false };
        backing.* = try splitList(self.gpa, text);
        // A value with no non-empty segment leaves the default in place.
        const items = backing.*.?;
        if (items.len == 0) return .{ .items = default, .from_env = false };
        return .{ .items = items, .from_env = true };
    }

    const List = struct {
        items: []const []const u8,
        from_env: bool,
    };
};

/// The log level is the one setting with no flag to derive an environment
/// variable from: `-v`/`-q` are its CLI surface, so its variable is spelled
/// here (docs/cli.md §5 Logging). The two deprecated names are kept as a
/// lower-priority fallback and are read literally for the same reason.
const log_level_env = "VLMZSD_LOG_LEVEL";
const deprecated_verbose_env = "VLMZSD_VERBOSE";
const deprecated_quiet_env = "VLMZSD_QUIET";

/// The log level across the three-tier sources. Repeatable `-v`/`-q` are the
/// CLI surface; `VLMZSD_LOG_LEVEL` replaces the deprecated
/// `VLMZSD_VERBOSE`/`VLMZSD_QUIET`, which remain as a lower-priority fallback.
/// Any `-q` wins over `-v`: `-q` → warn, `-qq`+ → err; `-v` → debug, `-vv`+ →
/// trace.
///
/// An unrecognized `VLMZSD_LOG_LEVEL` is not fatal: it is recorded on `opts` for
/// `main` to warn about, and the level stays `info`. The value is validated even
/// when the CLI overrides it, so a typo is never silent. The deprecated
/// variables' presence is recorded the same way, so `main` can warn about them
/// too.
fn resolveLogLevel(r: Resolver, opts: *ServerOptions) !cli_helper.Level {
    opts.legacy_verbose_present = envGet(r.env, deprecated_verbose_env) != null;
    opts.legacy_quiet_present = envGet(r.env, deprecated_quiet_env) != null;

    var env_level: ?cli_helper.Level = null;
    if (envGet(r.env, log_level_env)) |s| {
        env_level = cli_helper.parseLevel(s) catch blk: {
            opts.invalid_log_level = s;
            break :blk null;
        };
    }

    const quiet_count = r.res.flagCount("quiet");
    if (quiet_count > 0) return if (quiet_count == 1) .warn else .err;
    const verbose_count = r.res.flagCount("verbose");
    if (verbose_count > 0) return if (verbose_count == 1) .debug else .trace;

    if (env_level) |level| return level;
    if (opts.invalid_log_level != null) return .info;

    // Deprecated variables keep their historical quiet-beats-verbose rule.
    const quiet = if (envGet(r.env, deprecated_quiet_env)) |s| try cli_helper.parseBool(s) else false;
    if (quiet) return .warn;
    const verbose = if (envGet(r.env, deprecated_verbose_env)) |s| try cli_helper.parseBool(s) else false;
    if (verbose) return .debug;
    return .info;
}

/// Split a comma-separated env-var value into a trimmed list. The returned
/// slice is the whole allocation, so the caller can free it with the length it
/// received. Empty and whitespace-only segments are skipped.
fn splitList(gpa: Allocator, s: []const u8) ![]const []const u8 {
    var count: usize = 0;
    var scan = std.mem.splitScalar(u8, s, ',');
    while (scan.next()) |item| {
        if (std.mem.trim(u8, item, " \t").len > 0) count += 1;
    }

    const out = try gpa.alloc([]const u8, count);
    var it = std.mem.splitScalar(u8, s, ',');
    var i: usize = 0;
    while (it.next()) |item| {
        const trimmed = std.mem.trim(u8, item, " \t");
        if (trimmed.len == 0) continue;
        out[i] = trimmed;
        i += 1;
    }
    std.debug.assert(i == count);
    return out;
}

/// Resolve every option into a `ServerOptions`. The whole configuration surface
/// is the list below: one name and one default per option.
fn resolveOptions(r: Resolver) !ServerOptions {
    // `vlmzsd` takes options only; a stray word is a mistyped flag value, not
    // something to ignore.
    if (r.res.positionals.items.len > 0) return error.UnexpectedPositional;

    const gpa = r.gpa;
    var opts = ServerOptions{};
    // The env-var lists own memory, so every error below releases them.
    errdefer opts.deinit(gpa);

    opts.port = try r.int(u16, "port", default_port);

    const listen = try r.list("listen", &opts.listen_backing, &.{"::"});
    opts.listen = listen.items;
    // Each entry must be an IP literal: the port has its own option, so a
    // value that parses only as `address:port` is a mistake to report here
    // rather than at bind time.
    for (opts.listen) |addr| {
        _ = Io.net.IpAddress.parse(addr, opts.port) catch {
            r.diag.* = .{
                .spelling = if (listen.from_env)
                    Resolver.envSpelling("listen")
                else
                    Resolver.flagSpelling("listen"),
                .value = addr,
            };
            return error.InvalidListenAddress;
        };
    }

    opts.timeout_seconds = try r.seconds("timeout", "30s");
    opts.max_clients = try r.int(u32, "max-clients", default_client_cap);
    opts.data_file = r.str("data", null);

    const epids = try r.list("epid", &opts.epid_backing, &.{});
    opts.epids = epids.items;

    opts.randomize = try r.int(u8, "randomize", 1);
    opts.lcid = try r.int(u32, "lcid", 0);
    if (opts.lcid > kms.max_lcid) return error.LcidOutOfRange;
    opts.build = try r.int(u32, "build", 0);
    if (opts.build > kms.max_build) return error.BuildOutOfRange;

    opts.activation_interval_minutes = try r.minutes("activation-interval", "2h");
    opts.renewal_interval_minutes = try r.minutes("renewal-interval", "7d");
    opts.whitelist = try r.int(u32, "whitelist", 0);
    opts.ip_protection = try r.int(u8, "ip-protection", 0);

    opts.check_client_time = try r.enabled("check-client-time");
    opts.maintain_clients = try r.enabled("maintain-clients");
    opts.start_empty = try r.enabled("start-empty");

    // The "disable" flags read the positive variable (`--no-ndr64` ←
    // `VLMZSD_NDR64`), so they spell it out.
    opts.ndr64 = try r.disabled("no-ndr64", "VLMZSD_NDR64", true);
    opts.btfn = try r.disabled("no-btfn", "VLMZSD_BTFN", true);
    opts.disconnect_per_request = try r.enabled("disconnect-per-request");

    opts.pid_file = r.str("pid-file", null);
    opts.log_level = try resolveLogLevel(r, &opts);
    opts.quiet_loopback = try r.enabled("quiet-loopback");

    return opts;
}

/// Find a CSVLC index by its human-readable name (used by `--epid name=epid`).
fn findCsvlkByName(data: *const kmsdata.KmsData, name: []const u8) ?usize {
    for (data.csvlk, 0..) |csvlk, i| {
        if (std.mem.eql(u8, csvlk.name, name)) return i;
    }
    return null;
}

/// Store `epid` as the override for CSVLC `idx`, releasing the value an earlier
/// `--epid` entry put there, so a repeated name keeps the last ePID.
fn putOverride(gpa: Allocator, overrides: []?[]const u8, idx: usize, epid: []const u8) !void {
    if (overrides[idx]) |previous| gpa.free(previous);
    overrides[idx] = null;
    overrides[idx] = try gpa.dupe(u8, epid);
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
    errdefer {
        for (overrides) |slot| if (slot) |s| gpa.free(s);
        gpa.free(overrides);
    }
    @memset(overrides, null);

    // 1. `--epid <name>=<epid>` overrides.
    for (opts.epids) |entry| {
        const eq = std.mem.indexOfScalar(u8, entry, '=') orelse {
            log.warn("ignoring malformed --epid entry (expected name=epid): {s}", .{entry});
            continue;
        };
        const name = entry[0..eq];
        const epid = entry[eq + 1 ..];
        if (epid.len == 0) {
            // An empty ePID would be answered to clients as a blank product
            // key; it is a malformed entry, not an override.
            log.warn("ignoring --epid with an empty ePID: {s}", .{name});
            continue;
        }
        const idx = findCsvlkByName(data, name) orelse {
            log.warn("ignoring --epid for unknown CSVLC name: {s}", .{name});
            continue;
        };
        // A repeated name keeps the last ePID; the earlier one is ours to free.
        try putOverride(gpa, overrides, idx, epid);
    }

    // 2. Level-1 pre-randomization: one shared random build and one shared
    //    random LCID, per-CSVLC random key ID (only when the CSVLC has no
    //    --epid override).
    if (opts.randomize == 1) {
        const lang: i16 = if (opts.lcid != 0) @intCast(opts.lcid) else @intCast(kms.randomLcid(rng));
        var host_build: i32 = if (opts.build != 0) @intCast(opts.build) else 0;
        for (overrides, 0..) |*slot, i| {
            if (slot.* != null) continue;
            if (host_build == 0) host_build = kms.randomHostBuild(data, rng, opts.ndr64) orelse return error.NoHostBuild;
            var buf: [kms.pid_buffer_size]u8 = undefined;
            const pid = try kms.generateRandomPid(data, i, &buf, lang, host_build, rng, opts.ndr64, now_unix);
            slot.* = try gpa.dupe(u8, pid);
        }
    }

    return overrides;
}

/// Admission gate for concurrent client tasks, rather than a blocking
/// `Io.Semaphore` wait: `Io.Semaphore` offers no non-blocking query, so the
/// accept loop could not ask "is there room?" *before* arming an accept, and
/// would sit in `waitUncancelable` (not a cancelation point) after every extra
/// `accept`.
///
/// Invariant: the accept loop is the sole acquirer, which is what lets `peak`
/// be a plain counter. A second acceptor would also need a CAS loop for it (and
/// could race the cap check in `admit`).
const InFlight = struct {
    count: std.atomic.Value(u32) = .init(0),
    /// Maximum concurrent client tasks; `0` means unlimited.
    cap: u32,
    /// High-water mark of `count`; written only by the accept loop.
    peak: u32 = 0,
    /// Set by `release`, waited on by the accept loop while it is parked at the
    /// cap. Sticky until `reset`, so a set that races the loop's gate check is
    /// still seen by its next `wait` — nothing to miss.
    slot_free: Io.Event = .unset,

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
    /// successful acquire. Wakes the accept loop if it is parked at the cap; a
    /// `set` with no waiter is harmless, because the loop resets it before
    /// re-reading the gate.
    fn release(self: *InFlight, io: Io) void {
        const previous = self.count.fetchSub(1, .acq_rel);
        std.debug.assert(previous > 0);
        self.slot_free.set(io);
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
    /// Local port reported in this connection's BIND_ACK, formatted here
    /// because `--port 0` gives every listen socket its own port.
    port_str: []const u8,
    port_buf: [6]u8 = undefined,
    use_ndr64: bool,
    use_btfn: bool,
    disconnect_per_request: bool,
    timeout_seconds: u32,
    /// Association group id echoed in this connection's BIND/ALTER-CONTEXT
    /// responses (non-zero, one per connection — C `RpcAssocGroup++`).
    rpc_assoc_group: u32,
    in_flight: *InFlight,
    tally: *ThreadTally,
    log: *cli_helper.Logger,
    /// Peer address ("host:port") formatted into `peer_buf` on entry, so every
    /// protocol event can name the connection it belongs to.
    peer_buf: [64]u8 = undefined,
    peer: []const u8 = "",
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
        .packet => |p| {
            if (!ctx.quiet) ctx.log.trace("{s}: RPC packet type {d}, frag_length {d}", .{ ctx.peer, p.packet_type, p.frag_length });
        },
        .bind_negotiated => |ndr64| {
            if (!ctx.quiet) ctx.log.debug("{s}: BIND: negotiated {s}", .{ ctx.peer, if (ndr64) "NDR64" else "NDR32" });
        },
        .fault => |nca| ctx.log.warn("{s}: RPC fault (NCA 0x{X:0>8})", .{ ctx.peer, nca }),
        .request_rejected => |r| {
            if (r.major != 0) {
                ctx.log.warn("{s}: KMS v{d} request rejected (HRESULT 0x{X:0>8})", .{ ctx.peer, r.major, r.hr });
            } else {
                ctx.log.warn("{s}: invalid KMS request rejected (HRESULT 0x{X:0>8})", .{ ctx.peer, r.hr });
            }
        },
        .response => |r| {
            if (!ctx.quiet) ctx.log.debug("{s}: KMS v{d} request → {d}-byte response", .{ ctx.peer, r.major, r.size });
        },
    }
}

/// Log the single close line that pairs with the `accepted` line. Every close
/// goes through here, so the phrasing cannot drift between paths:
/// `connection from <peer> closed <cause>`.
fn logClosed(ctx: *ClientContext, comptime cause: []const u8, args: anytype) void {
    if (ctx.quiet) return;
    ctx.log.debug("connection from {s} closed " ++ cause, .{ctx.peer} ++ args);
}

/// The log writer's task. It is counted but not announced: it starts before the
/// resolved log level is applied, so its own start line would be filtered out at
/// `-v` (or, worse, appear at random depending on the schedule), and `main`
/// announces the role once the level is known instead.
fn logWriterTask(log: *cli_helper.Logger, tally: *ThreadTally) void {
    stated_pool_thread = true;
    _ = tally.total.fetchAdd(1, .monotonic);
    cli_helper.Logger.writerLoop(log);
}

/// Which server tasks have already announced the calling thread. Every pool
/// thread runs at least one of them, so counting first uses per thread counts
/// the pool exactly, with no registry to keep and no lock on the path.
threadlocal var stated_pool_thread = false;
threadlocal var stated_client_thread = false;

/// The pool's threads, as this process has observed them. `std.Io.Threaded`
/// spawns a worker when a task is dispatched and none is idle, and never
/// reclaims one, so a thread's first task is its only lifecycle event: it is
/// created on demand and lives until the process exits. Counting first uses
/// therefore yields the process's thread count after adding the main thread —
/// no estimate, and no gap for the threads that only ever ran an `accept`, the
/// shutdown read, or the log writer.
const ThreadTally = struct {
    /// Every pool thread that has run a server task.
    total: std.atomic.Value(u32) = .init(0),
    /// The subset that has served a client, which is what scales with load.
    clients: std.atomic.Value(u32) = .init(0),
};

/// Report the calling thread when it runs a server task: once when the thread
/// itself is first seen, and once more when it first serves a client. Both are
/// needed — a thread usually starts out on an `accept` and is then handed the
/// connection it accepted. Each event has exactly one wording, so `serving
/// clients` lines count client worker threads and `started` lines count the
/// pool's non-client threads. When a thread debuts on a connection the second
/// line carries both facts and the first one is skipped.
///
/// The id is the OS thread id — `gettid` on Linux, so it matches `ps -L` and
/// `/proc/<pid>/task/<tid>`, and `pthread_threadid_np` on macOS, the id
/// `sample`/`spindump` and crash reports show.
fn notePoolThread(tally: *ThreadTally, log: *cli_helper.Logger, comptime serving_client: bool) void {
    const new_thread = !stated_pool_thread;
    const new_client = serving_client and !stated_client_thread;
    if (!new_thread and !new_client) return;

    const thread_id = std.Thread.getCurrentId();
    if (new_thread) {
        stated_pool_thread = true;
        _ = tally.total.fetchAdd(1, .monotonic);
    }
    const threads = tally.total.load(.monotonic);
    if (!new_client) {
        log.debug("pool worker {d} started (pool threads: {d})", .{ thread_id, threads });
        return;
    }
    stated_client_thread = true;
    const clients = tally.clients.fetchAdd(1, .monotonic) + 1;
    log.debug(
        "pool worker {d} serving clients (client workers: {d}, pool threads: {d})",
        .{ thread_id, clients, threads },
    );
}

/// Wall clock for one connection's requests: `serveRpc` calls this before
/// dispatching each REQUEST, so the timestamp checks see the current time.
fn clientNowUnix(context: ?*anyopaque) i64 {
    const ctx: *const ClientContext = @ptrCast(@alignCast(context.?));
    return cli_helper.nowUnix(ctx.io);
}

/// Serve one connection as a pooled task (dispatched via `Group.concurrent`).
/// Releases its admission slot and frees the context on exit.
fn serveClientThread(ctx: *ClientContext) void {
    defer {
        ctx.stream.close(ctx.io);
        // Copy the gate out before `destroy` invalidates `ctx`, and release
        // last: the count must never lag behind the resources it accounts for,
        // or the accept loop could admit a client over the cap.
        const io = ctx.io;
        const in_flight = ctx.in_flight;
        ctx.gpa.destroy(ctx);
        in_flight.release(io);
    }

    // Only when --quiet-loopback is on, and only for loopback peers (the
    // container HEALTHCHECK): suppress debug chatter; warn/err still logs.
    ctx.quiet = ctx.quiet_loopback and network.isLoopbackPeer(ctx.stream.socket.handle);
    ctx.peer = network.formatPeer(ctx.stream.socket.handle, &ctx.peer_buf);
    // Before the connection line, and regardless of `quiet`: this reports the
    // thread, not the connection.
    notePoolThread(ctx.tally, ctx.log, true);
    if (!ctx.quiet) ctx.log.debug("connection from {s} accepted", .{ctx.peer});

    // `rbuf` is the packet reader's read-ahead (`.read_ahead` below): a header
    // and its body usually arrive in one segment, so one read fills it and the
    // rest of the packet is served from memory. Reads on a connected socket go
    // through `.idle.peer`, so the `Io.Reader` argument is only the fallback
    // for sources without one (the tests) and stays empty here.
    var rbuf: [4096]u8 = undefined;
    var wbuf: [4096]u8 = undefined;
    var reader = Io.Reader.fixed("");
    var writer = ctx.stream.writer(ctx.io, &wbuf);

    const end: network.ServeEnd = network.serveRpc(ctx.gpa, &reader, &writer.interface, ctx.prng.random(), .{
        .cfg = ctx.cfg,
        // Sampled per request, so `--check-client-time` and level-2 ePIDs follow
        // a keep-alive connection instead of measuring against the accept time.
        .clock = .{ .context = ctx, .nowUnix = clientNowUnix },
        .on_event = logProtocolEvent,
        .event_context = ctx,
        .secondary_address = ctx.port_str,
        .rpc_assoc_group = ctx.rpc_assoc_group,
        .use_ndr64 = ctx.use_ndr64,
        .use_btfn = ctx.use_btfn,
        .disconnect_per_request = ctx.disconnect_per_request,
        // Reads go through `Io.operateTimeout(.net_receive)`: the backend owns
        // the deadline and the cancelation point, so SIGINT/SIGTERM ends every
        // parked read at once.
        .idle = .{ .peer = .{
            .io = ctx.io,
            .handle = ctx.stream.socket.handle,
            .timeout = network.timeoutSeconds(ctx.timeout_seconds),
        } },
        .read_ahead = &rbuf,
    }) catch |e| switch (e) {
        error.Timeout => {
            // Nothing arrived for `--timeout` seconds (the C `SO_RCVTIMEO`).
            // The connection is not broken and the last request was answered:
            // this is an idle cleanup, not a failure.
            logClosed(ctx, "after {d}s idle", .{ctx.timeout_seconds});
            return;
        },
        error.Canceled => {
            // The read wait is a backend cancelation point, so a cancelation
            // request (shutdown) ends it directly: a clean exit, not a failure.
            logClosed(ctx, "at shutdown", .{});
            return;
        },
        error.ConnectionResetByPeer, error.SocketUnconnected => {
            // The client aborted the connection (a RST, not a FIN): it gave up
            // on a slow server, or a probe/firewall/EDR reset it. `send` to a
            // peer that already left reports EPIPE, which the socket layer
            // folds into `SocketUnconnected`, so the same client behaviour can
            // surface from the write path. Like `closed by peer`, this is how a
            // connection ends — not a server fault — so it keeps the close-line
            // phrasing and level, with the error name kept for diagnosis.
            logClosed(ctx, "by peer ({s})", .{@errorName(e)});
            return;
        },
        else => {
            ctx.log.warn("connection from {s} error: {s}", .{ ctx.peer, @errorName(e) });
            return;
        },
    };

    // `serveRpc` reports why it stopped, so every connection gets exactly one
    // close line, paired with the `accepted` line above.
    switch (end) {
        .peer_closed => logClosed(ctx, "by peer", .{}),
        .unsupported_packet => logClosed(ctx, "on unsupported RPC packet type", .{}),
        .after_request => logClosed(ctx, "after request", .{}),
    }
}

/// Self-pipe write end (`[1]`): the SIGINT/SIGTERM handler writes one byte here
/// (async-signal-safe) to announce the signal. The read end (`[0]`) is the
/// input of a shutdown task parked in an `Io` read inside the accept loop's
/// `Io.Select` (see `shutdownTask`), so the handler does no cleanup itself and
/// the normal control flow (with its defers) runs the shutdown. The pipe is the
/// one piece of unavoidable global state: a handler cannot take a context
/// pointer, and `Io.Event.set` is a vtable call, so the wake-up has to be a
/// plain `write`.
///
/// The first signal ends the shutdown task and the accept loop runs the
/// shutdown; a second one exits hard from the handler itself (see
/// `handleShutdown`).
var shutdown_pipe: [2]std.posix.fd_t = .{ -1, -1 };

/// A second SIGINT/SIGTERM abandons the drain and exits hard; the first one is
/// the graceful path.
const force_exit_signal_count: u32 = 2;

/// Shutdown signals seen so far. Written only by `handleShutdown`, which two
/// threads can run concurrently (a signal is delivered to an arbitrary thread),
/// so the increment must be atomic. `u32` is lock-free on every supported
/// target, so this is async-signal-safe.
var shutdown_signals: std.atomic.Value(u32) = .init(0);

/// Record one shutdown signal; `false` means the operator asked again, so the
/// caller must exit without draining. Parameterised on the counter rather than
/// reading the global directly, so tests can exercise the policy without
/// touching signals, the pipe, or `_exit`.
fn noteShutdownSignal(counter: *std.atomic.Value(u32)) bool {
    return counter.fetchAdd(1, .monotonic) + 1 < force_exit_signal_count;
}

fn handleShutdown(sig: std.posix.SIG) callconv(.c) void {
    if (!noteShutdownSignal(&shutdown_signals)) {
        // `std.process.exit` would run atexit handlers and flush stdio, which
        // is not async-signal-safe; `_exit` is. Nothing is printed on purpose:
        // a second signal usually exists because the log sink is blocked, and a
        // `write` would block on that same sink — the exit code (`128 + signum`)
        // is the only channel still guaranteed to work.
        std.c._exit(128 + @as(c_int, @intCast(@backingInt(sig))));
    }
    // Wake the accept loop: one byte, which its shutdown task receives from an
    // `Io` read. A flag alone would not work: nobody is parked on it.
    const byte: [1]u8 = .{1};
    _ = std.c.write(shutdown_pipe[1], &byte, 1);
}

/// The self-pipe's ends as `Io` handles, so the read side and the close path
/// agree on their flags: the read end stays blocking (its waiter is meant to
/// park), the write end is non-blocking (see `installSignalHandlers`).
fn shutdownPipeFile(comptime end: enum { read, write }) Io.File {
    return switch (end) {
        .read => .{ .handle = shutdown_pipe[0], .flags = .{ .nonblocking = false } },
        .write => .{ .handle = shutdown_pipe[1], .flags = .{ .nonblocking = true } },
    };
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

/// Bit `index` of the accept loop's armed-socket set.
fn armedBit(index: usize) u64 {
    std.debug.assert(index < max_listen_sockets);
    return @as(u64, 1) << @intCast(index);
}

/// What wakes the accept loop. `Io.Select` reports the first task to finish,
/// so a signal, a new client, and a freed admission slot all arrive here.
const AcceptWake = union(enum) {
    /// One byte from the self-pipe: SIGINT/SIGTERM arrived.
    shutdown: [1]u8,
    /// A listen socket produced a client (or an `accept` error to report).
    client: AcceptOutcome,
    /// The loop was parked at the client cap and a task released its slot.
    slot_free: void,
};

/// One `accept` result, tagged with the socket it came from.
const AcceptOutcome = union(enum) {
    accepted: struct { server: usize, stream: Io.net.Stream },
    failed: struct { server: usize, err: Io.net.Server.AcceptError },
};

/// One `accept` on the listen socket at `server_index`: one task, one client,
/// so the loop handles, and re-arms, each socket once per connection. A blocked
/// `accept` is a task whose thread the backend can interrupt, which is why it
/// can be one of the select's waiters.
fn acceptTask(self: *ServerContext, server_index: usize) AcceptOutcome {
    notePoolThread(self.tally, self.log, false);
    const stream = self.servers[server_index].accept(self.io) catch |err| return .{
        .failed = .{ .server = server_index, .err = err },
    };
    return .{ .accepted = .{ .server = server_index, .stream = stream } };
}

/// Park until the signal handler's byte reaches the shutdown pipe. The read is
/// a cancelable `Io` operation, so the select's cancel path ends it if the loop
/// stops without a signal; the byte itself is irrelevant, only its arrival is.
fn shutdownTask(io: Io, pipe: Io.File, tally: *ThreadTally, log: *cli_helper.Logger) [1]u8 {
    notePoolThread(tally, log, false);
    var byte: [1]u8 = .{0};
    var buffer: [1]u8 = undefined;
    var reader = pipe.readerStreaming(io, &buffer);
    _ = reader.interface.readSliceShort(&byte) catch 0;
    return byte;
}

/// Park until a client task frees an admission slot.
fn slotFreeTask(io: Io, gate: *InFlight, tally: *ThreadTally, log: *cli_helper.Logger) void {
    notePoolThread(tally, log, false);
    gate.slot_free.wait(io) catch {};
}

/// State shared by the accept loop: everything it needs to wait on the listen
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
    /// Shared with the log writer task: a copy here would count the writer's
    /// thread into a struct nobody reports.
    tally: *ThreadTally,
    conn_group: *Io.Group,
    prng: std.Random,
    /// Next association group id; seeded non-zero (C `RpcAssocGroup = rand32()`).
    assoc_group: u32,

    /// Accept and dispatch clients until SIGINT/SIGTERM arrives.
    ///
    /// One `Io.Select` owns every wait, one waiter per wake-up source: a
    /// shutdown reader (the handler's byte on the self-pipe), one `accept` per
    /// listen socket (re-armed after each result), and — while the client cap
    /// is reached — an admission-gate event that `InFlight.release` sets.
    /// `await` returns whichever completes first, so the loop blocks in one
    /// place and always has something to act on.
    ///
    /// Each waiter is a `concurrent` task, never `async`: `async` may run a
    /// task inline, and an `accept` parked on this thread could not observe a
    /// cancelation request.
    fn run(self: *ServerContext) !void {
        std.debug.assert(self.servers.len <= max_listen_sockets);

        // One result slot per possibly-outstanding task: the shutdown read,
        // one `accept` per listen socket, and at most one gate wait. An
        // undersized buffer would deadlock `Select.cancel`.
        var wakes: [max_listen_sockets + 2]AcceptWake = undefined;
        var select: Io.Select(AcceptWake) = .init(self.io, &wakes);
        defer {
            // `cancel` rather than `cancelDiscard`: a completed accept may still
            // sit in the queue holding an open stream, so drain and close what
            // the tasks produced instead of dropping it.
            while (select.cancel()) |wake| switch (wake) {
                .client => |outcome| switch (outcome) {
                    .accepted => |client| client.stream.close(self.io),
                    .failed => {},
                },
                .shutdown, .slot_free => {},
            };
        }

        const pipe: Io.File = shutdownPipeFile(.read);
        const tally: *ThreadTally = self.tally;
        select.concurrent(.shutdown, shutdownTask, .{ self.io, pipe, tally, self.log }) catch |e| {
            // Without this waiter the loop could never stop on a signal.
            self.log.err("failed to start shutdown reader: {s}", .{@errorName(e)});
            return e;
        };

        // Bit `i` is set while server `i` has an accept task in flight. An
        // armed socket stays armed until its accept reports, so the loop never
        // dispatches a second one for the same socket.
        var armed: u64 = 0;
        var slot_free_armed = false;
        var saturated = false;

        while (true) {
            // Admission control runs *before* arming accepts: while the cap is
            // reached, the listen sockets have no accept task, so excess
            // connections wait in the kernel backlog (TCP backpressure)
            // instead of being accepted into a worker that has nowhere to go.
            const at_cap = self.in_flight.atCap();
            if (at_cap != saturated) {
                saturated = at_cap;
                // One warn per saturation period: saturation is a property of
                // the period, not of each wake-up.
                if (saturated) self.log.warn("client cap reached ({d}), deferring accept", .{self.in_flight.cap});
            }

            if (!saturated) {
                try self.armAccepts(&select, &armed);
            } else if (!slot_free_armed) {
                // Reset, *then* re-read the gate: a release before this read
                // lowers the count (so the loop accepts at once), and one after
                // it sets the event (so the wait returns at once). This order
                // makes the wake-up neither losable nor able to spin.
                self.in_flight.slot_free.reset();
                if (!self.in_flight.atCap()) continue;
                select.concurrent(.slot_free, slotFreeTask, .{
                    self.io,
                    &self.in_flight,
                    tally,
                    self.log,
                }) catch |e| {
                    // Without this waiter a saturated loop would wait forever.
                    self.log.err("failed to start admission-gate wait: {s}", .{@errorName(e)});
                    return e;
                };
                slot_free_armed = true;
            }

            const wake = select.await() catch |e| {
                self.log.err("accept wait failed: {s}", .{@errorName(e)});
                return e;
            };

            switch (wake) {
                // SIGINT/SIGTERM: return so `main`'s defers run the shutdown.
                .shutdown => {
                    self.log.info("shutdown signal received, exiting", .{});
                    self.log.info("peak concurrent clients: {d}", .{self.in_flight.peak});
                    const clients = self.tally.clients.load(.acquire);
                    const threads = self.tally.total.load(.acquire);
                    self.log.info(
                        "worker threads: {d} ({d} served clients)",
                        .{ threads, clients },
                    );
                    return;
                },
                .slot_free => slot_free_armed = false,
                .client => |outcome| switch (outcome) {
                    .accepted => |client| {
                        armed &= ~armedBit(client.server);
                        self.admit(client.server, client.stream);
                    },
                    .failed => |failure| {
                        armed &= ~armedBit(failure.server);
                        self.log.warn("accept failed: {s}", .{@errorName(failure.err)});
                    },
                },
            }
        }
    }

    /// Arm one accept task per listen socket that has none in flight.
    fn armAccepts(self: *ServerContext, select: *Io.Select(AcceptWake), armed: *u64) !void {
        for (self.servers, 0..) |_, i| {
            const bit = armedBit(i);
            if (armed.* & bit != 0) continue;
            select.concurrent(.client, acceptTask, .{ self, i }) catch |e| {
                self.log.err("failed to start accept task: {s}", .{@errorName(e)});
                return e;
            };
            armed.* |= bit;
        }
    }

    /// Apply ip-protection, take an admission slot, and dispatch one accepted
    /// connection onto the pool. Every early return closes the stream and
    /// leaves the slot count unchanged.
    fn admit(self: *ServerContext, server_index: usize, stream: Io.net.Stream) void {
        // ip-protection level 2: reject clients with a public IP.
        if (self.opts.ip_protection & ip_protect_reject_public != 0) {
            if (!network.isClientPrivate(stream.socket.handle)) {
                stream.close(self.io);
                self.log.debug("client with public IP address rejected", .{});
                return;
            }
        }

        // The loop checked `atCap` before arming accepts and is the only
        // acquirer, so this fails only for an accept that completed before the
        // cap was reached. Drop that connection rather than exceed the cap.
        if (!self.in_flight.tryAcquire()) {
            stream.close(self.io);
            self.log.warn("admission gate refused an accepted client, dropping connection", .{});
            return;
        }

        const ctx = self.gpa.create(ClientContext) catch |e| {
            stream.close(self.io);
            self.in_flight.release(self.io);
            self.log.warn("out of memory accepting client: {s}", .{@errorName(e)});
            return;
        };
        ctx.* = .{
            .stream = stream,
            .io = self.io,
            .gpa = self.gpa,
            .cfg = self.cfg,
            .prng = std.Random.DefaultPrng.init(self.prng.int(u64)),
            .port_str = "",
            .use_ndr64 = self.opts.ndr64,
            .use_btfn = self.opts.btfn,
            .disconnect_per_request = self.opts.disconnect_per_request,
            .timeout_seconds = self.opts.timeout_seconds,
            .rpc_assoc_group = self.assoc_group,
            .in_flight = &self.in_flight,
            .tally = self.tally,
            .log = self.log,
            .quiet_loopback = self.opts.quiet_loopback,
        };
        // The BIND_ACK advertises the local port the client reached. It comes
        // from the listen socket that accepted the connection, because
        // `--port 0` gives every socket its own ephemeral port (the reference
        // reads it from the local socket with `getnameinfo`). Formatting after
        // the assignment keeps `port_str` pointing at `ctx.port_buf` itself.
        const bound_port = self.servers[server_index].socket.address.getPort();
        ctx.port_str = std.fmt.bufPrint(&ctx.port_buf, "{d}", .{bound_port}) catch unreachable;

        // One association group per connection, always non-zero
        // (C `RpcAssocGroup++` in `runServer`).
        self.assoc_group +%= 1;

        self.conn_group.concurrent(self.io, serveClientThread, .{ctx}) catch |e| {
            ctx.stream.close(self.io);
            self.gpa.destroy(ctx);
            self.in_flight.release(self.io);
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

    var diag: cli_helper.Diag = .{};
    var res = cli_helper.parseWithDiag(init.gpa, &vlmzsd_opts, args_list.items, &diag) catch |err| {
        // Short diagnostic naming the argument; the full help is one `--help` away.
        var ebuf: [128]u8 = undefined;
        cli_helper.fatalStderr(init.io, "vlmzsd", "{s}", .{cli_helper.parseErrorMessage(err, diag, &ebuf)});
    };
    defer res.deinit();

    if (res.hasFlag("help")) {
        var hbuf: [4096]u8 = undefined;
        var hw = std.Io.File.writer(std.Io.File.stdout(), init.io, &hbuf);
        try cli_helper.writeHelp(&hw.interface, "vlmzsd", &vlmzsd_opts, "");
        try hw.interface.flush();
        return;
    }
    if (res.hasFlag("version")) {
        var buf: [64]u8 = undefined;
        var fw = std.Io.File.writer(std.Io.File.stdout(), init.io, &buf);
        try fw.interface.print("vlmzsd {s}\n", .{version_display});
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
    var tally: ThreadTally = .{};
    var log_group: Io.Group = .init;
    defer log_group.cancel(init.io);
    defer log.shutdown(init.io);
    log_group.concurrent(init.io, logWriterTask, .{ &log, &tally }) catch |e| {
        // No writer task means no consumer for the queue, so `fatal` would
        // block in `shutdown`: report without the logger and exit.
        cli_helper.fatalStderr(init.io, "vlmzsd", "failed to start log writer task: {s}", .{@errorName(e)});
    };

    const resolver: Resolver = .{ .gpa = init.gpa, .env = init.environ_map, .res = &res, .diag = &diag };
    var opts = resolveOptions(resolver) catch |e| switch (e) {
        error.UnexpectedPositional => cli_helper.fatalStderr(init.io, "vlmzsd", "takes no positional arguments", .{}),
        error.LcidOutOfRange => cli_helper.fatalStderr(init.io, "vlmzsd", "--lcid must be 0..{d} (0 = random)", .{kms.max_lcid}),
        error.BuildOutOfRange => cli_helper.fatalStderr(init.io, "vlmzsd", "--build must be 0..{d} (0 = random)", .{kms.max_build}),
        error.TimeoutOutOfRange => cli_helper.fatalStderr(init.io, "vlmzsd", "--timeout must be at most {d} seconds", .{std.math.maxInt(u32)}),
        error.IntervalOutOfRange => cli_helper.fatalStderr(init.io, "vlmzsd", "policy interval must be at most {d} minutes", .{std.math.maxInt(u32)}),
        error.InvalidListenAddress => cli_helper.fatalStderr(init.io, "vlmzsd", "{s}: \"{s}\" is not an IP address (the port comes from --port)", .{ diag.spelling, diag.value }),
        else => blk: {
            var vbuf: [128]u8 = undefined;
            if (diag.spelling.len > 0) {
                const text = std.fmt.bufPrint(&vbuf, "{s}: invalid value \"{s}\"", .{ diag.spelling, diag.value }) catch @errorName(e);
                cli_helper.fatalStderr(init.io, "vlmzsd", "{s}", .{text});
            }
            // Not about one value (e.g. an unknown .kmd field): name the error.
            cli_helper.fatalStderr(init.io, "vlmzsd", "{s}", .{@errorName(e)});
            break :blk {};
        },
    };
    defer opts.deinit(init.gpa);

    log.min_level = opts.log_level;
    // The log writer is the one pool task that started before the level was
    // known, so its own start line was filtered by the default; announce the
    // role here instead, keeping the thread census complete for a `-v` reader.
    log.debug("log writer task started", .{});
    // Configuration notices are ordinary `warn` lines and obey the resolved
    // level: `-q` (warn) shows them, `-qq` (err) silences them.
    if (opts.invalid_log_level) |value| log.warn("ignoring invalid {s} \"{s}\" (expected trace, debug, info, warn, or err)", .{ log_level_env, value });
    if (opts.legacy_verbose_present) log.warn("{s} is deprecated; use {s} instead", .{ deprecated_verbose_env, log_level_env });
    if (opts.legacy_quiet_present) log.warn("{s} is deprecated; use {s} instead", .{ deprecated_quiet_env, log_level_env });

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

    const epid_overrides = buildEpidOverrides(init.gpa, &data, &opts, rng, cli_helper.nowUnix(init.io), &log) catch |e| {
        fatal(&log, init.io, "cannot initialize randomized ePIDs: {s}", .{@errorName(e)});
    };
    defer {
        for (epid_overrides) |slot| {
            if (slot) |s| init.gpa.free(s);
        }
        init.gpa.free(epid_overrides);
    }

    // Level 2 generates each ePID at request time. Reject a data file that
    // cannot supply a host build for the negotiated transfer syntax now,
    // instead of rejecting every request later.
    if (opts.randomize == 2) {
        var needs_random_pid = false;
        for (epid_overrides) |slot| if (slot == null) {
            needs_random_pid = true;
            break;
        };
        if (needs_random_pid and opts.build == 0 and !kms.hasHostBuildForNdr64(&data, opts.ndr64)) {
            fatal(&log, init.io, "no host build matches the NDR64 setting for randomized ePIDs", .{});
        }
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

    // Create the listening sockets. ip-protection level 1 listens only on the
    // host's private addresses; otherwise `--listen` (default ::, a dual-stack
    // socket covering both IPv4 and IPv6).
    var servers: std.ArrayList(Io.net.Server) = .empty;
    defer {
        for (servers.items) |*s| s.deinit(init.io);
        servers.deinit(init.gpa);
    }
    try createListenSockets(init.gpa, init.io, &opts, &log, &servers);

    // With `--port 0` the kernel picks the port, so report the one actually
    // bound instead of echoing "0".
    const bound_port: u16 = if (opts.port != 0) opts.port else servers.items[0].socket.address.getPort();
    log.info("vlmzsd {s} listening on port {d}", .{ version, bound_port });
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
    // gate checked *before* an accept task is armed. It is not delegated to the
    // pool: `std.Io.Threaded` never reclaims an idle worker (they live until
    // `deinit`), and `std.process.Init` does not expose its options, so the
    // bound has to be our own invariant.

    if (servers.items.len > max_listen_sockets) {
        fatal(&log, init.io, "too many listen sockets (max {d})", .{max_listen_sockets});
    }

    // Signals first, so the shutdown pipe outlives its waiters and its close
    // runs after the connection group joins (defers run in reverse). The
    // accept loop's shutdown task reads the pipe as an `Io` operation, and
    // `run` cancels that task before it returns, so keeping this order rules
    // out a close-before-join bug.
    installSignalHandlers(init.io, &log);
    defer {
        shutdownPipeFile(.read).close(init.io);
        shutdownPipeFile(.write).close(init.io);
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
        .tally = &tally,
        .conn_group = &conn_group,
        .prng = rng,
        .assoc_group = rng.int(u32) | 1,
    };
    try server.run();
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "InFlight admits up to the cap, then refuses without leaking slots" {
    const io: Io = std.testing.io;
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

    gate.release(io);
    try std.testing.expect(!gate.atCap());
    try std.testing.expect(gate.tryAcquire());
    try std.testing.expectEqual(@as(u32, 2), gate.count.load(.acquire));

    gate.release(io);
    gate.release(io);
    try std.testing.expectEqual(@as(u32, 0), gate.count.load(.acquire));
}

test "InFlight peak survives idle periods" {
    const io: Io = std.testing.io;
    var gate: InFlight = .{ .cap = 8 };
    try std.testing.expectEqual(@as(u32, 0), gate.peak);

    var round: u32 = 0;
    while (round < 3) : (round += 1) {
        try std.testing.expect(gate.tryAcquire());
        try std.testing.expect(gate.tryAcquire());
        try std.testing.expect(gate.tryAcquire());
        try std.testing.expectEqual(@as(u32, 3), gate.peak);

        gate.release(io);
        gate.release(io);
        gate.release(io);
        // Idle again: the high-water mark is what shutdown reports, so it must
        // not be reset when the count drops.
        try std.testing.expectEqual(@as(u32, 0), gate.count.load(.acquire));
        try std.testing.expectEqual(@as(u32, 3), gate.peak);
    }

    // A wider burst advances the mark; the earlier 3 is not sticky.
    const four = [_]u32{ 1, 2, 3, 4 };
    for (four) |_| try std.testing.expect(gate.tryAcquire());
    try std.testing.expectEqual(@as(u32, 4), gate.peak);
    for (four) |_| gate.release(io);
    try std.testing.expectEqual(@as(u32, 0), gate.count.load(.acquire));
    try std.testing.expectEqual(@as(u32, 4), gate.peak);
}

test "InFlight cap of 0 is unlimited" {
    const io: Io = std.testing.io;
    var gate: InFlight = .{ .cap = 0 };
    try std.testing.expect(!gate.atCap());

    var i: u32 = 0;
    while (i < 1000) : (i += 1) {
        try std.testing.expect(gate.tryAcquire());
        try std.testing.expect(!gate.atCap());
    }
    try std.testing.expectEqual(@as(u32, 1000), gate.count.load(.acquire));
    try std.testing.expectEqual(@as(u32, 1000), gate.peak);

    while (i > 0) : (i -= 1) gate.release(io);
    try std.testing.expectEqual(@as(u32, 0), gate.count.load(.acquire));
}

test "a slot freed while the accept loop is at the cap cannot be missed" {
    // The accept loop resets `slot_free`, re-reads the gate, then parks on it.
    // A release before that re-read shows up in the count; a release after it
    // sets the event, which stays set until the loop resets it again — so a
    // wait that has not parked yet still returns. Pin both halves of that
    // hand-off: the wake-up must not be lost, and the wait must not spin.
    const io: Io = std.testing.io;
    var gate: InFlight = .{ .cap = 1 };
    try std.testing.expect(gate.tryAcquire());

    gate.slot_free.reset();
    try std.testing.expect(gate.atCap());

    gate.release(io);
    try std.testing.expect(!gate.atCap());
    try std.testing.expect(gate.slot_free.isSet());
    try gate.slot_free.wait(io); // returns at once: the set came first

    // An unset event does not report a spurious wake-up, so the loop cannot
    // spin at the cap.
    gate.slot_free.reset();
    try std.testing.expectError(error.Timeout, gate.slot_free.waitTimeout(io, .{
        .duration = .{ .raw = .{ .nanoseconds = std.time.ns_per_ms }, .clock = .awake },
    }));
}

// The shutdown policy is exercised through `noteShutdownSignal` and a local
// counter: a test must never reach `_exit` (it would take the test runner with
// it), and it must never install the real handler or write to the real pipe
// (stdout carries the test runner protocol).
test "the first shutdown signal asks for a graceful exit" {
    var counter: std.atomic.Value(u32) = .init(0);
    try std.testing.expect(noteShutdownSignal(&counter));
    try std.testing.expectEqual(@as(u32, 1), counter.load(.acquire));
}

test "a second shutdown signal forces an exit" {
    var counter: std.atomic.Value(u32) = .init(0);
    try std.testing.expect(noteShutdownSignal(&counter)); // 1st: graceful
    try std.testing.expect(!noteShutdownSignal(&counter)); // 2nd: hard exit
    try std.testing.expect(!noteShutdownSignal(&counter)); // later ones too
    try std.testing.expectEqual(@as(u32, 3), counter.load(.acquire));
}

test "resolveLogLevel: CLI flags, VLMZSD_LOG_LEVEL, and invalid values" {
    const gpa = std.testing.allocator;
    var env: EnvironMap = .init(gpa);
    defer env.deinit();
    var diag: cli_helper.Diag = .{};

    var no_flags = try cli_helper.parse(gpa, &vlmzsd_opts, &.{});
    defer no_flags.deinit();
    var two_v = try cli_helper.parse(gpa, &vlmzsd_opts, &.{"-vv"});
    defer two_v.deinit();
    var both = try cli_helper.parse(gpa, &vlmzsd_opts, &.{ "-vv", "-q" });
    defer both.deinit();

    const plain: Resolver = .{ .gpa = gpa, .env = &env, .res = &no_flags, .diag = &diag };
    const verbose: Resolver = .{ .gpa = gpa, .env = &env, .res = &two_v, .diag = &diag };
    const mixed: Resolver = .{ .gpa = gpa, .env = &env, .res = &both, .diag = &diag };
    var opts = ServerOptions{};

    // Default is info, with nothing recorded.
    try std.testing.expectEqual(cli_helper.Level.info, try resolveLogLevel(plain, &opts));
    try std.testing.expectEqual(@as(?[]const u8, null), opts.invalid_log_level);

    // A valid env value is used, case-insensitively.
    try env.put("VLMZSD_LOG_LEVEL", "WaRn");
    try std.testing.expectEqual(cli_helper.Level.warn, try resolveLogLevel(plain, &opts));

    // An invalid env value is recorded (not fatal) and falls back to info.
    try env.put("VLMZSD_LOG_LEVEL", "loud");
    opts.invalid_log_level = null;
    try std.testing.expectEqual(cli_helper.Level.info, try resolveLogLevel(plain, &opts));
    try std.testing.expectEqualStrings("loud", opts.invalid_log_level.?);

    // The CLI overrides the env value, but the typo is still recorded.
    opts.invalid_log_level = null;
    try std.testing.expectEqual(cli_helper.Level.trace, try resolveLogLevel(verbose, &opts));
    try std.testing.expectEqualStrings("loud", opts.invalid_log_level.?);

    // Any `-q` beats `-v`.
    opts.invalid_log_level = null;
    try std.testing.expectEqual(cli_helper.Level.warn, try resolveLogLevel(mixed, &opts));

    // Deprecated booleans are the lowest-priority fallback; quiet beats verbose.
    _ = env.swapRemove("VLMZSD_LOG_LEVEL");
    try env.put("VLMZSD_VERBOSE", "true");
    opts.invalid_log_level = null;
    try std.testing.expectEqual(cli_helper.Level.debug, try resolveLogLevel(plain, &opts));
    try std.testing.expect(opts.legacy_verbose_present);
    try std.testing.expect(!opts.legacy_quiet_present);
}

test "splitList returns an exactly-sized list and skips empty segments" {
    const gpa = std.testing.allocator;

    // The returned slice must be the whole allocation: `ServerOptions.deinit`
    // frees it at the length it received, so a shorter sub-slice would free the
    // wrong size. Empty segments make the two lengths differ.
    const list = try splitList(gpa, " 127.0.0.1, ,::1 ,");
    defer gpa.free(list);
    try std.testing.expectEqual(@as(usize, 2), list.len);
    try std.testing.expectEqualStrings("127.0.0.1", list[0]);
    try std.testing.expectEqualStrings("::1", list[1]);

    // A value with no address at all allocates nothing, so freeing it is a
    // no-op instead of a leak.
    const empty = try splitList(gpa, " , ");
    defer gpa.free(empty);
    try std.testing.expectEqual(@as(usize, 0), empty.len);

    const single = try splitList(gpa, " :: ");
    defer gpa.free(single);
    try std.testing.expectEqual(@as(usize, 1), single.len);
    try std.testing.expectEqualStrings("::", single[0]);
}

test "resolveOptions: env lists, numeric limits, and positional arguments" {
    const gpa = std.testing.allocator;
    var env: EnvironMap = .init(gpa);
    defer env.deinit();

    // A list with no address leaves the default in place.
    try env.put("VLMZSD_LISTEN", " , ");
    var default_listen = try cli_helper.parse(gpa, &vlmzsd_opts, &.{});
    defer default_listen.deinit();
    {
        var diag: cli_helper.Diag = .{};
        var opts = try resolveOptions(.{ .gpa = gpa, .env = &env, .res = &default_listen, .diag = &diag });
        defer opts.deinit(gpa);
        try std.testing.expectEqual(@as(usize, 1), opts.listen.len);
        try std.testing.expectEqualStrings("::", opts.listen[0]);
    }

    // Gaps and padding are trimmed away, and the result owns its allocation.
    try env.put("VLMZSD_LISTEN", "127.0.0.1,, ::1");
    {
        var diag: cli_helper.Diag = .{};
        var opts = try resolveOptions(.{ .gpa = gpa, .env = &env, .res = &default_listen, .diag = &diag });
        defer opts.deinit(gpa);
        try std.testing.expectEqual(@as(usize, 2), opts.listen.len);
        try std.testing.expectEqualStrings("127.0.0.1", opts.listen[0]);
        try std.testing.expectEqualStrings("::1", opts.listen[1]);
    }
    _ = env.swapRemove("VLMZSD_LISTEN");

    // The documented limits are accepted ...
    var limits = try cli_helper.parse(gpa, &vlmzsd_opts, &.{
        "--lcid",                "32767",
        "--build",               "65535",
        "--timeout",             "4294967295s",
        "--activation-interval", "4294967295m",
    });
    defer limits.deinit();
    {
        var diag: cli_helper.Diag = .{};
        var opts = try resolveOptions(.{ .gpa = gpa, .env = &env, .res = &limits, .diag = &diag });
        defer opts.deinit(gpa);
        try std.testing.expectEqual(kms.max_lcid, opts.lcid);
        try std.testing.expectEqual(kms.max_build, opts.build);
        try std.testing.expectEqual(std.math.maxInt(u32), opts.timeout_seconds);
        try std.testing.expectEqual(std.math.maxInt(u32), opts.activation_interval_minutes);
    }

    // ... and one past each is a configuration error, not a panic.
    const Case = struct { args: []const []const u8, expected: anyerror };
    const cases = [_]Case{
        .{ .args = &.{ "--lcid", "32768" }, .expected = error.LcidOutOfRange },
        .{ .args = &.{ "--build", "65536" }, .expected = error.BuildOutOfRange },
        .{ .args = &.{ "--timeout", "4294967296s" }, .expected = error.TimeoutOutOfRange },
        .{ .args = &.{ "--activation-interval", "71582789h" }, .expected = error.IntervalOutOfRange },
        .{ .args = &.{ "--renewal-interval", "71582789h" }, .expected = error.IntervalOutOfRange },
        .{ .args = &.{"stray"}, .expected = error.UnexpectedPositional },
    };
    for (cases) |case| {
        var res = try cli_helper.parse(gpa, &vlmzsd_opts, case.args);
        defer res.deinit();
        var diag: cli_helper.Diag = .{};
        try std.testing.expectError(case.expected, resolveOptions(.{ .gpa = gpa, .env = &env, .res = &res, .diag = &diag }));
    }
}

test "--listen must be an IP literal, and a bad value names the option" {
    const gpa = std.testing.allocator;
    var env = EnvironMap.init(gpa);
    defer env.deinit();

    // An address with a port is the mistake the message is written for: the
    // port has its own option, and `ip:port` would otherwise fail at bind time
    // with the address and the port glued together.
    const bad = [_]struct { args: []const []const u8, spelling: []const u8, value: []const u8 }{
        .{ .args = &.{ "--listen", "0.0.0.0:1688" }, .spelling = "--listen", .value = "0.0.0.0:1688" },
        .{ .args = &.{ "--listen", "localhost" }, .spelling = "--listen", .value = "localhost" },
        .{ .args = &.{ "--listen", "::1", "--listen", "300.1.1.1" }, .spelling = "--listen", .value = "300.1.1.1" },
    };
    for (bad) |case| {
        var res = try cli_helper.parse(gpa, &vlmzsd_opts, case.args);
        defer res.deinit();
        var diag: cli_helper.Diag = .{};
        try std.testing.expectError(error.InvalidListenAddress, resolveOptions(.{ .gpa = gpa, .env = &env, .res = &res, .diag = &diag }));
        try std.testing.expectEqualStrings(case.spelling, diag.spelling);
        try std.testing.expectEqualStrings(case.value, diag.value);
    }

    // Literals the protocol uses are accepted, including a bare IPv6 address
    // whose colons are not a port separator.
    var ok = try cli_helper.parse(gpa, &vlmzsd_opts, &.{ "--listen", "127.0.0.1", "--listen", "::1", "--listen", "::" });
    defer ok.deinit();
    var diag: cli_helper.Diag = .{};
    var opts = try resolveOptions(.{ .gpa = gpa, .env = &env, .res = &ok, .diag = &diag });
    defer opts.deinit(gpa);
    try std.testing.expectEqual(@as(usize, 3), opts.listen.len);
}

test "--port: a bad value names the CLI spelling or the environment variable" {
    const gpa = std.testing.allocator;
    var env = EnvironMap.init(gpa);
    defer env.deinit();

    // From the CLI: the flag as typed.
    {
        var res = try cli_helper.parse(gpa, &vlmzsd_opts, &.{ "--port", "abc" });
        defer res.deinit();
        var diag: cli_helper.Diag = .{};
        try std.testing.expectError(error.InvalidCharacter, resolveOptions(.{ .gpa = gpa, .env = &env, .res = &res, .diag = &diag }));
        try std.testing.expectEqualStrings("--port", diag.spelling);
        try std.testing.expectEqualStrings("abc", diag.value);
    }

    // From the environment: the variable name, so a supervisor's typo is
    // traceable to the file that set it.
    try env.put("VLMZSD_PORT", "70000");
    {
        var res = try cli_helper.parse(gpa, &vlmzsd_opts, &.{});
        defer res.deinit();
        var diag: cli_helper.Diag = .{};
        try std.testing.expectError(error.Overflow, resolveOptions(.{ .gpa = gpa, .env = &env, .res = &res, .diag = &diag }));
        try std.testing.expectEqualStrings("VLMZSD_PORT", diag.spelling);
        try std.testing.expectEqualStrings("70000", diag.value);
    }
}

test "a repeated --epid name replaces the earlier override without leaking" {
    const gpa = std.testing.allocator;
    var overrides = [_]?[]const u8{null};
    defer if (overrides[0]) |s| gpa.free(s);

    try putOverride(gpa, &overrides, 0, "03612-00000-000-000000-03-1033-19045.0000-0002023");
    try std.testing.expectEqualStrings("03612-00000-000-000000-03-1033-19045.0000-0002023", overrides[0].?);

    try putOverride(gpa, &overrides, 0, "03612-00000-000-000000-03-1033-22631.0000-0002025");
    try std.testing.expectEqualStrings("03612-00000-000-000000-03-1033-22631.0000-0002025", overrides[0].?);
}

test "level-1 ePIDs share one LCID and one host build" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;

    var data = try kmsdata.parse(gpa, @embedFile("vlmcsd.kmd"));
    defer data.deinit(gpa);

    var out_buf: [512]u8 = undefined;
    var err_buf: [512]u8 = undefined;
    var log = try cli_helper.Logger.init(gpa, io, &out_buf, &err_buf);
    defer log.deinit(gpa);

    var opts = ServerOptions{};
    opts.randomize = 1;

    var prng: std.Random.DefaultPrng = .init(0xc0f_fee1);
    const overrides = try buildEpidOverrides(gpa, &data, &opts, prng.random(), 1_700_000_000, &log);
    defer {
        for (overrides) |slot| if (slot) |s| gpa.free(s);
        gpa.free(overrides);
    }

    // Level 1 pre-fills every CSVLC: `platform-group-keyhi-keylo-03-lcid-build.0000-ydayyear`.
    try std.testing.expectEqual(data.csvlk.len, overrides.len);
    var shared_lcid: ?[]const u8 = null;
    var shared_build: ?[]const u8 = null;
    for (overrides) |slot| {
        const pid = slot orelse return error.MissingEpid;
        var fields = std.mem.splitScalar(u8, pid, '-');
        var index: usize = 0;
        var lcid: []const u8 = "";
        var build: []const u8 = "";
        while (fields.next()) |field| : (index += 1) {
            switch (index) {
                5 => lcid = field,
                6 => build = field[0..std.mem.indexOfScalar(u8, field, '.').?],
                else => {},
            }
        }
        if (shared_lcid) |expected| {
            // One LCID for the whole run, as `randomPidInit` samples it once.
            try std.testing.expectEqualStrings(expected, lcid);
            try std.testing.expectEqualStrings(shared_build.?, build);
        } else {
            shared_lcid = lcid;
            shared_build = build;
        }
    }
    try std.testing.expect(shared_lcid.?.len > 0);
}

test "an --epid entry with an empty ePID is ignored" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;

    var data = try kmsdata.parse(gpa, @embedFile("vlmcsd.kmd"));
    defer data.deinit(gpa);

    var out_buf: [512]u8 = undefined;
    var err_buf: [512]u8 = undefined;
    var log = try cli_helper.Logger.init(gpa, io, &out_buf, &err_buf);
    defer log.deinit(gpa);

    var opts = ServerOptions{};
    opts.randomize = 0;
    opts.epids = &.{ "Windows=", "Windows=03612-00000-000-000000-03-1033-19045.0000-0002023" };

    var prng: std.Random.DefaultPrng = .init(0x5eed);
    const overrides = try buildEpidOverrides(gpa, &data, &opts, prng.random(), 1_700_000_000, &log);
    defer {
        for (overrides) |slot| if (slot) |s| gpa.free(s);
        gpa.free(overrides);
    }

    // The empty value is skipped, so the later entry survives instead of being
    // replaced by a blank product key.
    try std.testing.expectEqualStrings(
        "03612-00000-000-000000-03-1033-19045.0000-0002023",
        overrides[0].?,
    );
}
