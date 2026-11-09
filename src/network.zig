//! Network layer — idiomatic `std.Io` / `std.Io.net` socket I/O (the upstream
//! vlmcsd `network.c` is a historical reference only).
//!
//! The C `network.c`/`rpc.c` boundary is reorganized here: `rpc.zig` holds the
//! pure wire-format code, and this module adds the byte-stream I/O on top of
//! it (the `sendrecv` equivalents) plus the socket glue (`connect`/`listen`).
//! Everything here is internal (not wire-critical), so it is written
//! idiomatically against `std.Io` rather than transliterating the C socket
//! loops.

const std = @import("std");
const vlmzsd = @import("vlmzsd");
const rpc = vlmzsd.rpc;
const kms = vlmzsd.kms;

const Io = std.Io;
const Allocator = std.mem.Allocator;

// ---------------------------------------------------------------------------
// Byte streams
// ---------------------------------------------------------------------------

/// Where a packet's bytes come from, and how long a read may wait for them.
///
/// `peer` present → read from that connected socket through
/// `Io.operateTimeout(.net_receive)`: the **backend** owns both the deadline and
/// the cancelation point, so a shutdown signal ends a parked read with
/// `error.Canceled` without any self-pipe or wake fd.
/// `peer` absent → read from the `Io.Reader` handed to `PacketReader` (canned
/// input in tests).
///
/// Both the server loop and the client use these options, so `--timeout` means
/// the same on either side of the connection.
pub const ReadOptions = struct {
    peer: ?Peer = null,

    /// A connected socket, together with the `Io` handle that reaches it. `Io`
    /// has no default value, so it travels with the socket instead of being
    /// plumbed through every signature.
    pub const Peer = struct {
        io: Io,
        handle: std.posix.socket_t,
        /// Per-read deadline. `.none` waits without one (and stays cancelable).
        timeout: Io.Timeout = .none,
    };
};

/// Translate the CLI's whole-second `--timeout` into a backend deadline.
/// `0` means "no deadline": the read may wait forever, but a cancelation request
/// still ends it.
pub fn timeoutSeconds(seconds: u32) Io.Timeout {
    if (seconds == 0) return .none;
    return .{ .duration = .{ .raw = .{ .nanoseconds = @as(i96, seconds) * 1_000_000_000 }, .clock = .awake } };
}

/// One `net_receive` from `peer`; returns how many bytes arrived.
/// `error.EndOfStream` means the peer closed the connection.
///
/// `net_receive` is message oriented: one call copies at most one message
/// (never more than `buf.len` bytes) straight into `buf`, and reports EOF as a
/// zero-length message rather than as an error.
fn readSome(peer: ReadOptions.Peer, buf: []u8) !usize {
    var messages = [1]Io.net.IncomingMessage{
        .{ .from = undefined, .data = undefined, .control = &.{}, .flags = undefined },
    };
    const result = try peer.io.operateTimeout(.{ .net_receive = .{
        .socket_handle = peer.handle,
        .message_buffer = &messages,
        .data_buffer = buf,
        .flags = .{},
    } }, peer.timeout);
    const received = result.net_receive;
    if (received[0]) |err| return err;
    // A completed receive always fills the first message; treat the impossible
    // empty case as EOF rather than spinning on it.
    if (received[1] == 0) return error.EndOfStream;
    const message = messages[0];
    // The backend copies straight into `buf`; read-ahead, when enabled, is
    // layered above this in `PacketReader`.
    std.debug.assert(message.data.ptr == buf.ptr);
    if (message.data.len == 0) return error.EndOfStream;
    return message.data.len;
}

/// Read exactly `dest.len` bytes from `peer`, one `net_receive` per refill. Each
/// refill waits with its own deadline, so a peer that sends half a packet and
/// then stalls surfaces as `error.Timeout` instead of parking the caller in the
/// kernel (the reference used `SO_RCVTIMEO` for the same purpose).
fn readExactPeer(peer: ReadOptions.Peer, dest: []u8) !void {
    var off: usize = 0;
    while (off < dest.len) {
        const n = try readSome(peer, dest[off..]);
        if (n == 0) return error.EndOfStream;
        off += n;
    }
}

/// Packet reader: reads an exact number of bytes from a connected peer or from a
/// borrowed `Io.Reader` (canned test input), optionally through read-ahead.
///
/// The server asks for a 16-byte header and then the body, and TCP normally
/// delivers both in one segment: refilling through `buffer` reads them with one
/// `net_receive` and serves the body from memory. The deadline still applies per
/// refill, because each refill is one wait.
///
/// `Io.Reader.readSliceAll` cannot be used for the socket path: it loops until
/// the buffer is full, so a peer that sends half a packet parks the caller in
/// the kernel and no deadline can end that wait.
///
/// The state (`start`/`end`) must outlive one packet sequence, so a reader stays
/// with its connection and is never copied after the first read.
pub const PacketReader = struct {
    /// Where the bytes come from and how long a read may wait.
    idle: ReadOptions,
    /// Source used when `idle.peer` is null; the socket path bypasses it.
    reader: *Io.Reader,
    /// Read-ahead storage, owned by the caller; empty disables read-ahead.
    buffer: []u8,
    /// Buffered bytes are `buffer[start..end]`; `start == end` means empty.
    start: usize = 0,
    end: usize = 0,

    pub fn init(idle: ReadOptions, reader: *Io.Reader, buffer: []u8) PacketReader {
        return .{ .idle = idle, .reader = reader, .buffer = buffer };
    }

    /// Read exactly `dest.len` bytes. `error.EndOfStream` means the peer closed,
    /// possibly after some of `dest` was filled.
    pub fn read(self: *PacketReader, dest: []u8) !void {
        const peer = self.idle.peer orelse return self.readDirect(dest);
        if (self.buffer.len == 0) return readExactPeer(peer, dest);
        var off: usize = 0;
        while (off < dest.len) {
            if (self.start < self.end) {
                const n = @min(self.end - self.start, dest.len - off);
                @memcpy(dest[off..][0..n], self.buffer[self.start..][0..n]);
                self.start += n;
                off += n;
                continue;
            }
            // A read at least as large as the buffer goes straight into `dest`:
            // no copy, and it does not need the read-ahead at all.
            if (dest.len - off >= self.buffer.len) {
                const n = try readSome(peer, dest[off..]);
                if (n == 0) return error.EndOfStream;
                off += n;
                continue;
            }
            const n = try readSome(peer, self.buffer);
            if (n == 0) return error.EndOfStream;
            self.start = 0;
            self.end = n;
        }
    }

    /// No socket behind the reader: copy from the borrowed `Io.Reader`, which
    /// may be an unbuffered source such as `Io.Reader.fixed`.
    fn readDirect(self: *PacketReader, dest: []u8) !void {
        var off: usize = 0;
        while (off < dest.len) {
            var vec: [1][]u8 = .{dest[off..]};
            const n = try self.reader.readVec(&vec);
            if (n == 0) return error.EndOfStream;
            off += n;
        }
    }
};

/// Write all of `buf` and flush it (equivalent to `_send` in network.c). The
/// `Io.Writer` is buffered, so the flush is what puts the bytes on the socket.
pub fn writeAndFlush(writer: *Io.Writer, buf: []const u8) !void {
    try writer.writeAll(buf);
    try writer.flush();
}

// ---------------------------------------------------------------------------
// Server
// ---------------------------------------------------------------------------

/// Protocol-level event reported to the caller through `ServeOptions.events`.
/// This module reports what happened; the caller decides how to surface it
/// (e.g. logging), keeping this module free of any logger dependency.
pub const Event = union(enum) {
    /// BIND/ALTER-CONTEXT negotiation; payload is true when NDR64 was selected.
    bind_negotiated: bool,
    /// A received PDU that is not a `REQUEST` (BIND, ALTER-CONTEXT, or a type
    /// this server does not handle), reported as it arrives so the caller can
    /// log what the peer actually sent.
    packet: struct { packet_type: u8, frag_length: u16 },
    /// A FAULT was sent; payload is the NCA status code.
    fault: u32,
    /// A KMS request was rejected; `major` is the request's major version
    /// (0 = unparseable) and `hr` the HRESULT.
    request_rejected: struct { major: u32, hr: u32 },
    /// A KMS request was served; `major` is the version and `size` the
    /// response byte length.
    response: struct { major: u32, size: usize },
};

/// Event callback and its context, clumped so the two cannot drift apart.
/// `Clock` has the same shape for the wall clock.
pub const EventSink = struct {
    context: ?*anyopaque = null,
    callback: ?*const fn (context: ?*anyopaque, event: Event) void = null,

    /// Report `event`; a sink without a callback reports nothing.
    pub fn notify(self: EventSink, event: Event) void {
        if (self.callback) |callback| callback(self.context, event);
    }
};

/// Wall clock for the per-request timestamp check (`--check-client-time`) and
/// for level-2 ePID generation. The loop samples it once before each REQUEST:
/// sampling it per connection would keep comparing against the moment the
/// connection was accepted, which a keep-alive client can hold open for hours.
pub const Clock = struct {
    context: ?*anyopaque = null,
    now_unix: *const fn (context: ?*anyopaque) i64,
};

/// Policy for one served connection. Resources (allocator, streams, RNG) travel
/// in `ServeSession`, so this struct carries configuration only.
pub const ServeOptions = struct {
    cfg: *const kms.ServerConfig,
    /// Request clock (see `Clock`); required, so a caller cannot forget it.
    clock: Clock,
    /// Association group id echoed in BIND/ALTER-CONTEXT responses. The
    /// reference assigns a random non-zero value at startup and increments it
    /// per client (`network.c` `runServer`); callers should do the same.
    rpc_assoc_group: u32 = 0,
    /// Port-number string to embed in BIND responses ("" → none).
    secondary_address: []const u8 = "",
    use_ndr64: bool = false,
    /// Bind-time feature negotiation is enabled (`UseServerRpcBTFN`).
    use_btfn: bool = false,
    /// Close the connection after each RESPONSE/FAULT (C `DisconnectImmediately`).
    disconnect_per_request: bool = false,
    /// Optional sink for protocol-level events (see `Event`).
    events: EventSink = .{},
};

/// What one served connection borrows: the allocator the RPC layer takes packet
/// and response bodies from, the packet reader over its socket, the writer that
/// answers, and the RNG for ePIDs.
pub const ServeSession = struct {
    allocator: Allocator,
    packet_reader: *PacketReader,
    writer: *Io.Writer,
    rng: std.Random,
};

/// The header fields of a packet this module sends. The body travels separately
/// so the fragment length can be derived from it.
const Reply = struct {
    packet_type: u8,
    call_id: u32,
    flags: u8,
};

/// Write one RPC packet (header + body).
fn writePacket(writer: *Io.Writer, reply: Reply, body: []const u8) !void {
    // Every body this server sends is bounded by a request or a response struct,
    // so the fragment length always fits its 16-bit field.
    const frag_len = rpc.header_size + body.len;
    std.debug.assert(frag_len <= std.math.maxInt(u16));
    var header: rpc.RpcHeader = undefined;
    rpc.createRpcHeader(&header, reply.packet_type, @intCast(frag_len), reply.call_id, reply.flags);
    // One `writeVecAll` and one `flush` reach the socket as a single `net_write`
    // (sendmsg with both iovecs). Flushing the header and then the body would
    // leave in two segments, which Nagle can hold back until the peer's delayed
    // ACK arrives — up to hundreds of milliseconds on a real network.
    var parts: [2][]const u8 = .{ std.mem.asBytes(&header), body };
    try writer.writeVecAll(&parts);
    try writer.flush();
}

/// Why the server loop stopped. Every value is a normal end of the connection,
/// and every exit path of `serveRpc` reports one, so the caller can log exactly
/// one close line per connection.
pub const ServeEnd = enum {
    /// The peer closed the stream.
    peer_closed,
    /// The peer sent a packet type this server does not handle (the C
    /// `rpcServer` returns from its `default:` arm).
    unsupported_packet,
    /// `disconnect_per_request` closed the connection after a RESPONSE/FAULT
    /// (the C `DisconnectImmediately`).
    after_request,
};

/// The C reference writes the server's global CallId (2) into FAULT headers, not
/// the request's CallId.
const fault_call_id: u32 = 2;

/// What a received PDU asks the loop to do.
const Kind = enum {
    bind,
    alter_context,
    request,
};

/// One received PDU: its parsed header and the allocator-owned body.
const Frame = struct {
    header: rpc.RpcHeader,
    body: []u8,
};

/// State of one served connection: the borrowed resources, the caller's policy
/// and the contexts BIND negotiated.
const Connection = struct {
    session: ServeSession,
    options: ServeOptions,
    negotiation: rpc.BindNegotiation = .{},

    fn run(self: *Connection) !ServeEnd {
        while (true) {
            const header = self.readHeader() catch |err| switch (err) {
                error.EndOfStream => return .peer_closed,
                else => |e| return e,
            };

            // Report every PDU except a `REQUEST` (whose outcome the `response`
            // / `request_rejected` events already describe). Without this a BIND
            // followed by an ALTER-CONTEXT — or by a type dropped below — leaves
            // no trace, and "BIND then nothing" is indistinguishable from "the
            // peer went silent".
            if (header.packet_type != rpc.packet_type.request) {
                self.options.events.notify(.{ .packet = .{
                    .packet_type = header.packet_type,
                    .frag_length = header.frag_length,
                } });
            }

            const kind: Kind = switch (header.packet_type) {
                rpc.packet_type.bind_req => .bind,
                rpc.packet_type.request => .request,
                rpc.packet_type.alter_context_req => .alter_context,
                // Unsupported packet type: close the connection (C `rpcServer`
                // returns from its `default:` arm). Reported through `ServeEnd`
                // so the caller logs the close instead of losing it.
                else => return .unsupported_packet,
            };

            const body = self.readBody(header) catch |err| switch (err) {
                error.EndOfStream => return .peer_closed,
                else => |e| return e,
            };
            defer self.session.allocator.free(body);

            const frame: Frame = .{ .header = header, .body = body };
            switch (kind) {
                .bind, .alter_context => try self.serveBind(frame, kind),
                .request => if (try self.serveRequest(frame)) |end| return end,
            }
        }
    }

    fn readHeader(self: *Connection) !rpc.RpcHeader {
        var header: rpc.RpcHeader = undefined;
        try self.session.packet_reader.read(std.mem.asBytes(&header));
        return header;
    }

    /// Read the body of `header` into an allocator-owned buffer.
    fn readBody(self: *Connection, header: rpc.RpcHeader) ![]u8 {
        const frag_len: usize = header.frag_length;
        if (frag_len < rpc.header_size) return error.InvalidPacket;
        const body = try self.session.allocator.alloc(u8, frag_len - rpc.header_size);
        errdefer self.session.allocator.free(body);
        try self.session.packet_reader.read(body);
        return body;
    }

    /// Answer a BIND or ALTER-CONTEXT.
    fn serveBind(self: *Connection, frame: Frame, kind: Kind) !void {
        std.debug.assert(kind != .request);
        const is_bind = kind == .bind;
        const resp_body = try rpc.buildBindResponse(
            self.session.allocator,
            frame.body,
            self.options.rpc_assoc_group,
            .{
                .use_ndr64 = self.options.use_ndr64,
                .use_btfn = self.options.use_btfn,
                // The local port string belongs in a BIND response only: the
                // reference suppresses it for ALTER-CONTEXT (`rpc.c` `rpcBind`
                // sets `SecondaryAddressLength = 0` when the packet type is
                // `RPC_PT_ALTERCONTEXT_REQ`).
                .secondary_address = if (is_bind) self.options.secondary_address else "",
            },
            &self.negotiation,
        );
        defer self.session.allocator.free(resp_body);

        if (is_bind) {
            self.options.events.notify(.{ .bind_negotiated = self.negotiation.hasNdr64() });
        }

        try writePacket(self.session.writer, .{
            .packet_type = if (is_bind) rpc.packet_type.bind_ack else rpc.packet_type.alter_context_ack,
            // BIND_ACK echoes the request's packet flags (incl. MULTIPLEX);
            // ALTER_CONTEXT_ACK always uses FIRST|LAST (matches the reference).
            .flags = if (is_bind) frame.header.packet_flags else rpc.packet_flags.first | rpc.packet_flags.last,
            .call_id = frame.header.call_id,
        }, resp_body);
    }

    /// Dispatch one REQUEST. Returns `.after_request` when `disconnect_per_request`
    /// closes the connection, or null to keep serving.
    fn serveRequest(self: *Connection, frame: Frame) !?ServeEnd {
        const now_unix = self.options.clock.now_unix(self.options.clock.context);
        const dispatch = try rpc.dispatchKmsRequest(
            self.session.allocator,
            frame.body,
            &self.negotiation,
            self.options.cfg,
            self.session.rng,
            now_unix,
        );
        switch (dispatch.kind) {
            .fault => |nca| {
                self.options.events.notify(.{ .fault = nca });
                const fault_body = rpc.buildFault(nca);
                try writePacket(self.session.writer, .{
                    .packet_type = rpc.packet_type.fault,
                    .call_id = fault_call_id,
                    .flags = rpc.packet_flags.first | rpc.packet_flags.last | rpc.packet_flags.not_exec,
                }, &fault_body);
            },
            .response => |resp_body| {
                defer self.session.allocator.free(resp_body);
                self.report(dispatch);
                // RESPONSE echoes the request's packet flags (incl. MULTIPLEX).
                try writePacket(self.session.writer, .{
                    .packet_type = rpc.packet_type.response,
                    .call_id = frame.header.call_id,
                    .flags = frame.header.packet_flags,
                }, resp_body);
            },
        }
        return if (self.options.disconnect_per_request) .after_request else null;
    }

    /// Report a served or rejected request as one event.
    fn report(self: *Connection, dispatch: rpc.DispatchResult) void {
        if (dispatch.response_size < 0) {
            self.options.events.notify(.{ .request_rejected = .{
                .major = dispatch.major_version,
                .hr = @bitCast(dispatch.response_size),
            } });
        } else {
            self.options.events.notify(.{ .response = .{
                .major = dispatch.major_version,
                .size = @intCast(dispatch.response_size),
            } });
        }
    }
};

/// Serve the RPC loop over a connected stream (equivalent to the C `rpcServer`),
/// returning why the connection ended (`ServeEnd`). Failures — including
/// `error.Timeout` when a read outlives the session's deadline — stay errors.
pub fn serveRpc(session: ServeSession, options: ServeOptions) !ServeEnd {
    var connection: Connection = .{ .session = session, .options = options };
    return connection.run();
}

// ---------------------------------------------------------------------------
// Client
// ---------------------------------------------------------------------------

pub const SendResult = struct {
    /// Raw KMS response bytes (allocator-allocated).
    data: []u8,
    /// HRESULT-style status (0 on success).
    status: i32,
};

/// One client connection: the byte streams, the requested transfer syntax and
/// the CallId sequence. Keeping them together also makes the CallId increment
/// impossible to forget at a call site.
///
/// The reader and the writer are borrowed, so a session must live in a stable
/// location (a `var` in the caller's frame) and is never copied after `init`.
pub const ClientSession = struct {
    allocator: Allocator,
    packet_reader: PacketReader,
    writer: *Io.Writer,
    /// Next DCE/RPC CallId; BIND and ALTER-CONTEXT consume one each.
    call_id: u32 = 2,
    /// Transfer syntax the next request is wrapped in. Callers narrow it from
    /// the BIND answer (the reference client sends its first request as NDR32).
    use_ndr64: bool = true,
    /// Requested in BIND; an ALTER-CONTEXT always asks for NDR32 only.
    use_btfn: bool = false,
    multiplexed: bool = false,

    /// Perform the BIND handshake and return what the server negotiated.
    pub fn bind(self: *ClientSession) !rpc.BindResult {
        const req = try rpc.buildBindRequest(self.allocator, rpc.packet_type.bind_req, self.call_id, .{
            .use_ndr64 = self.use_ndr64,
            .use_btfn = self.use_btfn,
            .multiplexed = self.multiplexed,
        });
        defer self.allocator.free(req);
        const resp_body = try self.transact(req);
        defer self.allocator.free(resp_body);
        return rpc.parseBindResponse(resp_body);
    }

    /// Bind the presentation context the BIND left out. The reference client
    /// (`rpcBindClient`) always wants NDR32 for its first request and adds it
    /// with an ALTER-CONTEXT when the server NACKed it — which a server does
    /// whenever NDR64 is available (Microsoft behavior), so this is also the
    /// sequence the Windows KMS client sends.
    pub fn alterContext(self: *ClientSession) !rpc.BindResult {
        // `buildBindRequest` attaches the NDR64/BTFN contexts to a BIND only, so
        // the request carries the single NDR32 item, as context id 0.
        const req = try rpc.buildBindRequest(self.allocator, rpc.packet_type.alter_context_req, self.call_id, .{
            .use_ndr64 = false,
            .use_btfn = false,
            .multiplexed = self.multiplexed,
        });
        defer self.allocator.free(req);
        const resp_body = try self.transact(req);
        defer self.allocator.free(resp_body);
        return rpc.parseBindResponse(resp_body);
    }

    /// Send a raw KMS request and return the raw KMS response.
    pub fn sendRequest(self: *ClientSession, kms_request: []const u8) !SendResult {
        const req = try rpc.wrapKmsRequest(self.allocator, kms_request, self.use_ndr64, self.call_id);
        defer self.allocator.free(req);
        const resp_body = try self.transact(req);
        defer self.allocator.free(resp_body);

        const parsed = rpc.parseKmsResponse(resp_body, self.use_ndr64);
        return .{
            .data = try self.allocator.dupe(u8, parsed.data),
            .status = parsed.status,
        };
    }

    /// Send one packet and return the reply body (allocator-owned).
    fn transact(self: *ClientSession, request: []const u8) ![]u8 {
        self.call_id += 1;
        try writeAndFlush(self.writer, request);
        return self.readPacket();
    }

    /// Read one RPC packet (header + body) and return its body bytes.
    fn readPacket(self: *ClientSession) ![]u8 {
        var header: rpc.RpcHeader = undefined;
        try self.packet_reader.read(std.mem.asBytes(&header));

        const frag_len: usize = header.frag_length;
        if (frag_len < rpc.header_size) return error.InvalidPacket;
        const body = try self.allocator.alloc(u8, frag_len - rpc.header_size);
        errdefer self.allocator.free(body);
        try self.packet_reader.read(body);
        return body;
    }
};

// ---------------------------------------------------------------------------
// Socket glue
// ---------------------------------------------------------------------------

/// `--address-family` as the address family to keep, or null for either.
fn familyFilter(address_family: u8) ?Io.net.IpAddress.Family {
    return switch (address_family) {
        4 => .ip4,
        6 => .ip6,
        else => null,
    };
}

/// Connect to `address:port`, accepting an IPv4/IPv6 literal (scope ids
/// included) or a host name. `address_family` (0 = any, 4 = IPv4-only,
/// 6 = IPv6-only) filters the address family.
pub fn connect(io: Io, address: []const u8, port: u16, address_family: u8) !Io.net.Stream {
    // Literals first: a `HostName` cannot carry an IPv6 literal.
    if (Io.net.IpAddress.resolve(io, address, port)) |ip| {
        return connectIpAddress(io, ip, address_family);
    } else |_| {}

    const host = try Io.net.HostName.init(address);
    // `HostName.connect` races every resolved address and returns the first
    // success, but has no family filter; a filtered connect stays manual.
    if (familyFilter(address_family) == null) {
        return Io.net.HostName.connect(host, io, port, .{ .mode = .stream });
    }
    return connectHostName(io, host, port, address_family);
}

/// Connect to a parsed IP literal, rejecting a mismatched address family.
fn connectIpAddress(io: Io, ip: Io.net.IpAddress, address_family: u8) !Io.net.Stream {
    if (familyFilter(address_family)) |wanted| {
        if (std.meta.activeTag(ip) != wanted) return error.AddressFamilyMismatch;
    }
    return Io.net.IpAddress.connect(&ip, io, .{ .mode = .stream });
}

/// Resolve `host` and connect to the first reachable address, filtering by
/// `address_family` (mirrors the C `getaddrinfo` `ai_family` behavior). The
/// standard `HostName.connect` cannot express this filter.
fn connectHostName(io: Io, host: Io.net.HostName, port: u16, address_family: u8) !Io.net.Stream {
    const family = familyFilter(address_family);

    var canonical_buf: [Io.net.HostName.max_len]u8 = undefined;
    var result_buf: [32]Io.net.HostName.LookupResult = undefined;
    var queue: Io.Queue(Io.net.HostName.LookupResult) = .init(&result_buf);

    try Io.net.HostName.lookup(host, io, &queue, .{
        .port = port,
        .canonical_name_buffer = &canonical_buf,
        .family = family,
    });

    var last_err: ?Io.net.IpAddress.ConnectError = null;
    while (queue.getOne(io)) |result| {
        switch (result) {
            .address => |addr| {
                const stream = Io.net.IpAddress.connect(&addr, io, .{ .mode = .stream }) catch |err| {
                    last_err = err;
                    continue;
                };
                return stream;
            },
            .canonical_name => continue,
        }
    } else |err| switch (err) {
        error.Canceled => return err,
        error.Closed => {},
    }

    return last_err orelse error.UnknownHostName;
}

/// Listen on `address:port`.
pub fn listen(io: Io, address: []const u8, port: u16) !Io.net.Server {
    const ip = try Io.net.IpAddress.resolve(io, address, port);
    return Io.net.IpAddress.listen(&ip, io, .{ .reuse_address = true });
}

/// True when the IPv4 address `ip` (numeric, host byte order) is
/// private/reserved. Public addresses return false.
fn isPrivateIpv4(ip: u32) bool {
    return (ip & 0xff000000) == 0x7f000000 or // 127/8 localhost
        (ip & 0xffff0000) == 0xc0a80000 or // 192.168/16
        (ip & 0xffff0000) == 0xa9fe0000 or // 169.254/16 link-local
        (ip & 0xff000000) == 0x0a000000 or // 10/8
        (ip & 0xfff00000) == 0xac100000; // 172.16/12
}

/// True when `bytes` is an IPv4-mapped IPv6 address (::ffff:a.b.c.d), which a
/// dual-stack IPv6 socket reports for IPv4 peers.
fn isIpv4Mapped(bytes: [16]u8) bool {
    for (bytes[0..10]) |b| {
        if (b != 0) return false;
    }
    return bytes[10] == 0xff and bytes[11] == 0xff;
}

/// True when `addr` is a private/reserved IPv4 or IPv6 address (mirrors the
/// C `isPrivateIPAddress` in network.c). Public addresses return false.
pub fn isPrivateIPAddress(addr: *const std.posix.sockaddr) bool {
    return switch (addr.family) {
        std.posix.AF.INET => blk: {
            const in: *const std.posix.sockaddr.in = @ptrCast(@alignCast(addr));
            // sockaddr_in.addr is stored in network byte order; on a
            // little-endian host this yields the numeric value via byte swap.
            break :blk isPrivateIpv4(@byteSwap(in.addr));
        },
        std.posix.AF.INET6 => blk: {
            const in6: *const std.posix.sockaddr.in6 = @ptrCast(@alignCast(addr));
            // A dual-stack socket presents IPv4 peers as IPv4-mapped
            // addresses; judge them by the embedded IPv4 address.
            if (isIpv4Mapped(in6.addr)) {
                break :blk isPrivateIpv4(std.mem.readInt(u32, in6.addr[12..16], .big));
            }
            const qword0 = std.mem.readInt(u64, in6.addr[0..8], .big);
            const qword1 = std.mem.readInt(u64, in6.addr[8..16], .big);
            const word0 = std.mem.readInt(u16, in6.addr[0..2], .big);
            const is_loopback = qword0 == 0 and qword1 == 1; // ::1
            const is_global = (word0 & 0xe000) == 0x2000; // 2000::/3
            break :blk !(is_global and !is_loopback);
        },
        else => false,
    };
}

/// True when `addr` is a loopback address: 127.0.0.0/8 (including the
/// IPv4-mapped form a dual-stack socket reports) or ::1.
fn isLoopbackAddress(addr: *const std.posix.sockaddr) bool {
    return switch (addr.family) {
        std.posix.AF.INET => blk: {
            const in: *const std.posix.sockaddr.in = @ptrCast(@alignCast(addr));
            break :blk (@byteSwap(in.addr) & 0xff000000) == 0x7f000000;
        },
        std.posix.AF.INET6 => blk: {
            const in6: *const std.posix.sockaddr.in6 = @ptrCast(@alignCast(addr));
            if (isIpv4Mapped(in6.addr)) {
                const ip4 = std.mem.readInt(u32, in6.addr[12..16], .big);
                break :blk (ip4 & 0xff000000) == 0x7f000000;
            }
            const qword0 = std.mem.readInt(u64, in6.addr[0..8], .big);
            const qword1 = std.mem.readInt(u64, in6.addr[8..16], .big);
            break :blk qword0 == 0 and qword1 == 1; // ::1
        },
        else => false,
    };
}

/// Read the connected socket's peer address, or null when it cannot be
/// determined.
///
/// `std.posix.getpeername` cannot be used here: it maps `EINVAL` to
/// `unreachable`, and Darwin reports `EINVAL` for a connection the peer has
/// already reset (verified: an RST in the receive queue makes `getpeername`
/// fail, a graceful FIN leaves it working). A client that gives up on a slow
/// server would then panic the serving task instead of surfacing as "unknown
/// peer". Calling the syscall directly keeps every failure — including that
/// one — a value, which is what these callers expect: they race with a peer
/// that can vanish at any moment.
fn peerAddress(fd: std.posix.socket_t) ?std.posix.sockaddr.storage {
    var addr: std.posix.sockaddr.storage align(8) = undefined;
    var addrlen: std.posix.socklen_t = @sizeOf(std.posix.sockaddr.storage);
    const rc = std.posix.system.getpeername(fd, @ptrCast(&addr), &addrlen);
    if (std.posix.errno(rc) != .SUCCESS) return null;
    return addr;
}

/// True when the connected socket's peer is a loopback address (the container
/// HEALTHCHECK probes from here). Returns false when the peer address cannot
/// be determined.
pub fn isLoopbackPeer(fd: std.posix.socket_t) bool {
    const addr = peerAddress(fd) orelse return false;
    return isLoopbackAddress(@ptrCast(&addr));
}

/// True when the connected socket's peer address is private. Returns false
/// when the peer address cannot be determined (the C `serveClient` closes such
/// connections), so callers treat false as "reject".
pub fn isClientPrivate(fd: std.posix.socket_t) bool {
    const addr = peerAddress(fd) orelse return false;
    return isPrivateIPAddress(@ptrCast(&addr));
}

/// Format the connected socket's peer address into `buf` (e.g. "1.2.3.4:1688").
/// Returns "unknown peer" when the peer address cannot be determined (see
/// `peerAddress`) — the peer is already gone, so it can no longer be named.
pub fn formatPeer(fd: std.posix.socket_t, buf: []u8) []const u8 {
    const addr = peerAddress(fd) orelse return "unknown peer";
    var w = Io.Writer.fixed(buf);
    sockaddrToIpAddress(@ptrCast(&addr)).format(&w) catch return "unknown peer";
    return w.buffered();
}

// ---------------------------------------------------------------------------
// Interface enumeration (`getifaddrs`; used by ip-protection level 1)
// ---------------------------------------------------------------------------

const Ifaddrs = extern struct {
    ifa_next: ?*Ifaddrs,
    ifa_name: ?[*:0]u8,
    ifa_flags: c_uint,
    ifa_addr: ?*std.posix.sockaddr,
    ifa_netmask: ?*std.posix.sockaddr,
    ifa_dstaddr: ?*std.posix.sockaddr,
    ifa_data: ?*anyopaque,
};

extern "c" fn getifaddrs(ifap: *?*Ifaddrs) c_int;
extern "c" fn freeifaddrs(ifa: *Ifaddrs) void;

fn sockaddrToIpAddress(addr: *const std.posix.sockaddr) Io.net.IpAddress {
    switch (addr.family) {
        std.posix.AF.INET => {
            const in: *const std.posix.sockaddr.in = @ptrCast(@alignCast(addr));
            var ip4: Io.net.Ip4Address = .{ .bytes = undefined, .port = std.mem.bigToNative(u16, in.port) };
            @memcpy(&ip4.bytes, std.mem.asBytes(&in.addr));
            return .{ .ip4 = ip4 };
        },
        std.posix.AF.INET6 => {
            const in6: *const std.posix.sockaddr.in6 = @ptrCast(@alignCast(addr));
            return .{ .ip6 = .{ .bytes = in6.addr, .port = std.mem.bigToNative(u16, in6.port) } };
        },
        else => unreachable,
    }
}

/// Enumerate the host's private IP addresses (mirrors the C
/// `getPrivateIPAddresses`). Returns an allocator-owned list with port 0 set.
pub fn getPrivateIPAddresses(allocator: Allocator) ![]Io.net.IpAddress {
    var ifap: ?*Ifaddrs = null;
    if (getifaddrs(&ifap) != 0) return error.GetIfAddrsFailed;
    defer if (ifap) |ifa| freeifaddrs(ifa);

    var list: std.ArrayList(Io.net.IpAddress) = .empty;
    errdefer list.deinit(allocator);

    var cur = ifap;
    while (cur) |ifa| : (cur = ifa.ifa_next) {
        const addr = ifa.ifa_addr orelse continue;
        if (!isPrivateIPAddress(addr)) continue;
        // Skip IPv6 link-local (fe80::/10): it cannot be bound without a scope
        // id and is unreachable from other hosts anyway.
        if (addr.family == std.posix.AF.INET6) {
            const in6: *const std.posix.sockaddr.in6 = @ptrCast(@alignCast(addr));
            if (in6.addr[0] == 0xFE and (in6.addr[1] & 0xC0) == 0x80) continue;
        }
        try list.append(allocator, sockaddrToIpAddress(addr));
    }

    return list.toOwnedSlice(allocator);
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const kmsdata = @import("vlmzsd").kmsdata;

const TestData = struct {
    data: kmsdata.KmsData,

    fn deinit(self: *TestData, allocator: Allocator) void {
        self.data.deinit(allocator);
    }
};

fn loadTestData(allocator: Allocator) !TestData {
    const raw: []const u8 = @embedFile("vlmcsd.kmd");
    const data = try kmsdata.parse(allocator, raw);
    return .{ .data = data };
}

/// Request time used by the wire tests: the same instant `makeBase` stamps into
/// `client_time`, so a clock-dependent check behaves deterministically.
const test_now_unix: i64 = 1_700_000_000;

fn fixedNowUnix(context: ?*anyopaque) i64 {
    _ = context;
    return test_now_unix;
}

const fixed_clock: Clock = .{ .now_unix = fixedNowUnix };

fn makeBase(data: *const kmsdata.KmsData) kms.Request {
    var base: kms.Request = std.mem.zeroes(kms.Request);
    base.version = 6 << 16;
    base.license_status = 1;
    base.kms_id = data.kms()[0].guid;
    base.app_id = data.apps()[0].guid;
    base.act_id = data.kms()[0].guid;
    base.cmid = [16]u8{ 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 };
    base.n_policy = 25;
    base.client_time = kms.u64ToFileTime(kms.unixTimeToFileTime(test_now_unix));
    for ("test-host", 0..) |c, i| base.workstation_name[i] = c;
    return base;
}

fn parseHeader(bytes: []const u8) rpc.RpcHeader {
    var header: rpc.RpcHeader = undefined;
    @memcpy(std.mem.asBytes(&header), bytes[0..rpc.header_size]);
    return header;
}

test "isPrivateIPAddress ipv4" {
    const ipv4 = struct {
        fn addr(a: u8, b: u8, c: u8, d: u8) std.posix.sockaddr.in {
            var sa: std.posix.sockaddr.in = .{ .port = 0, .addr = 0 };
            // sockaddr_in.addr holds the address in network byte order.
            const value = (@as(u32, a) << 24) | (@as(u32, b) << 16) | (@as(u32, c) << 8) | d;
            std.mem.writeInt(u32, std.mem.asBytes(&sa.addr)[0..4], value, .big);
            return sa;
        }
    };

    inline for (.{
        .{ 127, 0, 0, 1, true }, // localhost
        .{ 10, 1, 2, 3, true }, // 10/8
        .{ 192, 168, 1, 1, true }, // 192.168/16
        .{ 169, 254, 1, 1, true }, // 169.254/16
        .{ 172, 16, 0, 1, true }, // 172.16/12
        .{ 172, 31, 255, 255, true }, // 172.16/12 end
        .{ 8, 8, 8, 8, false }, // public
        .{ 172, 32, 0, 1, false }, // outside 172.16/12
    }) |case| {
        var sa = ipv4.addr(case[0], case[1], case[2], case[3]);
        try std.testing.expectEqual(case[4], isPrivateIPAddress(@ptrCast(&sa)));
    }
}

test "IPv4-mapped address private detection" {
    // A dual-stack socket reports IPv4 peers as ::ffff:a.b.c.d; extract the
    // embedded IPv4 for an exact decision — docs/migration.md §5.
    const mapped = struct {
        fn addr(octets: [4]u8) std.posix.sockaddr.in6 {
            var sa = std.mem.zeroes(std.posix.sockaddr.in6);
            sa.family = std.posix.AF.INET6;
            sa.addr[10] = 0xFF;
            sa.addr[11] = 0xFF;
            @memcpy(sa.addr[12..16], &octets);
            return sa;
        }
    };

    var pub6 = mapped.addr(.{ 8, 8, 8, 8 }); // public IPv4
    try std.testing.expect(!isPrivateIPAddress(@ptrCast(&pub6)));

    var priv6 = mapped.addr(.{ 10, 0, 0, 1 }); // 10/8 private
    try std.testing.expect(isPrivateIPAddress(@ptrCast(&priv6)));
}

test "isPrivateIPAddress ipv6" {
    const ipv6 = struct {
        fn addr(bytes: [16]u8) std.posix.sockaddr.in6 {
            return .{ .port = 0, .flowinfo = 0, .addr = bytes, .scope_id = 0 };
        }
    };

    // ::1 (loopback) → private.
    {
        var sa = ipv6.addr([_]u8{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 });
        try std.testing.expect(isPrivateIPAddress(@ptrCast(&sa)));
    }
    // 2001:db8::1 (2000::/3) → public.
    {
        var sa = ipv6.addr([_]u8{ 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 });
        try std.testing.expect(!isPrivateIPAddress(@ptrCast(&sa)));
    }
    // fe80::1 (link-local) → private.
    {
        var sa = ipv6.addr([_]u8{ 0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 });
        try std.testing.expect(isPrivateIPAddress(@ptrCast(&sa)));
    }
    // fd00::1 (ULA) → private.
    {
        var sa = ipv6.addr([_]u8{ 0xfd, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 });
        try std.testing.expect(isPrivateIPAddress(@ptrCast(&sa)));
    }
    // ::ffff:127.0.0.1 (IPv4-mapped loopback) → private.
    {
        var sa = ipv6.addr([_]u8{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 127, 0, 0, 1 });
        try std.testing.expect(isPrivateIPAddress(@ptrCast(&sa)));
    }
    // ::ffff:8.8.8.8 (IPv4-mapped public) → public.
    {
        var sa = ipv6.addr([_]u8{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 8, 8, 8, 8 });
        try std.testing.expect(!isPrivateIPAddress(@ptrCast(&sa)));
    }
}

test "isLoopbackAddress" {
    const ipv4 = struct {
        fn addr(a: u8, b: u8, c: u8, d: u8) std.posix.sockaddr.in {
            var sa: std.posix.sockaddr.in = .{ .port = 0, .addr = 0 };
            const value = (@as(u32, a) << 24) | (@as(u32, b) << 16) | (@as(u32, c) << 8) | d;
            std.mem.writeInt(u32, std.mem.asBytes(&sa.addr)[0..4], value, .big);
            return sa;
        }
    };
    const ipv6 = struct {
        fn addr(bytes: [16]u8) std.posix.sockaddr.in6 {
            return .{ .port = 0, .flowinfo = 0, .addr = bytes, .scope_id = 0 };
        }
    };

    // IPv4: loopback, private-but-not-loopback, public.
    {
        var sa = ipv4.addr(127, 0, 0, 1);
        try std.testing.expect(isLoopbackAddress(@ptrCast(&sa)));
    }
    {
        var sa = ipv4.addr(10, 0, 0, 1); // private, not loopback
        try std.testing.expect(!isLoopbackAddress(@ptrCast(&sa)));
    }
    {
        var sa = ipv4.addr(8, 8, 8, 8); // public
        try std.testing.expect(!isLoopbackAddress(@ptrCast(&sa)));
    }
    // IPv6: ::1 loopback vs global.
    {
        var sa = ipv6.addr([_]u8{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 });
        try std.testing.expect(isLoopbackAddress(@ptrCast(&sa)));
    }
    {
        var sa = ipv6.addr([_]u8{ 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 });
        try std.testing.expect(!isLoopbackAddress(@ptrCast(&sa)));
    }
    // IPv4-mapped: ::ffff:127.0.0.1 loopback vs ::ffff:8.8.8.8 public.
    {
        var sa = ipv6.addr([_]u8{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 127, 0, 0, 1 });
        try std.testing.expect(isLoopbackAddress(@ptrCast(&sa)));
    }
    {
        var sa = ipv6.addr([_]u8{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 8, 8, 8, 8 });
        try std.testing.expect(!isLoopbackAddress(@ptrCast(&sa)));
    }
}

test "serveRpc end-to-end (bind + v6 request)" {
    const alloc = std.testing.allocator;
    var td = try loadTestData(alloc);
    defer td.deinit(alloc);

    var cfg = kms.ServerConfig{ .data = &td.data };
    const base = makeBase(&td.data);

    var prng: std.Random.DefaultPrng = .init(0x1234_5678);
    const rng = prng.random();

    // Client-side packets: BIND request followed by a KMS request.
    const bind_req = try rpc.buildBindRequest(alloc, rpc.packet_type.bind_req, 2, .{ .use_ndr64 = false });
    defer alloc.free(bind_req);

    var request_v6: kms.RequestV6 = undefined;
    kms.createRequestV6(&request_v6, &base, rng);
    const rpc_req = try rpc.wrapKmsRequest(alloc, std.mem.asBytes(&request_v6), false, 3);
    defer alloc.free(rpc_req);

    const input = try std.mem.concat(alloc, u8, &.{ bind_req, rpc_req });
    defer alloc.free(input);

    var reader = Io.Reader.fixed(input);
    var packet_reader: PacketReader = .init(.{}, &reader, &.{});
    var output_buf: [4096]u8 align(4) = undefined;
    var writer = Io.Writer.fixed(&output_buf);

    // The stream ends after the request: `serveRpc` reports the peer close.
    const end: ServeEnd = try serveRpc(.{ .allocator = alloc, .packet_reader = &packet_reader, .writer = &writer, .rng = rng }, .{ .cfg = &cfg, .clock = fixed_clock });
    try std.testing.expectEqual(ServeEnd.peer_closed, end);

    const output = writer.buffered();
    try std.testing.expect(output.len >= 2 * rpc.header_size);

    // First packet: BIND_ACK.
    var pos: usize = 0;
    const bind_ack_header = parseHeader(output[pos..]);
    try std.testing.expectEqual(rpc.packet_type.bind_ack, bind_ack_header.packet_type);
    pos += bind_ack_header.frag_length;

    // Second packet: RESPONSE.
    const resp_header = parseHeader(output[pos..]);
    try std.testing.expectEqual(rpc.packet_type.response, resp_header.packet_type);
    const resp_body = output[pos + rpc.header_size .. pos + resp_header.frag_length];

    const parsed = rpc.parseKmsResponse(resp_body, false);
    try std.testing.expectEqual(@as(i32, 0), parsed.status);
    try std.testing.expect(parsed.data.len > 0);

    // Verify the KMS response against the original client request.
    var request_client = request_v6;
    var resp: kms.ResponseV6 = undefined;
    const result = kms.decryptResponseV6(&resp, parsed.data.len, @constCast(parsed.data), &request_client, null);
    try std.testing.expect(result.ok());
}

test "ALTER-CONTEXT response carries no secondary address" {
    const alloc = std.testing.allocator;
    var td = try loadTestData(alloc);
    defer td.deinit(alloc);

    var cfg = kms.ServerConfig{ .data = &td.data };
    var prng: std.Random.DefaultPrng = .init(0x9e37_79b9);

    const alter_req = try rpc.buildBindRequest(alloc, rpc.packet_type.alter_context_req, 4, .{});
    defer alloc.free(alter_req);

    var reader = Io.Reader.fixed(alter_req);
    var packet_reader: PacketReader = .init(.{}, &reader, &.{});
    var output_buf: [4096]u8 align(4) = undefined;
    var writer = Io.Writer.fixed(&output_buf);

    const end: ServeEnd = try serveRpc(.{
        .allocator = alloc,
        .packet_reader = &packet_reader,
        .writer = &writer,
        .rng = prng.random(),
    }, .{
        .cfg = &cfg,
        .clock = fixed_clock,
        .secondary_address = "1688",
    });
    try std.testing.expectEqual(ServeEnd.peer_closed, end); // the trailing close

    const output = writer.buffered();
    const header = parseHeader(output);
    try std.testing.expectEqual(rpc.packet_type.alter_context_ack, header.packet_type);

    const body = output[rpc.header_size..header.frag_length];
    // `rpcBind` leaves `SecondaryAddressLength` at 0 for ALTER-CONTEXT, so
    // `NumResults` sits at offset 12 and the body is 16 + 24 * ctx-items bytes
    // — docs/migration.md §4.2.
    try std.testing.expectEqual(@as(u16, 0), std.mem.readInt(u16, body[8..10], .little));
    try std.testing.expectEqual(@as(u32, 1), std.mem.readInt(u32, body[12..16], .little));
    try std.testing.expectEqual(@as(usize, 40), body.len);
}

test "BIND response layout" {
    const alloc = std.testing.allocator;

    const bind_req = try rpc.buildBindRequest(alloc, rpc.packet_type.bind_req, 2, .{ .use_ndr64 = true });
    defer alloc.free(bind_req);

    var negotiation = rpc.BindNegotiation{};
    const body = try rpc.buildBindResponse(alloc, bind_req[rpc.header_size..], 7, .{
        .use_ndr64 = true,
        .secondary_address = "1688",
    }, &negotiation);
    defer alloc.free(body);

    // MaxXmitFrag/MaxRecvFrag are echoed verbatim, then the caller's AssocGroup.
    try std.testing.expectEqualSlices(u8, bind_req[rpc.header_size..][0..4], body[0..4]);
    try std.testing.expectEqual(@as(u32, 7), std.mem.readInt(u32, body[4..8], .little));
    // Secondary address: length includes the NUL, then the port string; the
    // result block starts at the next 4-byte boundary — docs/migration.md §4.2.
    try std.testing.expectEqual(@as(u16, 5), std.mem.readInt(u16, body[8..10], .little));
    try std.testing.expectEqualSlices(u8, "1688", body[10..14]);
    try std.testing.expectEqual(@as(u32, 2), std.mem.readInt(u32, body[16..20], .little));
    try std.testing.expectEqual(@as(usize, 20 + 2 * 24), body.len);

    // Context 0 (NDR32) is NACKed while NDR64 is available; context 1 (NDR64)
    // is accepted with syntax version 1.
    const ndr32_result = body[20..44];
    try std.testing.expectEqual(rpc.bind_nack, std.mem.readInt(u16, ndr32_result[0..2], .little));
    try std.testing.expectEqual(rpc.syntax_unsupported, std.mem.readInt(u16, ndr32_result[2..4], .little));
    const ndr64_result = body[44..68];
    try std.testing.expectEqual(rpc.bind_accept, std.mem.readInt(u16, ndr64_result[0..2], .little));
    try std.testing.expectEqualSlices(u8, rpc.transfer_syntax_ndr64[0..], ndr64_result[4..20]);
    try std.testing.expectEqual(@as(u32, 1), std.mem.readInt(u32, ndr64_result[20..24], .little));
}

test "disconnect-per-request ends the loop after the response" {
    const alloc = std.testing.allocator;
    var td = try loadTestData(alloc);
    defer td.deinit(alloc);

    var cfg = kms.ServerConfig{ .data = &td.data };
    const base = makeBase(&td.data);
    var prng: std.Random.DefaultPrng = .init(0x2545_f491);
    const rng = prng.random();

    const bind_req = try rpc.buildBindRequest(alloc, rpc.packet_type.bind_req, 2, .{ .use_ndr64 = false });
    defer alloc.free(bind_req);

    var request_v6: kms.RequestV6 = undefined;
    kms.createRequestV6(&request_v6, &base, rng);
    const rpc_req = try rpc.wrapKmsRequest(alloc, std.mem.asBytes(&request_v6), false, 3);
    defer alloc.free(rpc_req);

    const input = try std.mem.concat(alloc, u8, &.{ bind_req, rpc_req });
    defer alloc.free(input);

    var reader = Io.Reader.fixed(input);
    var packet_reader: PacketReader = .init(.{}, &reader, &.{});
    var output_buf: [8192]u8 align(4) = undefined;
    var writer = Io.Writer.fixed(&output_buf);

    const end: ServeEnd = try serveRpc(.{ .allocator = alloc, .packet_reader = &packet_reader, .writer = &writer, .rng = rng }, .{
        .cfg = &cfg,
        .clock = fixed_clock,
        .disconnect_per_request = true,
    });
    // The loop stops after the RESPONSE instead of waiting for another request,
    // and says so — the caller logs `closed: after request`. A BIND_ACK alone
    // does not disconnect: the C reference only reacts to RESPONSE/FAULT.
    try std.testing.expectEqual(ServeEnd.after_request, end);

    const output = writer.buffered();
    const ack_header = parseHeader(output);
    try std.testing.expectEqual(rpc.packet_type.bind_ack, ack_header.packet_type);
    const resp_header = parseHeader(output[ack_header.frag_length..]);
    try std.testing.expectEqual(rpc.packet_type.response, resp_header.packet_type);
    // Exactly those two packets, and nothing was awaited afterwards.
    try std.testing.expectEqual(output.len, @as(usize, ack_header.frag_length) + @as(usize, resp_header.frag_length));
}

test "the request clock is sampled per request, not per connection" {
    const alloc = std.testing.allocator;
    var td = try loadTestData(alloc);
    defer td.deinit(alloc);

    // `--check-client-time` compares each request's timestamp with the clock.
    var cfg = kms.ServerConfig{ .data = &td.data, .check_client_time = true };

    var prng: std.Random.DefaultPrng = .init(0x7a1d_b00c);
    const rng = prng.random();
    const bind_req = try rpc.buildBindRequest(alloc, rpc.packet_type.bind_req, 2, .{ .use_ndr64 = false });
    defer alloc.free(bind_req);

    // Two requests on one connection, five hours apart — beyond the 4-hour
    // tolerance, so both can only be accepted if the clock advances with them.
    const later = test_now_unix + 5 * 60 * 60;

    var base1 = makeBase(&td.data);
    base1.client_time = kms.u64ToFileTime(kms.unixTimeToFileTime(test_now_unix));
    var request1: kms.RequestV6 = undefined;
    kms.createRequestV6(&request1, &base1, rng);
    const rpc_req1 = try rpc.wrapKmsRequest(alloc, std.mem.asBytes(&request1), false, 3);
    defer alloc.free(rpc_req1);

    var base2 = makeBase(&td.data);
    base2.client_time = kms.u64ToFileTime(kms.unixTimeToFileTime(later));
    var request2: kms.RequestV6 = undefined;
    kms.createRequestV6(&request2, &base2, rng);
    const rpc_req2 = try rpc.wrapKmsRequest(alloc, std.mem.asBytes(&request2), false, 4);
    defer alloc.free(rpc_req2);

    const input = try std.mem.concat(alloc, u8, &.{ bind_req, rpc_req1, rpc_req2 });
    defer alloc.free(input);

    var reader = Io.Reader.fixed(input);
    var packet_reader: PacketReader = .init(.{}, &reader, &.{});
    var output_buf: [8192]u8 align(4) = undefined;
    var writer = Io.Writer.fixed(&output_buf);

    const Sink = struct {
        samples: u32 = 0,
        responses: u32 = 0,
        rejections: u32 = 0,

        /// Advances five hours per sample, so each request is compared against
        /// its own instant. The first sample is the first request's time.
        fn now(context: ?*anyopaque) i64 {
            const self: *@This() = @ptrCast(@alignCast(context.?));
            const sample = test_now_unix + @as(i64, self.samples) * 5 * 60 * 60;
            self.samples += 1;
            return sample;
        }

        fn onEvent(context: ?*anyopaque, event: Event) void {
            const self: *@This() = @ptrCast(@alignCast(context.?));
            switch (event) {
                .response => self.responses += 1,
                .request_rejected => self.rejections += 1,
                else => {},
            }
        }
    };
    var sink: Sink = .{};

    const end: ServeEnd = try serveRpc(.{ .allocator = alloc, .packet_reader = &packet_reader, .writer = &writer, .rng = rng }, .{
        .cfg = &cfg,
        .clock = .{ .context = &sink, .now_unix = Sink.now },
        .events = .{ .context = &sink, .callback = Sink.onEvent },
    });
    try std.testing.expectEqual(ServeEnd.peer_closed, end);

    // One sample per REQUEST (BIND is not one), and both accepted: a clock
    // sampled once per connection would compare request 2 against request 1's
    // instant and reject it with 0xC004F06C.
    try std.testing.expectEqual(@as(u32, 2), sink.samples);
    try std.testing.expectEqual(@as(u32, 2), sink.responses);
    try std.testing.expectEqual(@as(u32, 0), sink.rejections);
}

test "ALTER-CONTEXT lets an NDR32 request follow a NDR64-only BIND" {
    const alloc = std.testing.allocator;
    var td = try loadTestData(alloc);
    defer td.deinit(alloc);

    var cfg = kms.ServerConfig{ .data = &td.data };
    const base = makeBase(&td.data);
    var prng: std.Random.DefaultPrng = .init(0x0bad_c0de);
    const rng = prng.random();

    // The wire sequence of the reference client: BIND offering both syntaxes,
    // then — because the server NACKs NDR32 while NDR64 is available — an
    // ALTER-CONTEXT that binds NDR32, then an NDR32 request on context 0.
    const bind_req = try rpc.buildBindRequest(alloc, rpc.packet_type.bind_req, 2, .{ .use_ndr64 = true });
    defer alloc.free(bind_req);
    const alter_req = try rpc.buildBindRequest(alloc, rpc.packet_type.alter_context_req, 3, .{});
    defer alloc.free(alter_req);

    var request_v6: kms.RequestV6 = undefined;
    kms.createRequestV6(&request_v6, &base, rng);
    const rpc_req = try rpc.wrapKmsRequest(alloc, std.mem.asBytes(&request_v6), false, 4);
    defer alloc.free(rpc_req);

    const input = try std.mem.concat(alloc, u8, &.{ bind_req, alter_req, rpc_req });
    defer alloc.free(input);

    var reader = Io.Reader.fixed(input);
    var packet_reader: PacketReader = .init(.{}, &reader, &.{});
    var output_buf: [8192]u8 align(4) = undefined;
    var writer = Io.Writer.fixed(&output_buf);

    const end: ServeEnd = try serveRpc(.{ .allocator = alloc, .packet_reader = &packet_reader, .writer = &writer, .rng = rng }, .{
        .cfg = &cfg,
        .clock = fixed_clock,
        .use_ndr64 = true,
        .secondary_address = "1688",
    });
    try std.testing.expectEqual(ServeEnd.peer_closed, end);

    const output = writer.buffered();
    const ack_header = parseHeader(output);
    try std.testing.expectEqual(rpc.packet_type.bind_ack, ack_header.packet_type);

    const alter_offset: usize = ack_header.frag_length;
    const alter_header = parseHeader(output[alter_offset..]);
    try std.testing.expectEqual(rpc.packet_type.alter_context_ack, alter_header.packet_type);

    const resp_offset: usize = alter_offset + alter_header.frag_length;
    const resp_header = parseHeader(output[resp_offset..]);
    try std.testing.expectEqual(rpc.packet_type.response, resp_header.packet_type);

    // A RESPONSE — not the `nca_unk_if` FAULT an unbound context would produce:
    // the ALTER-CONTEXT made context 0 the NDR32 context on the server too.
    const resp_body = output[resp_offset + rpc.header_size .. resp_offset + resp_header.frag_length];
    const parsed = rpc.parseKmsResponse(resp_body, false);
    try std.testing.expectEqual(@as(i32, 0), parsed.status);
    try std.testing.expect(parsed.data.len > 0);
}

test "client bind handshake" {
    const alloc = std.testing.allocator;

    // Server side produces a BIND_ACK for the client's BIND request.
    const server_bind_req = try rpc.buildBindRequest(alloc, rpc.packet_type.bind_req, 2, .{ .use_ndr64 = false });
    defer alloc.free(server_bind_req);

    var negotiation = rpc.BindNegotiation{};
    const resp_body = try rpc.buildBindResponse(
        alloc,
        server_bind_req[rpc.header_size..],
        0,
        .{ .secondary_address = "1688" },
        &negotiation,
    );
    defer alloc.free(resp_body);

    var response_packet = try alloc.alloc(u8, rpc.header_size + resp_body.len);
    defer alloc.free(response_packet);

    var header: rpc.RpcHeader = undefined;
    rpc.createRpcHeader(&header, rpc.packet_type.bind_ack, @intCast(rpc.header_size + resp_body.len), 2, rpc.packet_flags.first | rpc.packet_flags.last);
    @memcpy(response_packet[0..rpc.header_size], std.mem.asBytes(&header));
    @memcpy(response_packet[rpc.header_size..], resp_body);

    // Client performs the handshake against the canned response.
    var reader = Io.Reader.fixed(response_packet);
    var request_buf: [4096]u8 align(4) = undefined;
    var writer = Io.Writer.fixed(&request_buf);
    var session: ClientSession = .{
        .allocator = alloc,
        .packet_reader = .init(.{}, &reader, &.{}),
        .writer = &writer,
        .use_ndr64 = false,
    };

    const result = try session.bind();
    try std.testing.expect(result.has_ndr32);
    try std.testing.expect(!result.has_ndr64);

    const sent = writer.buffered();
    try std.testing.expect(sent.len >= rpc.header_size);
    const sent_header = parseHeader(sent);
    try std.testing.expectEqual(rpc.packet_type.bind_req, sent_header.packet_type);
}

/// Test helper: a TCP connection whose ends are both owned by the test, so
/// sending from the client end makes the accepted end readable. (Not
/// `Io.net.Socket.createPair`: its only families are `.ip4`/`.ip6`, and
/// `socketpair(2)` implements neither — errno 95 on Linux, 102 on macOS.) This
/// module is built without libc — a `std.c` reference fails to compile on Linux —
/// so no pipe either.
const StreamPair = struct {
    server: Io.net.Server,
    /// The end the test reads from.
    accepted: Io.net.Stream,
    /// The end the test sends from.
    client: Io.net.Stream,
    client_open: bool = true,

    fn init(io: Io) !StreamPair {
        const addr = try Io.net.IpAddress.parse("127.0.0.1", 0);
        var server = try Io.net.IpAddress.listen(&addr, io, .{ .mode = .stream });
        errdefer server.deinit(io);
        const client = try Io.net.IpAddress.connect(&server.socket.address, io, .{ .mode = .stream });
        errdefer client.close(io);
        const accepted = try server.accept(io);
        return .{ .server = server, .accepted = accepted, .client = client };
    }

    fn deinit(self: *StreamPair, io: Io) void {
        self.closeClient(io);
        self.accepted.close(io);
        self.server.deinit(io);
    }

    fn closeClient(self: *StreamPair, io: Io) void {
        if (!self.client_open) return;
        self.client.close(io);
        self.client_open = false;
    }

    fn send(self: *StreamPair, io: Io, bytes: []const u8) !void {
        var buffer: [16]u8 = undefined;
        var writer = self.client.writer(io, &buffer);
        try writer.interface.writeAll(bytes);
        try writer.interface.flush();
    }

    /// Options that read from the accepted end with `timeout` as the deadline.
    fn readOptions(self: *StreamPair, io: Io, timeout: Io.Timeout) ReadOptions {
        return .{ .peer = .{ .io = io, .handle = self.accepted.socket.handle, .timeout = timeout } };
    }
};

/// The socket path never consults the `Io.Reader` argument; these tests pass an
/// empty one so both paths share a single call shape.
fn emptyReader() Io.Reader {
    return .fixed("");
}

/// Test helper: `n` milliseconds as a backend deadline.
fn ms(n: u64) Io.Timeout {
    return .{ .duration = .{ .raw = .{ .nanoseconds = @as(i96, n) * 1_000_000 }, .clock = .awake } };
}

fn elapsedMs(from: Io.Timestamp, io: Io) i96 {
    return @divTrunc(from.durationTo(Io.Timestamp.now(io, .awake)).nanoseconds, 1_000_000);
}

/// Test helper: park in `PacketReader.read` so the test can cancel it.
const ReadWaiter = struct {
    packet_reader: *PacketReader,
    buf: []u8,
    outcome: *?anyerror,

    fn run(self: ReadWaiter) Io.Cancelable!void {
        self.packet_reader.read(self.buf) catch |err| {
            self.outcome.* = err;
            return;
        };
        self.outcome.* = null;
    }
};

test "timeoutSeconds maps 0 to no deadline" {
    try std.testing.expect(timeoutSeconds(0) == .none);
    const timeout = timeoutSeconds(30);
    try std.testing.expectEqual(@as(i96, 30 * 1_000_000_000), timeout.duration.raw.nanoseconds);
    try std.testing.expectEqual(Io.Clock.awake, timeout.duration.clock);
}

// `--timeout`: a peer that accepts the connection and then says nothing must not
// park the read forever. The deadline comes from the backend, so it also holds
// for a *partial* packet, which is what the per-refill loop is for.
test "a silent peer hits the read deadline" {
    const alloc = std.testing.allocator;

    var threaded: std.Io.Threaded = .init(alloc, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var pair = try StreamPair.init(io);
    defer pair.deinit(io);

    var reader = emptyReader();
    var packet_reader: PacketReader = .init(pair.readOptions(io, ms(300)), &reader, &.{});
    var buffer: [16]u8 = undefined;

    const started = Io.Timestamp.now(io, .awake);
    const outcome = packet_reader.read(&buffer);
    const dt = elapsedMs(started, io);

    // 300 ms is the deadline; allow scheduling slack but insist the wait ended
    // long before the 1 s (whole-second) `--timeout` this stands in for.
    try std.testing.expectError(error.Timeout, outcome);
    try std.testing.expect(dt >= 200 and dt < 900);
}

// Shutdown: this replaces the old self-pipe/wake-fd arrangement. The wait is a
// backend cancelation point, so the group's cancelation request ends it by
// itself — no second fd to poll, no `--timeout` to wait out.
test "a cancelation request ends a parked read" {
    const alloc = std.testing.allocator;

    var threaded: std.Io.Threaded = .init(alloc, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var pair = try StreamPair.init(io);
    defer pair.deinit(io);

    var reader = emptyReader();
    var packet_reader: PacketReader = .init(pair.readOptions(io, .none), &reader, &.{});
    var buffer: [16]u8 = undefined;
    var outcome: ?anyerror = null;

    var group: Io.Group = .init;
    defer group.cancel(io);
    try group.concurrent(io, ReadWaiter.run, .{ReadWaiter{
        .packet_reader = &packet_reader, // no deadline: wait forever
        .buf = &buffer,
        .outcome = &outcome,
    }});

    try io.sleep(.{ .nanoseconds = 100 * 1_000_000 }, .awake);
    const started = Io.Timestamp.now(io, .awake);
    group.cancel(io); // requests cancelation, then blocks until the task returns
    const dt = elapsedMs(started, io);

    // "Promptly" = the cancelation alone ended it, not the (absent) deadline.
    try std.testing.expect(dt < 500);
    try std.testing.expectEqual(@as(?anyerror, error.Canceled), outcome);
}

// EOF is a zero-length message, not an error, and the bytes that *did* arrive
// are already in the caller's buffer.
test "a closed peer reads as end of stream" {
    const alloc = std.testing.allocator;

    var threaded: std.Io.Threaded = .init(alloc, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var pair = try StreamPair.init(io);
    defer pair.deinit(io);

    try pair.send(io, "ab");
    pair.closeClient(io);

    var reader = emptyReader();
    var packet_reader: PacketReader = .init(pair.readOptions(io, ms(500)), &reader, &.{});
    var buffer: [4]u8 = undefined;
    try std.testing.expectError(error.EndOfStream, packet_reader.read(&buffer));
    try std.testing.expectEqualStrings("ab", buffer[0..2]);
}

// Split packets are the norm (`writePacket` writes the header and the body
// separately), so the per-refill deadline must not treat a partial packet as a
// failure: the two halves arrive 100 ms apart and the read still completes.
test "a split packet arrives across refills" {
    const alloc = std.testing.allocator;

    var threaded: std.Io.Threaded = .init(alloc, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var pair = try StreamPair.init(io);
    defer pair.deinit(io);

    var group: Io.Group = .init;
    defer group.cancel(io);
    try group.concurrent(io, sendAfterDelay, .{ io, &pair });

    try pair.send(io, "abc"); // first half now, second half after 100 ms

    var reader = emptyReader();
    var packet_reader: PacketReader = .init(pair.readOptions(io, ms(1_000)), &reader, &.{});
    var buffer: [6]u8 = undefined;
    try packet_reader.read(&buffer);
    try std.testing.expectEqualStrings("abcdef", &buffer);
}

fn sendAfterDelay(io: Io, pair: *StreamPair) Io.Cancelable!void {
    try io.sleep(.{ .nanoseconds = 100 * 1_000_000 }, .awake);
    pair.send(io, "def") catch return;
}

/// Abort `pair`'s client end: `SO_LINGER 0` makes `close` send a RST instead of
/// a FIN — how a client that gave up on a slow server ends the connection.
fn resetClient(io: Io, pair: *StreamPair) !void {
    const linger: std.posix.linger = .{ .onoff = 1, .linger = 0 };
    try std.posix.setsockopt(pair.client.socket.handle, std.posix.SOL.SOCKET, std.posix.SO.LINGER, std.mem.asBytes(&linger));
    pair.closeClient(io);
}

/// Poll `formatPeer` until the kernel has processed the RST (only it knows
/// when), so the test does not depend on a fixed sleep.
fn peerAfterReset(io: Io, fd: std.posix.socket_t, buf: []u8) ![]const u8 {
    var attempt: u8 = 0;
    while (attempt < 100) : (attempt += 1) {
        const peer = formatPeer(fd, buf);
        if (std.mem.eql(u8, peer, "unknown peer")) return peer;
        try io.sleep(.{ .nanoseconds = 10 * 1_000_000 }, .awake);
    }
    return error.PeerNameNeverDropped;
}

// A peer that resets the connection can no longer be named, and asking must not
// panic. Darwin fails `getpeername` with EINVAL for a reset connection, and
// `std.posix.getpeername` maps EINVAL to `unreachable`; called from a serving
// task that aborts the whole process. On Linux the same state is ENOTCONN.
// The reset then reads as `ConnectionResetByPeer`, the error `serveClientThread`
// reports for this case.
test "a reset peer has no name and reads as a reset" {
    const alloc = std.testing.allocator;

    var threaded: std.Io.Threaded = .init(alloc, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var pair = try StreamPair.init(io);
    defer pair.deinit(io);

    try resetClient(io, &pair);

    var buf: [64]u8 = undefined;
    try std.testing.expectEqualStrings("unknown peer", try peerAfterReset(io, pair.accepted.socket.handle, &buf));
    try std.testing.expect(!isLoopbackPeer(pair.accepted.socket.handle));

    var reader = emptyReader();
    var packet_reader: PacketReader = .init(pair.readOptions(io, ms(1_000)), &reader, &.{});
    var packet: [8]u8 = undefined;
    try std.testing.expectError(error.ConnectionResetByPeer, packet_reader.read(&packet));
}

// The counterpart: a graceful close (FIN) leaves the address readable, so
// "unknown peer" stays diagnostic of a reset rather than of any close — the
// close line for a plain disconnect keeps naming the client.
test "a gracefully closed peer keeps its name" {
    const alloc = std.testing.allocator;

    var threaded: std.Io.Threaded = .init(alloc, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var pair = try StreamPair.init(io);
    defer pair.deinit(io);

    pair.closeClient(io);

    var buf: [64]u8 = undefined;
    const peer = formatPeer(pair.accepted.socket.handle, &buf);
    try std.testing.expect(std.mem.startsWith(u8, peer, "127.0.0.1:"));
    try std.testing.expect(isLoopbackPeer(pair.accepted.socket.handle));
}

const ServedPair = struct {
    end: ServeEnd,
    responses: []const u8,
};

/// Serve one connection over `pair`: write `input` from the client end — all at
/// once, or split at `split_after` with a 100 ms gap — run `serveRpc` on the
/// accepted end with `read_ahead` as the packet reader's storage, and return how
/// the connection ended plus the response bytes.
fn serveInput(
    alloc: Allocator,
    io: Io,
    pair: *StreamPair,
    cfg: *const kms.ServerConfig,
    rng: std.Random,
    input: []const u8,
    split_after: ?usize,
    read_ahead: []u8,
    out: []u8,
) !ServedPair {
    var group: Io.Group = .init;
    defer group.cancel(io);
    if (split_after) |cut| {
        const Split = struct {
            io: Io,
            pair: *StreamPair,
            first: []const u8,
            rest: []const u8,

            fn run(self: @This()) Io.Cancelable!void {
                self.pair.send(self.io, self.first) catch return;
                try self.io.sleep(.{ .nanoseconds = 100 * 1_000_000 }, .awake);
                self.pair.send(self.io, self.rest) catch return;
            }
        };
        try group.concurrent(io, Split.run, .{Split{
            .io = io,
            .pair = pair,
            .first = input[0..cut],
            .rest = input[cut..],
        }});
    } else {
        try pair.send(io, input);
    }

    var reader = emptyReader();
    var packet_reader: PacketReader = .init(pair.readOptions(io, ms(1_000)), &reader, read_ahead);
    var writer = Io.Writer.fixed(out);
    const end = try serveRpc(.{
        .allocator = alloc,
        .packet_reader = &packet_reader,
        .writer = &writer,
        .rng = rng,
    }, .{
        .cfg = cfg,
        .clock = fixed_clock,
        .disconnect_per_request = true,
    });
    return .{ .end = end, .responses = writer.buffered() };
}

/// Assert that `responses` is exactly a BIND_ACK followed by a RESPONSE.
fn expectBindAckAndResponse(responses: []const u8) !void {
    const ack = parseHeader(responses);
    try std.testing.expectEqual(rpc.packet_type.bind_ack, ack.packet_type);
    const resp = parseHeader(responses[ack.frag_length..]);
    try std.testing.expectEqual(rpc.packet_type.response, resp.packet_type);
    try std.testing.expectEqual(
        responses.len,
        @as(usize, ack.frag_length) + @as(usize, resp.frag_length),
    );
}

// The BIND and the REQUEST leave in one write, so they arrive in one segment:
// the read-ahead must satisfy both the header and the body from that fill and
// still produce both response packets in order.
test "serveRpc reads BIND and REQUEST from one segment" {
    const alloc = std.testing.allocator;
    var td = try loadTestData(alloc);
    defer td.deinit(alloc);
    var cfg = kms.ServerConfig{ .data = &td.data };

    var prng: std.Random.DefaultPrng = .init(0x2545_f491);
    const rng = prng.random();
    const base = makeBase(&td.data);
    var request_v6: kms.RequestV6 = undefined;
    kms.createRequestV6(&request_v6, &base, rng);
    const rpc_req = try rpc.wrapKmsRequest(alloc, std.mem.asBytes(&request_v6), false, 3);
    defer alloc.free(rpc_req);
    const bind_req = try rpc.buildBindRequest(alloc, rpc.packet_type.bind_req, 2, .{ .use_ndr64 = false });
    defer alloc.free(bind_req);

    var threaded: std.Io.Threaded = .init(alloc, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var pair = try StreamPair.init(io);
    defer pair.deinit(io);

    const both = try std.mem.concat(alloc, u8, &.{ bind_req, rpc_req });
    defer alloc.free(both);

    var read_ahead: [4096]u8 = undefined;
    var out: [8192]u8 align(4) = undefined;
    const served = try serveInput(alloc, io, &pair, &cfg, rng, both, null, &read_ahead, &out);
    try std.testing.expectEqual(ServeEnd.after_request, served.end);
    try expectBindAckAndResponse(served.responses);
}

// A packet that arrives in pieces must still complete: the deadline applies per
// refill, so the 100 ms gap is well inside `--timeout`, and the read-ahead must
// not turn a short refill into a failure.
test "serveRpc reads a split packet through the read-ahead buffer" {
    const alloc = std.testing.allocator;
    var td = try loadTestData(alloc);
    defer td.deinit(alloc);
    var cfg = kms.ServerConfig{ .data = &td.data };

    var prng: std.Random.DefaultPrng = .init(0x0bad_c0de);
    const rng = prng.random();
    const base = makeBase(&td.data);
    var request_v6: kms.RequestV6 = undefined;
    kms.createRequestV6(&request_v6, &base, rng);
    const rpc_req = try rpc.wrapKmsRequest(alloc, std.mem.asBytes(&request_v6), false, 3);
    defer alloc.free(rpc_req);
    const bind_req = try rpc.buildBindRequest(alloc, rpc.packet_type.bind_req, 2, .{ .use_ndr64 = false });
    defer alloc.free(bind_req);

    var threaded: std.Io.Threaded = .init(alloc, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var pair = try StreamPair.init(io);
    defer pair.deinit(io);

    // Split inside the REQUEST: its header arrives with the BIND, its body 100 ms
    // later, so the body read needs a second refill.
    const both = try std.mem.concat(alloc, u8, &.{ bind_req, rpc_req });
    defer alloc.free(both);

    var read_ahead: [4096]u8 = undefined;
    var out: [8192]u8 align(4) = undefined;
    const served = try serveInput(
        alloc,
        io,
        &pair,
        &cfg,
        rng,
        both,
        bind_req.len,
        &read_ahead,
        &out,
    );
    try std.testing.expectEqual(ServeEnd.after_request, served.end);
    try expectBindAckAndResponse(served.responses);
}

// The read-ahead is a caller-provided buffer of any size: smaller than a header
// it still works, filling repeatedly and falling back to the direct read once
// the request is larger than the buffer.
test "serveRpc reads through a read-ahead smaller than a header" {
    const alloc = std.testing.allocator;
    var td = try loadTestData(alloc);
    defer td.deinit(alloc);
    var cfg = kms.ServerConfig{ .data = &td.data };

    var prng: std.Random.DefaultPrng = .init(0x7a1d_b00c);
    const rng = prng.random();
    const base = makeBase(&td.data);
    var request_v6: kms.RequestV6 = undefined;
    kms.createRequestV6(&request_v6, &base, rng);
    const rpc_req = try rpc.wrapKmsRequest(alloc, std.mem.asBytes(&request_v6), false, 3);
    defer alloc.free(rpc_req);
    const bind_req = try rpc.buildBindRequest(alloc, rpc.packet_type.bind_req, 2, .{ .use_ndr64 = false });
    defer alloc.free(bind_req);

    var threaded: std.Io.Threaded = .init(alloc, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var pair = try StreamPair.init(io);
    defer pair.deinit(io);

    const both = try std.mem.concat(alloc, u8, &.{ bind_req, rpc_req });
    defer alloc.free(both);

    var read_ahead: [4]u8 = undefined;
    var out: [8192]u8 align(4) = undefined;
    const served = try serveInput(alloc, io, &pair, &cfg, rng, both, null, &read_ahead, &out);
    try std.testing.expectEqual(ServeEnd.after_request, served.end);
    try expectBindAckAndResponse(served.responses);
}

// A literal is parsed before any socket work, so a mismatched `--address-family`
// fails deterministically, and a string that is neither a literal nor a valid
// host name fails as such instead of reaching the resolver.
test "connect filters a literal by address family" {
    const alloc = std.testing.allocator;
    var threaded: std.Io.Threaded = .init(alloc, .{});
    defer threaded.deinit();
    const io = threaded.io();

    try std.testing.expectError(error.AddressFamilyMismatch, connect(io, "127.0.0.1", 1688, 6));
    try std.testing.expectError(error.AddressFamilyMismatch, connect(io, "::1", 1688, 4));
    try std.testing.expectError(error.InvalidHostName, connect(io, "-invalid", 1688, 0));
}
