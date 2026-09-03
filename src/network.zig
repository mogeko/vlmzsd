//! Network layer — an idiomatic `std.Io` / `std.Io.net` replacement for
//! `reference/vlmcsd-src/network.c`.
//!
//! The C `network.c`/`rpc.c` boundary is reorganized here: `rpc.zig` holds the
//! pure wire-format code, and this module adds the byte-stream I/O on top of
//! it (the `sendrecv` equivalents) plus the socket glue (`connect`/`listen`).
//! Everything here is internal (not wire-critical), so it is written
//! idiomatically against `std.Io` rather than transliterating the C socket
//! loops.

const std = @import("std");
const Io = std.Io;
const rpc = @import("rpc.zig");
const kms = @import("kms.zig");

const Allocator = std.mem.Allocator;

// ---------------------------------------------------------------------------
// `sendrecv` equivalents
// ---------------------------------------------------------------------------

/// Read exactly `buf.len` bytes (equivalent to `_recv` in network.c).
pub fn readAll(reader: *Io.Reader, buf: []u8) !void {
    try reader.readSliceAll(buf);
}

/// Write all of `buf` (equivalent to `_send` in network.c). Flushes the
/// writer so the bytes reach the socket — the `Io.Writer` is buffered and
/// would otherwise hold them until the buffer fills.
pub fn writeAll(writer: *Io.Writer, buf: []const u8) !void {
    try writer.writeAll(buf);
    try writer.flush();
}

// ---------------------------------------------------------------------------
// Server
// ---------------------------------------------------------------------------

pub const ServeOptions = struct {
    cfg: *const kms.ServerConfig,
    rpc_assoc_group: u32 = 0,
    /// Port-number string to embed in BIND responses ("" → none).
    secondary_address: []const u8 = "",
    use_ndr64: bool = false,
    /// Bind-time feature negotiation is enabled (`UseServerRpcBTFN`).
    use_btfn: bool = false,
    /// Close the connection after each RESPONSE/FAULT (C `DisconnectImmediately`).
    disconnect_per_request: bool = false,
    /// Idle timeout in seconds (0 = disabled). Polls the connected socket for
    /// readability before each packet read (C `ServerTimeout`).
    timeout_seconds: u32 = 0,
    /// Connected socket fd, polled for readability when `timeout_seconds > 0`.
    socket_fd: std.posix.socket_t = 0,
};

/// Write one RPC packet (header + body).
fn writePacket(
    writer: *Io.Writer,
    packet_type: u8,
    call_id: u32,
    body: []const u8,
    flags: u8,
) !void {
    var header: rpc.RpcHeader = undefined;
    rpc.createRpcHeader(&header, packet_type, @intCast(rpc.header_size + body.len), call_id, flags);
    try writeAll(writer, std.mem.asBytes(&header));
    try writeAll(writer, body);
}

/// Wait until the connected socket is readable, or return `error.Timeout`
/// once the idle timeout elapses. A no-op when the timeout is disabled or the
/// reader already has buffered bytes (the buffered `Io.Reader` may have read
/// ahead past the packet being consumed).
fn waitReadable(options: ServeOptions, reader: *Io.Reader) !void {
    if (options.timeout_seconds == 0 or options.socket_fd == 0) return;
    if (reader.bufferedLen() > 0) return;
    var fds = [1]std.posix.pollfd{.{ .fd = options.socket_fd, .events = std.posix.POLL.IN, .revents = 0 }};
    const timeout_ms: i32 = @intCast(@as(i64, options.timeout_seconds) * 1000);
    const n = try std.posix.poll(&fds, timeout_ms);
    if (n == 0) return error.Timeout;
}

/// Serve the RPC loop over a connected stream (equivalent to the C `rpcServer`).
/// Returns when the peer closes the stream or sends an unsupported packet type.
pub fn serveRpc(
    allocator: Allocator,
    reader: *Io.Reader,
    writer: *Io.Writer,
    rng: std.Random,
    now_unix: i64,
    options: ServeOptions,
) !void {
    var negotiation = rpc.BindNegotiation{};

    while (true) {
        try waitReadable(options, reader);
        var header: rpc.RpcHeader = undefined;
        readAll(reader, std.mem.asBytes(&header)) catch |err| switch (err) {
            error.EndOfStream => return,
            else => return err,
        };

        const action: usize = switch (header.packet_type) {
            rpc.packet_type.bind_req => 0,
            rpc.packet_type.request => 1,
            rpc.packet_type.alter_context_req => 2,
            else => return,
        };

        const frag_len: usize = header.frag_length;
        if (frag_len < rpc.header_size) return error.InvalidPacket;
        const request_body = try allocator.alloc(u8, frag_len - rpc.header_size);
        defer allocator.free(request_body);
        try waitReadable(options, reader);
        readAll(reader, request_body) catch |err| switch (err) {
            error.EndOfStream => return,
            else => return err,
        };

        if (action == 0 or action == 2) {
            const resp_body = try rpc.buildBindResponse(allocator, request_body, options.rpc_assoc_group, .{
                .use_ndr64 = options.use_ndr64,
                .use_btfn = options.use_btfn,
                .secondary_address = options.secondary_address,
            }, &negotiation);
            defer allocator.free(resp_body);

            const resp_packet: u8 = if (action == 0) rpc.packet_type.bind_ack else rpc.packet_type.alter_context_ack;
            // BIND_ACK echoes the request's packet flags (incl. MULTIPLEX);
            // ALTER_CONTEXT_ACK always uses FIRST|LAST (matches the reference).
            const resp_flags: u8 = if (action == 0) header.packet_flags else rpc.packet_flags.first | rpc.packet_flags.last;
            try writePacket(writer, resp_packet, header.call_id, resp_body, resp_flags);
        } else {
            const dispatch = try rpc.dispatchKmsRequest(allocator, request_body, &negotiation, options.cfg, rng, now_unix);
            switch (dispatch) {
                .fault => |nca| {
                    const fault_body = rpc.buildFault(nca);
                    try writePacket(
                        writer,
                        rpc.packet_type.fault,
                        header.call_id,
                        &fault_body,
                        rpc.packet_flags.first | rpc.packet_flags.last | rpc.packet_flags.not_exec,
                    );
                    if (options.disconnect_per_request) return;
                },
                .response => |resp_body| {
                    defer allocator.free(resp_body);
                    // RESPONSE echoes the request's packet flags (incl. MULTIPLEX).
                    try writePacket(writer, rpc.packet_type.response, header.call_id, resp_body, header.packet_flags);
                    if (options.disconnect_per_request) return;
                },
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Client
// ---------------------------------------------------------------------------

pub const ClientOptions = struct {
    use_ndr64: bool = true,
    use_btfn: bool = false,
    multiplexed: bool = false,
};

/// Perform the BIND handshake and return the negotiated transfer syntaxes.
pub fn clientBind(
    allocator: Allocator,
    reader: *Io.Reader,
    writer: *Io.Writer,
    call_id: *u32,
    options: ClientOptions,
) !rpc.BindResult {
    const req = try rpc.buildBindRequest(allocator, rpc.packet_type.bind_req, call_id.*, .{
        .use_ndr64 = options.use_ndr64,
        .use_btfn = options.use_btfn,
        .multiplexed = options.multiplexed,
    });
    defer allocator.free(req);
    call_id.* += 1;

    try writeAll(writer, req);

    const resp_body = try readPacket(allocator, reader);
    defer allocator.free(resp_body);

    return rpc.parseBindResponse(resp_body);
}

pub const SendResult = struct {
    /// Raw KMS response bytes (allocator-allocated).
    data: []u8,
    /// HRESULT-style status (0 on success).
    status: i32,
};

/// Send a raw KMS request and return the raw KMS response.
pub fn clientSendRequest(
    allocator: Allocator,
    reader: *Io.Reader,
    writer: *Io.Writer,
    call_id: *u32,
    kms_request: []const u8,
    use_ndr64: bool,
) !SendResult {
    const req = try rpc.wrapKmsRequest(allocator, kms_request, use_ndr64, call_id.*);
    defer allocator.free(req);
    call_id.* += 1;

    try writeAll(writer, req);

    const resp_body = try readPacket(allocator, reader);
    defer allocator.free(resp_body);

    const parsed = rpc.parseKmsResponse(resp_body, use_ndr64);
    return .{
        .data = try allocator.dupe(u8, parsed.data),
        .status = parsed.status,
    };
}

/// Read one RPC packet (header + body) and return its body bytes.
fn readPacket(allocator: Allocator, reader: *Io.Reader) ![]u8 {
    var header: rpc.RpcHeader = undefined;
    try readAll(reader, std.mem.asBytes(&header));

    const frag_len: usize = header.frag_length;
    if (frag_len < rpc.header_size) return error.InvalidPacket;
    const body = try allocator.alloc(u8, frag_len - rpc.header_size);
    errdefer allocator.free(body);
    try readAll(reader, body);
    return body;
}

// ---------------------------------------------------------------------------
// Socket glue
// ---------------------------------------------------------------------------

/// Connect to `address:port` (IPv4/IPv6 literal). `address_family` (0 = any,
/// 4 = IPv4-only, 6 = IPv6-only) filters the literal's address family.
pub fn connect(io: Io, address: []const u8, port: u16, address_family: u8) !Io.net.Stream {
    const ip = try Io.net.IpAddress.parse(address, port);
    switch (address_family) {
        4 => switch (ip) {
            .ip4 => {},
            .ip6 => return error.AddressFamilyMismatch,
        },
        6 => switch (ip) {
            .ip6 => {},
            .ip4 => return error.AddressFamilyMismatch,
        },
        else => {},
    }
    return Io.net.IpAddress.connect(&ip, io, .{ .mode = .stream });
}

/// Listen on `address:port`.
pub fn listen(io: Io, address: []const u8, port: u16) !Io.net.Server {
    const ip = try Io.net.IpAddress.parse(address, port);
    return Io.net.IpAddress.listen(&ip, io, .{ .reuse_address = true });
}

/// True when `addr` is a private/reserved IPv4 or IPv6 address (mirrors the
/// C `isPrivateIPAddress` in network.c). Public addresses return false.
pub fn isPrivateIPAddress(addr: *const std.posix.sockaddr) bool {
    return switch (addr.family) {
        std.posix.AF.INET => blk: {
            const in: *const std.posix.sockaddr.in = @ptrCast(@alignCast(addr));
            // sockaddr_in.addr is stored in network byte order; on a
            // little-endian host this yields the numeric value via byte swap.
            const ip = @byteSwap(in.addr);
            break :blk (ip & 0xff000000) == 0x7f000000 or // 127/8 localhost
                (ip & 0xffff0000) == 0xc0a80000 or // 192.168/16
                (ip & 0xffff0000) == 0xa9fe0000 or // 169.254/16 link-local
                (ip & 0xff000000) == 0x0a000000 or // 10/8
                (ip & 0xfff00000) == 0xac100000; // 172.16/12
        },
        std.posix.AF.INET6 => blk: {
            const in6: *const std.posix.sockaddr.in6 = @ptrCast(@alignCast(addr));
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

/// True when the connected socket's peer address is private. Returns false
/// when the peer address cannot be determined (the C `serveClient` closes such
/// connections), so callers treat false as "reject".
pub fn isClientPrivate(fd: std.posix.socket_t) bool {
    var addr: std.posix.sockaddr.storage align(8) = undefined;
    var addrlen: std.posix.socklen_t = @sizeOf(std.posix.sockaddr.storage);
    std.posix.getpeername(fd, @ptrCast(&addr), &addrlen) catch return false;
    return isPrivateIPAddress(@ptrCast(&addr));
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
            var ip4: Io.net.Ip4Address = .{ .bytes = undefined, .port = 0 };
            @memcpy(&ip4.bytes, std.mem.asBytes(&in.addr));
            return .{ .ip4 = ip4 };
        },
        std.posix.AF.INET6 => {
            const in6: *const std.posix.sockaddr.in6 = @ptrCast(@alignCast(addr));
            return .{ .ip6 = .{ .bytes = in6.addr, .port = 0 } };
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

    var list = std.ArrayList(Io.net.IpAddress).empty;
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

const kmsdata = @import("kmsdata.zig");

const TestData = struct {
    raw: []u8,
    data: kmsdata.KmsData,

    fn deinit(self: *TestData, allocator: Allocator) void {
        self.data.deinit(allocator);
        allocator.free(self.raw);
    }
};

fn loadTestData(allocator: Allocator) !TestData {
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const raw = try std.Io.Dir.readFileAlloc(std.Io.Dir.cwd(), io, "reference/vlmcsd.kmd", allocator, .unlimited);
    errdefer allocator.free(raw);
    const data = try kmsdata.parse(allocator, raw);
    return .{ .raw = raw, .data = data };
}

fn makeBase(data: *const kmsdata.KmsData) kms.Request {
    var base: kms.Request = std.mem.zeroes(kms.Request);
    base.version = 6 << 16;
    base.license_status = 1;
    base.kms_id = data.kms()[0].guid;
    base.app_id = data.apps()[0].guid;
    base.act_id = data.kms()[0].guid;
    base.cmid = [16]u8{ 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 };
    base.n_policy = 25;
    base.client_time = kms.u64ToFileTime(kms.unixTimeToFileTime(1_700_000_000));
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
}

test "serveRpc end-to-end (bind + v6 request)" {
    const alloc = std.testing.allocator;
    var td = try loadTestData(alloc);
    defer td.deinit(alloc);

    var cfg = kms.ServerConfig{ .data = &td.data };
    const base = makeBase(&td.data);

    var prng = std.Random.DefaultPrng.init(0x1234_5678);
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
    var output_buf: [4096]u8 align(4) = undefined;
    var writer = Io.Writer.fixed(&output_buf);

    try serveRpc(alloc, &reader, &writer, rng, 1_700_000_000, .{ .cfg = &cfg });

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
    var call_id: u32 = 2;

    const result = try clientBind(alloc, &reader, &writer, &call_id, .{ .use_ndr64 = false });
    try std.testing.expect(result.has_ndr32);
    try std.testing.expect(!result.has_ndr64);

    const sent = writer.buffered();
    try std.testing.expect(sent.len >= rpc.header_size);
    const sent_header = parseHeader(sent);
    try std.testing.expectEqual(rpc.packet_type.bind_req, sent_header.packet_type);
}
