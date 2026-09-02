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

/// Write all of `buf` (equivalent to `_send` in network.c).
pub fn writeAll(writer: *Io.Writer, buf: []const u8) !void {
    try writer.writeAll(buf);
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
        var header_bytes: [rpc.header_size]u8 = undefined;
        readAll(reader, &header_bytes) catch |err| switch (err) {
            error.EndOfStream => return,
            else => return err,
        };
        const header: *const rpc.RpcHeader = @ptrCast(@alignCast(&header_bytes));

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
        readAll(reader, request_body) catch |err| switch (err) {
            error.EndOfStream => return,
            else => return err,
        };

        if (action == 0 or action == 2) {
            const resp_body = try rpc.buildBindResponse(allocator, request_body, options.rpc_assoc_group, .{
                .use_ndr64 = options.use_ndr64,
                .secondary_address = options.secondary_address,
            }, &negotiation);
            defer allocator.free(resp_body);

            const resp_packet: u8 = if (action == 0) rpc.packet_type.bind_ack else rpc.packet_type.alter_context_ack;
            try writePacket(writer, resp_packet, header.call_id, resp_body, rpc.packet_flags.first | rpc.packet_flags.last);
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
                },
                .response => |resp_body| {
                    defer allocator.free(resp_body);
                    try writePacket(writer, rpc.packet_type.response, header.call_id, resp_body, rpc.packet_flags.first | rpc.packet_flags.last);
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
    var header_bytes: [rpc.header_size]u8 = undefined;
    try readAll(reader, &header_bytes);
    const header: *const rpc.RpcHeader = @ptrCast(@alignCast(&header_bytes));

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

/// Connect to `address:port` (IPv4/IPv6 literal).
pub fn connect(io: Io, address: []const u8, port: u16) !Io.net.Stream {
    const ip = try Io.net.IpAddress.parse(address, port);
    return Io.net.IpAddress.connect(&ip, io, .{ .mode = .stream });
}

/// Listen on `address:port`.
pub fn listen(io: Io, address: []const u8, port: u16) !Io.net.Server {
    const ip = try Io.net.IpAddress.parse(address, port);
    return Io.net.IpAddress.listen(&ip, io, .{ .reuse_address = true });
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
