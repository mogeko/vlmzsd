//! DCE/RPC transport layer — wire/binary-compatible implementation of the
//! vlmcsd DCE/RPC wire format (the non-`USE_MSRPC` path; see `docs/migration.md`).
//!
//! This module implements the byte-level framing: RPC headers, BIND/ALTER-CONTEXT
//! negotiation, and NDR32/NDR64 request/response wrapping. It does not open
//! sockets itself; the socket layer (Phase 5) feeds bytes in and out through
//! these pure functions.
//!
//! Wire layout follows the C packed structs byte-for-byte (verified below);
//! variable-length parts (context items, NDR payloads) are read/written with
//! `std.mem.readInt`/`writeInt`, never by casting to padded structs.

const std = @import("std");
const kms = @import("kms.zig");
const kmsdata = @import("kmsdata.zig");

const Allocator = std.mem.Allocator;
const Guid = kms.Guid;

// ---------------------------------------------------------------------------
// GUIDs (stored as opaque 16 bytes, exactly as the C `BYTE[16]` tables)
// ---------------------------------------------------------------------------

pub const interface_uuid: Guid = .{
    0x75, 0x21, 0xc8, 0x51, 0x4e, 0x84, 0x50, 0x47,
    0xB0, 0xD8, 0xEC, 0x25, 0x55, 0x55, 0xBC, 0x06,
};
pub const transfer_syntax_ndr32: Guid = .{
    0x04, 0x5D, 0x88, 0x8A, 0xEB, 0x1C, 0xC9, 0x11,
    0x9F, 0xE8, 0x08, 0x00, 0x2B, 0x10, 0x48, 0x60,
};
pub const transfer_syntax_ndr64: Guid = .{
    0x33, 0x05, 0x71, 0x71, 0xba, 0xbe, 0x37, 0x49,
    0x83, 0x19, 0xb5, 0xdb, 0xef, 0x9c, 0xcc, 0x36,
};
pub const bind_time_feature_negotiation: Guid = .{
    0x2c, 0x1c, 0xb7, 0x6c, 0x12, 0x98, 0x40, 0x45,
    0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

pub const packet_type = struct {
    pub const request: u8 = 0;
    pub const response: u8 = 2;
    pub const fault: u8 = 3;
    pub const bind_req: u8 = 11;
    pub const bind_ack: u8 = 12;
    pub const alter_context_req: u8 = 14;
    pub const alter_context_ack: u8 = 15;
};

pub const packet_flags = struct {
    pub const first: u8 = 1;
    pub const last: u8 = 2;
    pub const cancel_pending: u8 = 4;
    pub const reserved: u8 = 8;
    pub const multiplex: u8 = 16;
    pub const not_exec: u8 = 32;
    pub const maybe: u8 = 64;
    pub const object: u8 = 128;
};

/// AckResult values for BIND/ALTER-CONTEXT results.
pub const bind_accept: u16 = 0;
pub const bind_nack: u16 = 2;
pub const bind_ack: u16 = 3;

/// AckReason values.
pub const abstract_syntax_unsupported: u16 = 1;
pub const syntax_unsupported: u16 = 2;

/// NCA faults.
pub const nca_unk_if: u32 = 0x1c010003;
pub const nca_proto_error: u32 = 0x1c01000b;

/// `RPC_INVALID_CTX`.
pub const invalid_ctx: u16 = std.math.maxInt(u16);

/// The wire value of the DataRepresentation field (`BE32(0x10000000)` stored
/// little-endian is the 4 bytes `10 00 00 00`).
pub const data_representation_le: u32 = 0x10;

/// Fixed sizes (bytes).
pub const header_size = 16;
pub const ctx_item_size = 44;
pub const ctx_result_size = 24;
pub const bind_request_fixed_size = 12; // up to the first CtxItem
pub const bind_response_fixed_size = 20; // up to the first CtxResult
pub const request32_fixed_size = 16; // up to Ndr.Data
pub const request64_fixed_size = 24; // up to Ndr64.Data
pub const response32_data_offset = 20;
pub const response64_data_offset = 32;

const kms_request_v4_size = @sizeOf(kms.RequestV4);
const kms_request_v6_size = @sizeOf(kms.RequestV6);

// ---------------------------------------------------------------------------
// RPC header
// ---------------------------------------------------------------------------

pub const RpcHeader = extern struct {
    version_major: u8,
    version_minor: u8,
    packet_type: u8,
    packet_flags: u8,
    data_representation: u32,
    frag_length: u16,
    auth_length: u16,
    call_id: u32,
};

comptime {
    // DCE/RPC wire contract — docs/migration.md §3.3.
    std.debug.assert(@sizeOf(RpcHeader) == 16);

    // Fixed sizes (bytes).
    std.debug.assert(header_size == 16);
    std.debug.assert(ctx_item_size == 44);
    std.debug.assert(ctx_result_size == 24);
    std.debug.assert(bind_request_fixed_size == 12);
    std.debug.assert(bind_response_fixed_size == 20);
    std.debug.assert(request32_fixed_size == 16);
    std.debug.assert(request64_fixed_size == 24);
    std.debug.assert(response32_data_offset == 20);
    std.debug.assert(response64_data_offset == 32);

    // NCA faults and the invalid context id.
    std.debug.assert(nca_unk_if == 0x1c010003);
    std.debug.assert(nca_proto_error == 0x1c01000b);
    std.debug.assert(invalid_ctx == 0xFFFF);

    // DataRepresentation = BE32(0x10000000) stored little-endian → bytes `10 00 00 00`.
    std.debug.assert(data_representation_le == 0x10);

    // Transfer-syntax GUIDs, byte-for-byte as the C `BYTE[16]` tables.
    std.debug.assert(std.mem.eql(u8, &interface_uuid, &[_]u8{ 0x75, 0x21, 0xc8, 0x51, 0x4e, 0x84, 0x50, 0x47, 0xb0, 0xd8, 0xec, 0x25, 0x55, 0x55, 0xbc, 0x06 }));
    std.debug.assert(std.mem.eql(u8, &transfer_syntax_ndr32, &[_]u8{ 0x04, 0x5d, 0x88, 0x8a, 0xeb, 0x1c, 0xc9, 0x11, 0x9f, 0xe8, 0x08, 0x00, 0x2b, 0x10, 0x48, 0x60 }));
    std.debug.assert(std.mem.eql(u8, &transfer_syntax_ndr64, &[_]u8{ 0x33, 0x05, 0x71, 0x71, 0xba, 0xbe, 0x37, 0x49, 0x83, 0x19, 0xb5, 0xdb, 0xef, 0x9c, 0xcc, 0x36 }));
    std.debug.assert(std.mem.eql(u8, &bind_time_feature_negotiation, &[_]u8{ 0x2c, 0x1c, 0xb7, 0x6c, 0x12, 0x98, 0x40, 0x45, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }));
}

/// Initialize an RPC header the way the reference does for KMS (one-fragment
/// packets). `flags` defaults to FIRST|LAST.
pub fn createRpcHeader(
    header: *RpcHeader,
    packet_type_value: u8,
    size: u16,
    call_id: u32,
    flags: u8,
) void {
    header.version_major = 5;
    header.version_minor = 0;
    header.packet_type = packet_type_value;
    header.packet_flags = flags;
    header.data_representation = data_representation_le;
    header.frag_length = size;
    header.auth_length = 0;
    header.call_id = call_id;
}

fn readLe(comptime T: type, bytes: []const u8, offset: usize) T {
    const n = @divExact(@typeInfo(T).int.bits, 8);
    return std.mem.readInt(T, bytes[offset..][0..n].ptr[0..n], .little);
}

fn writeLe(comptime T: type, bytes: []u8, offset: usize, value: T) void {
    const n = @divExact(@typeInfo(T).int.bits, 8);
    std.mem.writeInt(T, bytes[offset..][0..n], value, .little);
}

// ---------------------------------------------------------------------------
// Server side: BIND response
// ---------------------------------------------------------------------------

pub const BindResponseOptions = struct {
    /// NDR64 is enabled on this server (maps to `UseServerRpcNDR64`).
    use_ndr64: bool = false,
    /// Bind-time feature negotiation is enabled (`UseServerRpcBTFN`).
    use_btfn: bool = false,
    /// Port-number string to embed in the secondary address ("" → none).
    secondary_address: []const u8 = "",
};

pub const BindNegotiation = struct {
    ndr_ctx: u16 = invalid_ctx,
    ndr64_ctx: u16 = invalid_ctx,
};

/// Build a BIND/ALTER-CONTEXT response body (no RPC header).
/// `request_body` is the request body (no header). Returns the response body
/// and records the negotiated context ids in `negotiation`.
pub fn buildBindResponse(
    allocator: Allocator,
    request_body: []const u8,
    rpc_assoc_group: u32,
    options: BindResponseOptions,
    negotiation: *BindNegotiation,
) ![]u8 {
    if (request_body.len < bind_request_fixed_size) return error.InvalidBindRequest;

    const num_ctx_items = readLe(u32, request_body, 8);
    const items_end = bind_request_fixed_size + @as(usize, num_ctx_items) * ctx_item_size;
    if (items_end > request_body.len) return error.InvalidBindRequest;

    // First pass: locate NDR32/NDR64 contexts.
    var ndr64_possible = false;
    for (0..num_ctx_items) |i| {
        const base = bind_request_fixed_size + i * ctx_item_size;
        const context_id = readLe(u16, request_body, base);
        const transfer_syntax = request_body[base + 24 .. base + 40];
        if (std.mem.eql(u8, transfer_syntax, &transfer_syntax_ndr32)) {
            negotiation.ndr_ctx = context_id;
        }
        if (options.use_ndr64 and std.mem.eql(u8, transfer_syntax, &transfer_syntax_ndr64)) {
            ndr64_possible = true;
            negotiation.ndr64_ctx = context_id;
        }
    }

    // Secondary address layout: length (incl. NUL) + string, padded to 4.
    const port_len: usize = options.secondary_address.len;
    const port_size: usize = if (port_len == 0) 0 else port_len + 1;
    const results_offset: usize = (10 + port_size + 3) & ~@as(usize, 3);

    const total = results_offset + 4 + @as(usize, num_ctx_items) * ctx_result_size;
    const buf = try allocator.alloc(u8, total);
    @memset(buf, 0);

    // MaxXmitFrag / MaxRecvFrag are echoed back.
    @memcpy(buf[0..4], request_body[0..4]);
    writeLe(u32, buf, 4, rpc_assoc_group);
    writeLe(u16, buf, 8, @intCast(port_size));
    if (port_len > 0) @memcpy(buf[10..][0..port_len], options.secondary_address);
    writeLe(u32, buf, results_offset, num_ctx_items);

    for (0..num_ctx_items) |i| {
        const item_base = bind_request_fixed_size + i * ctx_item_size;
        const context_id = readLe(u16, request_body, item_base);
        const item_interface_uuid = request_body[item_base + 4 .. item_base + 20];
        const transfer_syntax = request_body[item_base + 24 .. item_base + 40];

        const res_base = results_offset + 4 + i * ctx_result_size;
        const is_interface = std.mem.eql(u8, item_interface_uuid, &interface_uuid);

        var ack_result: u16 = bind_nack;
        var ack_reason: u16 = if (is_interface) syntax_unsupported else abstract_syntax_unsupported;
        var result_syntax: Guid = [_]u8{0} ** 16;
        var syntax_version: u32 = 0;

        if (is_interface and !ndr64_possible and std.mem.eql(u8, transfer_syntax, &transfer_syntax_ndr32)) {
            ack_result = bind_accept;
            ack_reason = bind_accept;
            result_syntax = transfer_syntax_ndr32;
            syntax_version = 2;
        } else if (std.mem.eql(u8, transfer_syntax, &transfer_syntax_ndr64)) {
            if (!options.use_ndr64) ack_reason = syntax_unsupported;
            if (is_interface and ndr64_possible) {
                ack_result = bind_accept;
                ack_reason = bind_accept;
                result_syntax = transfer_syntax_ndr64;
                syntax_version = 1;
            }
        } else if (std.mem.eql(u8, transfer_syntax[0..8], bind_time_feature_negotiation[0..8])) {
            ack_reason = syntax_unsupported;
            if (options.use_btfn) {
                ack_result = bind_ack;
                // Feature mask is encoded in the GUID's words.
                ack_reason = readLe(u16, transfer_syntax, 8) & 0x3;
                syntax_version = 0;
            }
        }

        _ = context_id;
        writeLe(u16, buf, res_base, ack_result);
        writeLe(u16, buf, res_base + 2, ack_reason);
        @memcpy(buf[res_base + 4 .. res_base + 20], &result_syntax);
        writeLe(u32, buf, res_base + 20, syntax_version);
    }

    return buf;
}

// ---------------------------------------------------------------------------
// Server side: request dispatch
// ---------------------------------------------------------------------------

/// Result of dispatching an RPC request. The metadata fields let the caller
/// (the socket layer) emit logs without reaching into protocol internals.
pub const DispatchResult = struct {
    kind: union(enum) {
        /// NCA fault (unknown context or unsupported KMS version).
        fault: u32,
        /// Normal RPC response body (allocator-allocated).
        response: []u8,
    },
    /// KMS major version parsed from the request (0 = invalid/unknown).
    major_version: u16 = 0,
    /// Positive = response byte length; negative = HRESULT rejection.
    response_size: i32 = 0,
};

/// Build the 16-byte FAULT response body for an NCA error. The caller pairs it
/// with a FAULT header whose `FragLength` is `header_size + 16 = 32`.
pub fn buildFault(nca_error: u32) [16]u8 {
    var buf = [_]u8{0} ** 16;
    writeLe(u32, &buf, 0, 32); // AllocHint
    writeLe(u32, &buf, 8, nca_error); // Error.Code
    return buf;
}

/// Dispatch an RPC request body to the KMS layer and build the RPC response
/// body (no header). `request_body` is not modified.
pub fn dispatchKmsRequest(
    allocator: Allocator,
    request_body: []const u8,
    negotiation: *const BindNegotiation,
    cfg: *const kms.ServerConfig,
    rng: std.Random,
    now_unix: i64,
) !DispatchResult {
    if (request_body.len < request32_fixed_size) return error.InvalidRequest;

    const context_id = readLe(u16, request_body, 4);
    const is_ndr64 = context_id == negotiation.ndr64_ctx;
    const is_ndr32 = context_id == negotiation.ndr_ctx;
    if (!is_ndr32 and !is_ndr64) return .{ .kind = .{ .fault = nca_unk_if } };

    const data_offset: usize = if (is_ndr64) request64_fixed_size else request32_fixed_size;

    // Rejection HRESULT (E_INVALIDARG). Mirrors the C `rpcRequest`: any
    // invalid request (too short, unsupported version, non-zero minor) is
    // answered with a normal RESPONSE carrying a zero-length payload and this
    // status — not a FAULT and not a disconnect.
    const e_invalid_arg: i32 = @bitCast(@as(u32, 0x8007000D));

    var kms_response_buf: [kms.max_response_size]u8 align(4) = undefined;
    var response_size: i32 = e_invalid_arg;
    var major_ver: u16 = 0;

    // Mirror `checkRpcRequestSize` (rpc.c): only KMS v4.0/v5.0/v6.0 are
    // supported. `major_index` wraps for major < 4 exactly like the C
    // `uint16_t` arithmetic, so the `<= 2` test rejects those too.
    if (request_body.len >= data_offset + 4) {
        const version = readLe(u32, request_body, data_offset);
        const major_index: u32 = (version >> 16) - 4;
        const minor: u32 = version & 0xffff;
        if (major_index <= 2 and minor == 0) {
            major_ver = @intCast(version >> 16);
            const kms_request_size: usize = if (major_ver == 4) kms_request_v4_size else kms_request_v6_size;
            if (request_body.len >= data_offset + kms_request_size) {
                if (major_ver == 4) {
                    var request_v4: kms.RequestV4 = undefined;
                    @memcpy(std.mem.asBytes(&request_v4)[0..kms_request_size], request_body[data_offset..][0..kms_request_size]);
                    response_size = kms.createResponseV4(&request_v4, &kms_response_buf, cfg, rng, now_unix);
                } else {
                    var request_v6: kms.RequestV6 = undefined;
                    @memcpy(std.mem.asBytes(&request_v6)[0..kms_request_size], request_body[data_offset..][0..kms_request_size]);
                    response_size = kms.createResponseV6(&request_v6, &kms_response_buf, cfg, rng, now_unix);
                }
            }
        }
    }

    // Assemble the response body (NDR32 or NDR64).
    const ndr_size: usize = if (is_ndr64) 24 else 12;
    const data_is_size: usize = if (is_ndr64) 8 else 4;

    var len: usize = if (response_size < 0)
        ndr_size - data_is_size
    else
        @as(usize, @intCast(response_size)) + ndr_size;

    // Return code location (relative to the NDR union start @8).
    const return_code_off = 8 + len;
    len += 4;
    const pad: usize = (4 - (len & 3)) & 3;
    len += pad;

    const total = len + 8;
    const body = try allocator.alloc(u8, total);
    @memset(body, 0);

    const return_code: u32 = if (response_size < 0) @bitCast(response_size) else 0;

    if (is_ndr64) {
        const data_len: u64 = if (response_size < 0) 0 else @intCast(response_size);
        writeLe(u64, body, 8, data_len); // DataLength
        writeLe(u64, body, 16, if (response_size < 0) 0 else 0x00020000); // DataSizeMax
        if (response_size >= 0) {
            writeLe(u64, body, 24, data_len); // DataSizeIs
            @memcpy(body[response64_data_offset..][0..@intCast(response_size)], kms_response_buf[0..@intCast(response_size)]);
        }
    } else {
        const data_len: u32 = if (response_size < 0) 0 else @intCast(response_size);
        writeLe(u32, body, 8, data_len); // DataLength
        writeLe(u32, body, 12, if (response_size < 0) 0 else 0x00020000); // DataSizeMax
        if (response_size >= 0) {
            writeLe(u32, body, 16, data_len); // DataSizeIs
            @memcpy(body[response32_data_offset..][0..@intCast(response_size)], kms_response_buf[0..@intCast(response_size)]);
        }
    }

    writeLe(u32, body, return_code_off, return_code);

    writeLe(u32, body, 0, @intCast(len)); // AllocHint
    writeLe(u16, body, 4, context_id);
    // CancelCount + Pad1 are already zero.

    return .{
        .kind = .{ .response = body },
        .major_version = major_ver,
        .response_size = response_size,
    };
}

// ---------------------------------------------------------------------------
// Client side
// ---------------------------------------------------------------------------

pub const BindRequestOptions = struct {
    use_ndr64: bool = true,
    use_btfn: bool = false,
    multiplexed: bool = false,
};

/// Build a BIND request (header + body). `packet_type_value` selects BIND or
/// ALTER-CONTEXT.
pub fn buildBindRequest(
    allocator: Allocator,
    packet_type_value: u8,
    call_id: u32,
    options: BindRequestOptions,
) ![]u8 {
    const is_bind = packet_type_value == packet_type.bind_req;
    var ctx_items: usize = 1;
    if (is_bind and options.use_ndr64) ctx_items += 1;
    if (is_bind and options.use_btfn) ctx_items += 1;
    // `bind_request_fixed_size` is up to (not including) the first CtxItem.
    const body_size = bind_request_fixed_size + ctx_items * ctx_item_size;
    const total = header_size + body_size;

    const buf = try allocator.alloc(u8, total);
    @memset(buf, 0);

    var header: RpcHeader = undefined;
    var flags: u8 = packet_flags.first | packet_flags.last;
    if (options.multiplexed) flags |= packet_flags.multiplex;
    createRpcHeader(&header, packet_type_value, @intCast(total), call_id, flags);
    @memcpy(buf[0..header_size], std.mem.asBytes(&header));

    const body = buf[header_size..];
    writeLe(u16, body, 0, 5840); // MaxXmitFrag
    writeLe(u16, body, 2, 5840); // MaxRecvFrag
    writeLe(u32, body, 4, 0); // AssocGroup
    writeLe(u32, body, 8, @intCast(ctx_items)); // NumCtxItems

    var ctx_index: usize = 0;
    while (ctx_index < ctx_items) : (ctx_index += 1) {
        const base = bind_request_fixed_size + ctx_index * ctx_item_size;
        writeLe(u16, body, base, @intCast(ctx_index)); // ContextId
        writeLe(u16, body, base + 2, 1); // NumTransItems
        @memcpy(body[base + 4 .. base + 20], &interface_uuid);
        writeLe(u16, body, base + 20, 1); // InterfaceVerMajor
        writeLe(u16, body, base + 22, 0); // InterfaceVerMinor
        writeLe(u32, body, base + 40, if (ctx_index == 0) 2 else 1); // SyntaxVersion
        // TransferSyntax filled per-index below.
    }

    // Context 0: NDR32.
    @memcpy(body[bind_request_fixed_size + 24 .. bind_request_fixed_size + 40], &transfer_syntax_ndr32);

    var next: usize = 1;
    if (is_bind and options.use_ndr64) {
        @memcpy(body[bind_request_fixed_size + next * ctx_item_size + 24 ..][0..16], &transfer_syntax_ndr64);
        next += 1;
    }
    if (is_bind and options.use_btfn) {
        @memcpy(body[bind_request_fixed_size + next * ctx_item_size + 24 ..][0..16], &bind_time_feature_negotiation);
    }

    return buf;
}

/// Client-side negotiation flags derived from a parsed BIND response.
pub const BindResult = struct {
    has_ndr32: bool = false,
    has_ndr64: bool = false,
    has_btfn: bool = false,
};

/// Parse a BIND/ALTER-CONTEXT response body (no header) and record which
/// transfer syntaxes were accepted.
pub fn parseBindResponse(response_body: []const u8) BindResult {
    var result = BindResult{};
    if (response_body.len < bind_response_fixed_size) return result;

    const secondary_len = readLe(u16, response_body, 8);
    const results_offset: usize = (10 + @as(usize, secondary_len) + 3) & ~@as(usize, 3);
    if (results_offset + 4 > response_body.len) return result;

    const num_results = readLe(u32, response_body, results_offset);

    for (0..num_results) |i| {
        const res_base = results_offset + 4 + i * ctx_result_size;
        if (res_base + ctx_result_size > response_body.len) break;
        const ack = readLe(u16, response_body, res_base);
        const transfer_syntax = response_body[res_base + 4 .. res_base + 20];
        if (ack == bind_accept) {
            if (std.mem.eql(u8, transfer_syntax, &transfer_syntax_ndr32)) {
                result.has_ndr32 = true;
            } else if (std.mem.eql(u8, transfer_syntax, &transfer_syntax_ndr64)) {
                result.has_ndr64 = true;
            }
        } else if (ack == bind_ack) {
            result.has_btfn = true;
        }
    }
    return result;
}

/// Wrap a raw KMS request (from `kms.createRequestV4/V6`) into a full RPC
/// request (header + body) for sending.
pub fn wrapKmsRequest(
    allocator: Allocator,
    kms_request: []const u8,
    use_ndr64: bool,
    call_id: u32,
) ![]u8 {
    const ndr_size: usize = if (use_ndr64) request64_fixed_size else request32_fixed_size;
    const ndr_tail: usize = if (use_ndr64) 16 else 8; // DataLength + DataSizeIs
    const total = header_size + ndr_size + kms_request.len;

    const buf = try allocator.alloc(u8, total);
    @memset(buf, 0);

    var header: RpcHeader = undefined;
    createRpcHeader(&header, packet_type.request, @intCast(total), call_id, packet_flags.first | packet_flags.last);
    @memcpy(buf[0..header_size], std.mem.asBytes(&header));

    const body = buf[header_size..];
    writeLe(u32, body, 0, @intCast(kms_request.len + ndr_tail)); // AllocHint
    writeLe(u16, body, 4, if (use_ndr64) 1 else 0); // ContextId
    writeLe(u16, body, 6, 0); // Opnum

    if (use_ndr64) {
        writeLe(u64, body, 8, kms_request.len);
        writeLe(u64, body, 16, kms_request.len);
        @memcpy(body[request64_fixed_size..][0..kms_request.len], kms_request);
    } else {
        writeLe(u32, body, 8, @intCast(kms_request.len));
        writeLe(u32, body, 12, @intCast(kms_request.len));
        @memcpy(body[request32_fixed_size..][0..kms_request.len], kms_request);
    }

    return buf;
}

pub const KmsResponseParse = struct {
    /// KMS response payload bytes (slice into `response_body`).
    data: []const u8,
    /// HRESULT-style status code (0 on success).
    status: i32,
};

/// Parse an RPC response body (no header) into the KMS payload and status.
pub fn parseKmsResponse(response_body: []const u8, use_ndr64: bool) KmsResponseParse {
    const data_offset: usize = if (use_ndr64) response64_data_offset else response32_data_offset;

    if (use_ndr64) {
        // 24 bytes covers DataLength + DataSizeMax; a rejected request body is
        // only 28 bytes (no DataSizeIs, status in its slot), so don't require 32.
        if (response_body.len < 24) return .{ .data = "", .status = nca_proto_error };
        const data_length = readLe(u64, response_body, 8);
        const data_size_max = readLe(u64, response_body, 16);
        const response_size: usize = @intCast(data_length);
        if (data_size_max == 0) {
            if (response_body.len < 28) return .{ .data = "", .status = nca_proto_error };
            return .{ .data = "", .status = readLe(i32, response_body, 24) };
        }
        if (response_body.len < data_offset + response_size + 4) return .{ .data = "", .status = nca_proto_error };
        return .{
            .data = response_body[data_offset..][0..response_size],
            .status = readLe(i32, response_body, data_offset + response_size),
        };
    }

    if (response_body.len < response32_data_offset) return .{ .data = "", .status = nca_proto_error };
    const data_length = readLe(u32, response_body, 8);
    const data_size_max = readLe(u32, response_body, 12);
    const response_size: usize = data_length;
    if (data_size_max == 0) {
        return .{ .data = "", .status = readLe(i32, response_body, 16) };
    }
    if (response_body.len < data_offset + response_size + 4) return .{ .data = "", .status = nca_proto_error };
    return .{
        .data = response_body[data_offset..][0..response_size],
        .status = readLe(i32, response_body, data_offset + response_size),
    };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "FAULT body bytes" {
    // AllocHint=32@0, Error.Code=nca@8, rest zero — docs/migration.md §3.3.
    const body = buildFault(nca_unk_if);
    try std.testing.expectEqual(@as(u32, 32), readLe(u32, &body, 0));
    try std.testing.expectEqual(@as(u32, 0), readLe(u32, &body, 4));
    try std.testing.expectEqual(nca_unk_if, readLe(u32, &body, 8));
    try std.testing.expectEqual(@as(u32, 0), readLe(u32, &body, 12));
}

test "bind NDR64 negotiation" {
    const alloc = std.testing.allocator;

    const req = try buildBindRequest(alloc, packet_type.bind_req, 2, .{ .use_ndr64 = true });
    defer alloc.free(req);

    var negotiation = BindNegotiation{};
    const resp = try buildBindResponse(
        alloc,
        req[header_size..],
        0x1234_5678,
        .{ .use_ndr64 = true, .secondary_address = "1688" },
        &negotiation,
    );
    defer alloc.free(resp);

    try std.testing.expectEqual(@as(u16, 0), negotiation.ndr_ctx);
    try std.testing.expectEqual(@as(u16, 1), negotiation.ndr64_ctx);

    const result = parseBindResponse(resp);
    // The reference NACKs NDR32 whenever NDR64 is available.
    try std.testing.expect(!result.has_ndr32);
    try std.testing.expect(result.has_ndr64);
}

test "bind NDR32-only negotiation" {
    const alloc = std.testing.allocator;

    const req = try buildBindRequest(alloc, packet_type.bind_req, 2, .{ .use_ndr64 = false });
    defer alloc.free(req);

    var negotiation = BindNegotiation{};
    const resp = try buildBindResponse(
        alloc,
        req[header_size..],
        0x1234_5678,
        .{ .secondary_address = "1688" },
        &negotiation,
    );
    defer alloc.free(resp);

    const result = parseBindResponse(resp);
    try std.testing.expect(result.has_ndr32);
    try std.testing.expect(!result.has_ndr64);
}

test "kms request wrap (NDR32)" {
    const alloc = std.testing.allocator;

    var payload = [_]u8{0xAB} ** 32;
    const wrapped = try wrapKmsRequest(alloc, &payload, false, 2);
    defer alloc.free(wrapped);

    var header: RpcHeader = undefined;
    @memcpy(std.mem.asBytes(&header), wrapped[0..header_size]);
    try std.testing.expectEqual(packet_type.request, header.packet_type);
    try std.testing.expectEqual(data_representation_le, header.data_representation);
    try std.testing.expectEqual(@as(u32, 2), header.call_id);

    const body = wrapped[header_size..];
    try std.testing.expectEqual(@as(u16, 0), readLe(u16, body, 4));
    try std.testing.expectEqual(@as(u32, 32), readLe(u32, body, 8));
    try std.testing.expectEqualSlices(u8, &payload, body[request32_fixed_size..][0..32]);
}

test "kms request wrap (NDR64)" {
    const alloc = std.testing.allocator;

    var payload = [_]u8{0xCD} ** 40;
    const wrapped = try wrapKmsRequest(alloc, &payload, true, 3);
    defer alloc.free(wrapped);

    const body = wrapped[header_size..];
    try std.testing.expectEqual(@as(u16, 1), readLe(u16, body, 4));
    try std.testing.expectEqual(@as(u64, 40), readLe(u64, body, 8));
    try std.testing.expectEqualSlices(u8, &payload, body[request64_fixed_size..][0..40]);
}

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

test "dispatch v6 request end-to-end" {
    const alloc = std.testing.allocator;
    var td = try loadTestData(alloc);
    defer td.deinit(alloc);

    var cfg = kms.ServerConfig{ .data = &td.data };
    const base = makeBase(&td.data);

    var prng = std.Random.DefaultPrng.init(0x1234_5678);
    const rng = prng.random();

    // Client builds the (encrypted) KMS request.
    var request_v6: kms.RequestV6 = undefined;
    kms.createRequestV6(&request_v6, &base, rng);

    // Server-side negotiation (normally established by the BIND handshake).
    var negotiation = BindNegotiation{ .ndr_ctx = 0, .ndr64_ctx = 1 };

    // Wrap → dispatch → parse the response.
    const rpc_request = try wrapKmsRequest(alloc, std.mem.asBytes(&request_v6), false, 2);
    defer alloc.free(rpc_request);

    const dispatch = try dispatchKmsRequest(alloc, rpc_request[header_size..], &negotiation, &cfg, rng, 1_700_000_000);
    const resp_body = switch (dispatch.kind) {
        .fault => return error.TestUnexpectedResult,
        .response => |body| body,
    };
    defer alloc.free(resp_body);

    const parsed = parseKmsResponse(resp_body, false);
    try std.testing.expectEqual(@as(i32, 0), parsed.status);
    try std.testing.expect(parsed.data.len > 0);

    // Client verifies the KMS response against the original request.
    var request_client = request_v6;
    var resp: kms.ResponseV6 = undefined;
    const result = kms.decryptResponseV6(&resp, parsed.data.len, @constCast(parsed.data), &request_client, null);
    try std.testing.expect(result.ok());
}

test "dispatch unsupported KMS version returns HRESULT" {
    const alloc = std.testing.allocator;
    var td = try loadTestData(alloc);
    defer td.deinit(alloc);

    var cfg = kms.ServerConfig{ .data = &td.data };
    var base = makeBase(&td.data);
    base.version = 7 << 16; // unsupported major version

    var prng = std.Random.DefaultPrng.init(0x1234_5678);
    const rng = prng.random();

    var request_v6: kms.RequestV6 = undefined;
    kms.createRequestV6(&request_v6, &base, rng);

    var negotiation = BindNegotiation{ .ndr_ctx = 0, .ndr64_ctx = 1 };
    const e_invalid_arg: i32 = @bitCast(@as(u32, 0x8007000D));

    // NDR64 error path must not overrun the body (regression: DataSizeIs was
    // written past the buffer when the payload was rejected).
    {
        const rpc_request = try wrapKmsRequest(alloc, std.mem.asBytes(&request_v6), true, 2);
        defer alloc.free(rpc_request);
        const dispatch = try dispatchKmsRequest(alloc, rpc_request[header_size..], &negotiation, &cfg, rng, 1_700_000_000);
        const resp_body = switch (dispatch.kind) {
            .fault => return error.TestUnexpectedResult,
            .response => |body| body,
        };
        defer alloc.free(resp_body);
        const parsed = parseKmsResponse(resp_body, true);
        try std.testing.expectEqual(e_invalid_arg, parsed.status);
        try std.testing.expectEqual(@as(usize, 0), parsed.data.len);
    }

    // NDR32 error path.
    {
        const rpc_request = try wrapKmsRequest(alloc, std.mem.asBytes(&request_v6), false, 2);
        defer alloc.free(rpc_request);
        const dispatch = try dispatchKmsRequest(alloc, rpc_request[header_size..], &negotiation, &cfg, rng, 1_700_000_000);
        const resp_body = switch (dispatch.kind) {
            .fault => return error.TestUnexpectedResult,
            .response => |body| body,
        };
        defer alloc.free(resp_body);
        const parsed = parseKmsResponse(resp_body, false);
        try std.testing.expectEqual(e_invalid_arg, parsed.status);
    }
}

test "rejected response wire bytes (NDR64)" {
    const alloc = std.testing.allocator;
    var td = try loadTestData(alloc);
    defer td.deinit(alloc);

    var cfg = kms.ServerConfig{ .data = &td.data };
    var base = makeBase(&td.data);
    base.version = 7 << 16; // unsupported major version

    var prng = std.Random.DefaultPrng.init(0x1234_5678);
    const rng = prng.random();
    var request_v6: kms.RequestV6 = undefined;
    kms.createRequestV6(&request_v6, &base, rng);

    var negotiation = BindNegotiation{ .ndr_ctx = 0, .ndr64_ctx = 1 };
    const rpc_request = try wrapKmsRequest(alloc, std.mem.asBytes(&request_v6), true, 2);
    defer alloc.free(rpc_request);

    const dispatch = try dispatchKmsRequest(alloc, rpc_request[header_size..], &negotiation, &cfg, rng, 1_700_000_000);
    const body = switch (dispatch.kind) {
        .fault => return error.TestUnexpectedResult,
        .response => |b| b,
    };
    defer alloc.free(body);

    // Rejected body is 28 bytes: AllocHint@0, ContextId@4, DataLength=0@8,
    // DataSizeMax=0@16, HRESULT 0x8007000D@24 — docs/migration.md §3.3.
    try std.testing.expectEqual(@as(usize, 28), body.len);
    try std.testing.expectEqual(@as(u32, 20), readLe(u32, body, 0)); // AllocHint
    try std.testing.expectEqual(@as(u64, 0), readLe(u64, body, 8)); // DataLength
    try std.testing.expectEqual(@as(u64, 0), readLe(u64, body, 16)); // DataSizeMax
    try std.testing.expectEqual(@as(u32, 0x8007000D), readLe(u32, body, 24)); // HRESULT
}

test "BTFN bind negotiation round-trip" {
    const alloc = std.testing.allocator;

    // Client BIND requesting NDR32 + NDR64 + BTFN.
    const bind_req = try buildBindRequest(alloc, packet_type.bind_req, 2, .{
        .use_ndr64 = true,
        .use_btfn = true,
        .multiplexed = false,
    });
    defer alloc.free(bind_req);

    // Server BIND_ACK with NDR64 and BTFN enabled.
    var negotiation = BindNegotiation{};
    const resp_body = try buildBindResponse(alloc, bind_req[header_size..], 0, .{
        .use_ndr64 = true,
        .use_btfn = true,
        .secondary_address = "1688",
    }, &negotiation);
    defer alloc.free(resp_body);

    const result = parseBindResponse(resp_body);
    // With NDR64 negotiated, NDR32 is declined (Microsoft behavior).
    try std.testing.expect(!result.has_ndr32);
    try std.testing.expect(result.has_ndr64);
    try std.testing.expect(result.has_btfn);
    try std.testing.expectEqual(@as(u16, 0), negotiation.ndr_ctx);
    try std.testing.expectEqual(@as(u16, 1), negotiation.ndr64_ctx);
}

test "BTFN declined when disabled" {
    const alloc = std.testing.allocator;

    const bind_req = try buildBindRequest(alloc, packet_type.bind_req, 2, .{
        .use_ndr64 = false,
        .use_btfn = true,
        .multiplexed = false,
    });
    defer alloc.free(bind_req);

    var negotiation = BindNegotiation{};
    const resp_body = try buildBindResponse(alloc, bind_req[header_size..], 0, .{
        .use_ndr64 = false,
        .use_btfn = false,
    }, &negotiation);
    defer alloc.free(resp_body);

    const result = parseBindResponse(resp_body);
    try std.testing.expect(result.has_ndr32);
    try std.testing.expect(!result.has_ndr64);
    try std.testing.expect(!result.has_btfn);
}
