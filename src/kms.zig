//! KMS protocol layer (v4/v5/v6) — wire/binary-compatible reimplementation
//! of `reference/vlmcsd-src/kms.c` / `kms.h`.
//!
//! Protocol structs are `extern struct` so their memory layout matches the
//! C packed structs byte-for-byte (verified below with compile-time
//! assertions). Numeric fields are stored little-endian, exactly as on the
//! wire; the target platforms (x86_64 / aarch64) are little-endian, matching
//! the reference, which uses `LE16`/`LE32`/`LE64` no-op macros there too.
//!
//! Global state from `shared_globals.c` is replaced by explicit context
//! (`ServerConfig`) and allocator / RNG parameters.

const std = @import("std");
const builtin = @import("builtin");
const crypto = @import("crypto.zig");
const kmsdata = @import("kmsdata.zig");

comptime {
    // The wire layout of this module (and the reference C code) assumes a
    // little-endian host; this is true for the macOS/Linux targets we support.
    if (builtin.target.cpu.arch.endian() != .little) {
        @compileError("kms.zig requires a little-endian target");
    }
}

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// A 16-byte GUID. Treated as opaque bytes (never parsed into scalar fields
/// here); the C reference only ever compares or copies GUIDs wholesale.
pub const Guid = [16]u8;

/// Windows FILETIME: 100-ns ticks since 1601-01-01, little-endian u64.
pub const FileTime = extern struct {
    low: u32,
    high: u32,
};

/// KMS request base (matches C `REQUEST`).
pub const Request = extern struct {
    version: u32,
    vm_info: u32,
    license_status: u32,
    binding_expiration: u32,
    app_id: Guid,
    act_id: Guid,
    kms_id: Guid,
    cmid: Guid,
    n_policy: u32,
    client_time: FileTime,
    cmid_prev: Guid,
    workstation_name: [64]u16,
};

/// KMS response base (matches C `RESPONSE`; `kms_pid` is the max-size slot).
pub const Response = extern struct {
    version: u32,
    pid_size: u32,
    kms_pid: [64]u16,
    cmid: Guid,
    client_time: FileTime,
    count: u32,
    vl_activation_interval: u32,
    vl_renewal_interval: u32,
};

pub const RequestV4 = extern struct {
    base: Request,
    mac: [16]u8,
};

pub const ResponseV4 = extern struct {
    base: Response,
    mac: [16]u8,
};

/// v5 and v6 requests are identical.
pub const RequestV6 = extern struct {
    version: u32,
    iv: [16]u8,
    base: Request,
    pad: [4]u8,
};

pub const ResponseV6 = extern struct {
    version: u32,
    iv: [16]u8,
    base: Response,
    random_xored_ivs: [16]u8,
    hash: [32]u8,
    hwid: [8]u8,
    xored_ivs: [16]u8,
    hmac: [16]u8,
};

pub const ResponseV5 = extern struct {
    version: u32,
    iv: [16]u8,
    base: Response,
    random_xored_ivs: [16]u8,
    hash: [32]u8,
};

// ---------------------------------------------------------------------------
// Constants (derived from the C `sizeof` expressions in kms.h)
// ---------------------------------------------------------------------------

pub const pid_buffer_size = 64;
pub const workstation_name_buffer = 64;
pub const max_response_size = 384;
pub const max_request_size = @sizeOf(RequestV6);
pub const max_clients = 671;

/// Fixed (max-ePID) sizes of the response structs.
pub const request_size: usize = @sizeOf(Request);
pub const response_v4_size: usize = @sizeOf(ResponseV4);
pub const response_v5_size: usize = @sizeOf(ResponseV5);
pub const response_v6_size: usize = @sizeOf(ResponseV6);

/// `RESPONSE_RESULT_OK` — the low 10 bits of the result mask.
pub const response_result_ok: u32 = (1 << 10) - 1;

pub const v4_pre_epid_size = @sizeOf(u32) * 2; // Version + PIDSize
pub const v4_post_epid_size = @sizeOf(Guid) + @sizeOf(FileTime) + @sizeOf(u32) * 3;
pub const v6_unencrypted_size = @sizeOf(u32) + @sizeOf([16]u8); // Version + IV
pub const v6_pre_epid_size = v6_unencrypted_size + @sizeOf(u32) + @sizeOf(u32);
pub const v5_post_epid_size = v4_post_epid_size + @sizeOf([16]u8) + @sizeOf([32]u8);
pub const v6_post_epid_size = v5_post_epid_size + @sizeOf([8]u8) + @sizeOf([16]u8) + @sizeOf([16]u8);
pub const v6_decrypt_size = @sizeOf([16]u8) + @sizeOf(Request) + @sizeOf([4]u8);

/// Offsets used by response construction / HMAC placement.
pub const version_size = @sizeOf(u32);
pub const cmid_offset = @offsetOf(Response, "cmid");
/// Offset of the embedded `Response` inside `ResponseV5`/`ResponseV6`.
pub const response_base_offset = @offsetOf(ResponseV6, "base");

const time_c1: u64 = 0x00000022816889BD;
const time_c2: u64 = 0x000000208CBAB5ED;
const time_c3: u64 = 0x3156CD5AC628477A;

pub const filetime_epoch_offset: i64 = 11_644_473_600; // seconds 1601-01-01 → 1970-01-01
const ticks_per_second: i64 = 10_000_000;

/// Default HwId shipped by the reference (`config.h` `HWID`).
pub const default_hwid = [8]u8{ 0x3A, 0x1C, 0x04, 0x96, 0x00, 0xB6, 0x00, 0x76 };

// HRESULT values returned by `CreateResponseBase` (used as rejection codes).
pub const hresult = struct {
    pub const ok: i32 = 0;
    pub const invalid_arg: i32 = @bitCast(@as(u32, 0x8007000D));
    pub const client_time_mismatch: i32 = @bitCast(@as(u32, 0xC004F06C));
    pub const product_rejected: i32 = @bitCast(@as(u32, 0xC004F042));
    pub const too_many_clients: i32 = @bitCast(@as(u32, 0xC004D104));
};

// ---------------------------------------------------------------------------
// Layout verification (byte-for-byte parity with the C packed structs)
// ---------------------------------------------------------------------------

comptime {
    std.debug.assert(@sizeOf(Request) == 236);
    std.debug.assert(@sizeOf(Response) == 172);
    std.debug.assert(@sizeOf(RequestV4) == 252);
    std.debug.assert(@sizeOf(ResponseV4) == 188);
    std.debug.assert(@sizeOf(RequestV6) == 260);
    std.debug.assert(@sizeOf(ResponseV6) == 280);
    std.debug.assert(@sizeOf(ResponseV5) == 240);

    std.debug.assert(@offsetOf(Request, "version") == 0);
    std.debug.assert(@offsetOf(Request, "app_id") == 16);
    std.debug.assert(@offsetOf(Request, "act_id") == 32);
    std.debug.assert(@offsetOf(Request, "kms_id") == 48);
    std.debug.assert(@offsetOf(Request, "cmid") == 64);
    std.debug.assert(@offsetOf(Request, "n_policy") == 80);
    std.debug.assert(@offsetOf(Request, "client_time") == 84);
    std.debug.assert(@offsetOf(Request, "cmid_prev") == 92);
    std.debug.assert(@offsetOf(Request, "workstation_name") == 108);

    std.debug.assert(@offsetOf(Response, "version") == 0);
    std.debug.assert(@offsetOf(Response, "pid_size") == 4);
    std.debug.assert(@offsetOf(Response, "kms_pid") == 8);
    std.debug.assert(@offsetOf(Response, "cmid") == 136);
    std.debug.assert(@offsetOf(Response, "client_time") == 152);
    std.debug.assert(@offsetOf(Response, "count") == 160);
    std.debug.assert(@offsetOf(Response, "vl_activation_interval") == 164);
    std.debug.assert(@offsetOf(Response, "vl_renewal_interval") == 168);

    std.debug.assert(@offsetOf(RequestV6, "version") == 0);
    std.debug.assert(@offsetOf(RequestV6, "iv") == 4);
    std.debug.assert(@offsetOf(RequestV6, "base") == 20);
    std.debug.assert(@offsetOf(RequestV6, "pad") == 256);

    std.debug.assert(@offsetOf(ResponseV6, "version") == 0);
    std.debug.assert(@offsetOf(ResponseV6, "iv") == 4);
    std.debug.assert(@offsetOf(ResponseV6, "base") == 20);
    std.debug.assert(@offsetOf(ResponseV6, "random_xored_ivs") == 192);
    std.debug.assert(@offsetOf(ResponseV6, "hash") == 208);
    std.debug.assert(@offsetOf(ResponseV6, "hwid") == 240);
    std.debug.assert(@offsetOf(ResponseV6, "xored_ivs") == 248);
    std.debug.assert(@offsetOf(ResponseV6, "hmac") == 264);

    std.debug.assert(v4_pre_epid_size == 8);
    std.debug.assert(v4_post_epid_size == 36);
    std.debug.assert(v6_unencrypted_size == 20);
    std.debug.assert(v6_pre_epid_size == 28);
    std.debug.assert(v5_post_epid_size == 84);
    std.debug.assert(v6_post_epid_size == 124);
    std.debug.assert(v6_decrypt_size == 256);
    std.debug.assert(cmid_offset == 136);
}

// ---------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------

fn readLe(comptime T: type, bytes: []const u8, offset: usize) T {
    const n = @divExact(@typeInfo(T).int.bits, 8);
    return std.mem.readInt(T, bytes[offset..][0..n].ptr[0..n], .little);
}

fn writeLe(comptime T: type, bytes: []u8, offset: usize, value: T) void {
    const n = @divExact(@typeInfo(T).int.bits, 8);
    std.mem.writeInt(T, bytes[offset..][0..n], value, .little);
}

/// `out ^= in` (16 bytes), matching `XorBlock(in, out)` in crypto.c.
fn xorBlock(in: *const [16]u8, out: *[16]u8) void {
    for (0..16) |i| out[i] ^= in[i];
}

pub fn guidEqual(a: *const Guid, b: *const Guid) bool {
    return std.mem.eql(u8, a, b);
}

pub fn zeroGuid() Guid {
    return [_]u8{0} ** 16;
}

pub fn fileTimeToU64(ft: FileTime) u64 {
    return (@as(u64, ft.high) << 32) | ft.low;
}

pub fn u64ToFileTime(v: u64) FileTime {
    return .{ .low = @truncate(v), .high = @truncate(v >> 32) };
}

/// Seconds since 1970-01-01 → FILETIME ticks (100 ns since 1601-01-01).
pub fn unixTimeToFileTime(unix: i64) u64 {
    return @intCast((unix + filetime_epoch_offset) * ticks_per_second);
}

/// FILETIME ticks → seconds since 1970-01-01.
pub fn fileTimeToUnixTime(ft: u64) i64 {
    return @as(i64, @intCast(ft / @as(u64, ticks_per_second))) - filetime_epoch_offset;
}

pub fn majorVersion(version: u32) u16 {
    return @intCast(version >> 16);
}

/// Look up `guid` in `list` from the end (the reference scans backwards).
/// Returns the matching index, or null when absent.
pub fn getProductIndex(guid: *const Guid, list: []const kmsdata.VlmcsdData) ?usize {
    var i = list.len;
    while (i > 0) {
        i -= 1;
        if (guidEqual(guid, &list[i].guid)) return i;
    }
    return null;
}

/// Convert UTF-8 `pid` to UCS-2 in `out`, appending a null terminator.
/// Matches `utf8_to_ucs2` in the reference (BMP only; > 0xFFFE rejected).
/// Returns the number of code units written, excluding the terminator.
fn utf8ToUcs2(out: []u16, pid: []const u8) error{PidTooLong}!usize {
    var view = std.unicode.Utf8View.init(pid) catch return error.PidTooLong;
    var it = view.iterator();
    var n: usize = 0;
    while (it.nextCodepoint()) |cp| {
        if (n + 1 >= out.len) return error.PidTooLong;
        if (cp > 0xFFFE) return error.PidTooLong;
        out[n] = @intCast(cp);
        out[n + 1] = 0;
        n += 1;
    }
    return n;
}

// ---------------------------------------------------------------------------
// Server side
// ---------------------------------------------------------------------------

/// Server-side configuration (replaces `shared_globals.c` state).
pub const ServerConfig = struct {
    data: *const kmsdata.KmsData,
    /// Minutes before an unsuccessful activation retry (default 2 hours).
    vl_activation_interval: u32 = 120,
    /// Minutes before a renewal is required (default 7 days).
    vl_renewal_interval: u32 = 10080,
    /// Reject requests whose client time differs > 4 hours from now.
    check_client_time: bool = false,
    /// Bit 0: reject unknown products; bit 1: reject retail/beta products.
    whitelisting_level: u32 = 0,
    /// HwId embedded in v6 responses.
    hwid: [8]u8 = default_hwid,
};

pub const BuildError = error{
    Rejected,
    PidTooLong,
    OutputTooSmall,
};

/// Write the ePID (UCS-2) and its byte length into `response`.
fn setEpid(response: *Response, pid: []const u8) BuildError!void {
    const n = try utf8ToUcs2(&response.kms_pid, pid);
    response.pid_size = @intCast((n + 1) * 2);
}

/// Build the unencrypted base response. Returns an HRESULT (0 = S_OK).
/// This is the non-strict (no client list) path plus whitelist/time checks,
/// matching `CreateResponseBaseCallback` with `MaintainClients` off.
pub fn createResponseBase(
    cfg: *const ServerConfig,
    request: *const Request,
    response: *Response,
    now_unix: i64,
) i32 {
    const min_clients = request.n_policy;
    const required_clients: u32 = if (min_clients < 1) 1 else min_clients << 1;

    const kms_items = cfg.data.kms();
    const index_opt = getProductIndex(&request.kms_id, kms_items);

    // Strict-mode checks (before touching the response).
    if (required_clients > 2000) return hresult.invalid_arg;

    if (cfg.check_client_time) {
        const request_time = fileTimeToUnixTime(fileTimeToU64(request.client_time));
        const diff = request_time - now_unix;
        if (diff > 4 * 60 * 60 or diff < -4 * 60 * 60) return hresult.client_time_mismatch;
    }

    if (cfg.whitelisting_level & 2 != 0) {
        if (index_opt) |i| {
            const item = kms_items[i];
            if (item.is_retail != 0 or item.is_preview != 0) return hresult.product_rejected;
        }
    }

    if (cfg.whitelisting_level & 1 != 0) {
        if (index_opt) |i| {
            const app_guid = cfg.data.apps()[kms_items[i].app_index].guid;
            if (!guidEqual(&app_guid, &request.app_id)) return hresult.product_rejected;
        } else {
            return hresult.product_rejected;
        }
    }

    const epid_index: usize = if (index_opt) |i| kms_items[i].epid_index else 0;

    const min_active_clients = cfg.data.csvlk[epid_index].min_active_clients;
    response.count = @max(required_clients, min_active_clients);

    setEpid(response, cfg.data.csvlk[epid_index].epid) catch return hresult.invalid_arg;

    response.version = request.version;
    response.cmid = request.cmid;
    response.client_time = request.client_time;
    response.vl_activation_interval = cfg.vl_activation_interval;
    response.vl_renewal_interval = cfg.vl_renewal_interval;

    return hresult.ok;
}

/// Compute the v6 HMAC over the encrypted part of the response.
/// `encrypt_start` points at the IV (first byte of the encrypted region) and
/// is already decrypted plaintext when verifying. The HMAC key is the last 16
/// bytes of SHA256(time slot), where the time slot is derived from the
/// response `ClientTime` (tolerance 0 when generating, -1/0/+1 when checking).
fn createV6Hmac(encrypt_start: []u8, encrypt_size: usize, tolerance: i8) void {
    var hash: [32]u8 = undefined;

    const ft_offset = encrypt_size - v6_post_epid_size + @sizeOf(Guid);
    const ft = readLe(u64, encrypt_start, ft_offset);

    const tol: u64 = @bitCast(@as(i64, tolerance));
    const time_slot = (ft / time_c1) *% time_c2 +% time_c3 +% (tol *% time_c1);

    var slot_bytes: [8]u8 = undefined;
    writeLe(u64, &slot_bytes, 0, time_slot);
    crypto.sha256(&slot_bytes, &hash);

    var hmac_out: [32]u8 = undefined;
    crypto.hmacSha256(hash[16..32], encrypt_start[0 .. encrypt_size - 16], &hmac_out);

    @memcpy(encrypt_start[encrypt_size - 16 ..][0..16], hmac_out[16..32]);
}

/// Move the variable-length ePID out of the fixed `RESPONSE` slot, shifting
/// everything after it left (equivalent to the `memmove` in `CreateResponse*`).
fn compactEpid(out: []u8, pid_size: usize, post_epid_size: usize) void {
    const dest = v6_pre_epid_size + pid_size;
    const src = response_base_offset + cmid_offset;
    if (dest <= src) {
        std.mem.copyForwards(u8, out[dest..], out[src..][0..post_epid_size]);
    } else {
        std.mem.copyBackwards(u8, out[dest..], out[src..][0..post_epid_size]);
    }
}

/// Create a v4 response. Returns the response byte length.
pub fn createResponseV4(
    request: *const RequestV4,
    out: *align(@alignOf(ResponseV4)) [max_response_size]u8,
    cfg: *const ServerConfig,
    now_unix: i64,
) BuildError!usize {
    const response: *ResponseV4 = @ptrCast(out);

    const hresult_code = createResponseBase(cfg, &request.base, &response.base, now_unix);
    if (hresult_code != hresult.ok) return error.Rejected;

    const pid_size = response.base.pid_size;

    // Shift the post-ePID fields up against the variable-length ePID.
    const post_epid_ptr = v4_pre_epid_size + pid_size;
    std.mem.copyForwards(u8, out[post_epid_ptr..], out[cmid_offset..][0..v4_post_epid_size]);

    const encrypt_size = v4_pre_epid_size + v4_post_epid_size + pid_size;

    // The v4 MAC sits at the variable-length boundary (after the shifted
    // post-ePID fields), not at the fixed `ResponseV4.mac` slot.
    var mac: [16]u8 = undefined;
    crypto.aesCmacV4(out[0..encrypt_size], &mac);
    @memcpy(out[encrypt_size..][0..16], &mac);

    return encrypt_size + @sizeOf([16]u8);
}

/// Create a v5 or v6 response. Returns the response byte length.
pub fn createResponseV6(
    request: *RequestV6,
    out: *align(@alignOf(ResponseV6)) [max_response_size]u8,
    cfg: *const ServerConfig,
    rng: std.Random,
    now_unix: i64,
) BuildError!usize {
    const is_v6 = majorVersion(request.version) > 5;
    const key: []const u8 = if (is_v6) &crypto.aes_key_v6 else &crypto.aes_key_v5;

    // 1. Decrypt the request in place (IV + base + pad, zero IV).
    crypto.aesCbcDecrypt(key, is_v6, null, std.mem.asBytes(request)[4..], v6_decrypt_size);

    const response: *ResponseV6 = @ptrCast(out);
    @memset(out[0..@sizeOf(ResponseV6)], 0);

    // 2. Random salt + its SHA-256.
    rng.bytes(&response.random_xored_ivs);
    crypto.sha256(&response.random_xored_ivs, &response.hash);

    if (is_v6) {
        response.version = request.version;
        rng.bytes(&response.iv);
        response.hwid = cfg.hwid;
        // Copy the (now decrypted) request IV — identical to XORing the
        // non-decrypted request IV with the response IV.
        @memcpy(&response.xored_ivs, &request.iv);
    } else {
        // v5: request and response IVs must be identical (version + IV).
        @memcpy(out[0..v6_unencrypted_size], std.mem.asBytes(request)[0..v6_unencrypted_size]);
    }

    // 3. RandomXoredIVs ^= decrypted request IV.
    xorBlock(&request.iv, &response.random_xored_ivs);

    // 4. Base response.
    const hresult_code = createResponseBase(cfg, &request.base, &response.base, now_unix);
    if (hresult_code != hresult.ok) return error.Rejected;

    // 5. Compact the variable-length ePID.
    const pid_size = response.base.pid_size;
    const post_epid_size: usize = if (is_v6) v6_post_epid_size else v5_post_epid_size;
    compactEpid(out, pid_size, post_epid_size);

    // 6. Encrypt from the IV onward (PKCS#7 padding is handled by the cipher).
    var encrypt_size: usize = v6_pre_epid_size - version_size + pid_size + post_epid_size;

    if (is_v6) createV6Hmac(out[version_size..], encrypt_size, 0);

    encrypt_size = crypto.aesCbcEncrypt(key, is_v6, null, out[version_size..], encrypt_size);

    return encrypt_size + version_size;
}

// ---------------------------------------------------------------------------
// Client side
// ---------------------------------------------------------------------------

/// Build a v4 client request (base + CMAC).
pub fn createRequestV4(out: *RequestV4, base: *const Request) void {
    out.base = base.*;
    crypto.aesCmacV4(std.mem.asBytes(&out.base)[0..@sizeOf(Request)], &out.mac);
}

/// Build a v5/v6 client request (version + random IV + encrypted base).
pub fn createRequestV6(out: *RequestV6, base: *const Request, rng: std.Random) void {
    out.version = base.version;
    rng.bytes(&out.iv);
    out.base = base.*;

    const is_v6 = majorVersion(base.version) > 5;
    const key: []const u8 = if (is_v6) &crypto.aes_key_v6 else &crypto.aes_key_v5;
    _ = crypto.aesCbcEncrypt(key, is_v6, &out.iv, std.mem.asBytes(out)[20..], @sizeOf(Request));
}

fn checkPidLength(base: *const Response) bool {
    const pid_size = base.pid_size;
    if (pid_size > pid_buffer_size * 2) return false;
    if (pid_size < 2) return false;
    const chars = pid_size / 2;
    if (base.kms_pid[chars - 1] != 0) return false;
    var i: usize = 0;
    while (i + 2 < chars) : (i += 1) {
        if (base.kms_pid[i] == 0) return false;
    }
    return true;
}

/// Result of verifying a decrypted response (mirrors the C bitfield union).
pub const ResponseResult = struct {
    hash_ok: bool = true,
    timestamp_ok: bool = true,
    client_machine_id_ok: bool = true,
    version_ok: bool = true,
    ivs_ok: bool = true,
    decrypt_success: bool = true,
    hmac_sha256_ok: bool = true,
    pid_length_ok: bool = true,
    rpc_ok: bool = true,
    iv_not_suspicious: bool = true,
    effective_response_size: u16 = 0,
    correct_response_size: u16 = 0,

    /// True when every bit that makes up `RESPONSE_RESULT_OK` is set.
    pub fn ok(self: *const ResponseResult) bool {
        return self.hash_ok and self.timestamp_ok and self.client_machine_id_ok and
            self.version_ok and self.ivs_ok and self.decrypt_success and
            self.hmac_sha256_ok and self.pid_length_ok and self.rpc_ok and
            self.iv_not_suspicious;
    }
};

/// Verify a v4 response against the request that produced it.
pub fn decryptResponseV4(
    out: *ResponseV4,
    response_size: usize,
    response: []const u8,
    raw_request: *const RequestV4,
) ResponseResult {
    var result = ResponseResult{};
    result.effective_response_size = @intCast(response_size);

    const pid_size_raw = readLe(u32, response, 4);
    const pid_size: usize = @min(pid_size_raw, pid_buffer_size * 2);
    const copy_size = v4_pre_epid_size + pid_size;
    const message_size = copy_size + v4_post_epid_size;

    @memcpy(std.mem.asBytes(out)[0..copy_size], response[0..copy_size]);
    @memcpy(std.mem.asBytes(out)[cmid_offset..][0 .. response_size - copy_size], response[copy_size..]);
    out.base.kms_pid[pid_buffer_size - 1] = 0;

    var mac: [16]u8 = undefined;
    crypto.aesCmacV4(response[0..message_size], &mac);

    result.pid_length_ok = checkPidLength(&out.base);
    result.version_ok = out.base.version == raw_request.base.version;
    result.hash_ok = std.mem.eql(u8, &out.mac, &mac);
    result.timestamp_ok = std.mem.eql(u8, std.mem.asBytes(&out.base.client_time), std.mem.asBytes(&raw_request.base.client_time));
    result.client_machine_id_ok = guidEqual(&out.base.cmid, &raw_request.base.cmid);
    result.correct_response_size = @intCast(@sizeOf(ResponseV4) - pid_buffer_size * 2 + pid_size);

    return result;
}

fn verifyResponseV6(
    result: *ResponseResult,
    response_v6: *const ResponseV6,
    request_v6: *const RequestV6,
    raw_response: []u8,
) void {
    result.ivs_ok = std.mem.eql(u8, &response_v6.xored_ivs, &request_v6.iv);
    result.iv_not_suspicious = !std.mem.eql(u8, &request_v6.iv, &response_v6.iv);

    var old_hmac: [16]u8 = undefined;
    @memcpy(&old_hmac, &response_v6.hmac);

    result.hmac_sha256_ok = false;
    const encrypt_size = result.correct_response_size - version_size;

    var tolerance: i8 = -1;
    while (tolerance < 2) : (tolerance += 1) {
        createV6Hmac(raw_response[version_size..], encrypt_size, tolerance);
        result.hmac_sha256_ok = std.mem.eql(
            u8,
            &old_hmac,
            raw_response[result.correct_response_size - 16 ..][0..16],
        );
        if (result.hmac_sha256_ok) break;
    }
}

fn verifyResponseV5(
    result: *ResponseResult,
    request_v6: *const RequestV6,
    response_v5: *const ResponseV5,
) void {
    result.ivs_ok = std.mem.eql(u8, &request_v6.iv, &response_v5.iv);
    result.hmac_sha256_ok = true;
}

/// Decrypt and verify a v5/v6 response. `response` is decrypted in place;
/// `raw_request` is decrypted in place (it must hold the encrypted request).
pub fn decryptResponseV6(
    out: *ResponseV6,
    response_size: usize,
    response: []u8,
    raw_request: *RequestV6,
    hwid: ?*[8]u8,
) ResponseResult {
    var result = ResponseResult{};
    result.effective_response_size = @intCast(response_size);

    const is_v6 = majorVersion(readLe(u32, response, 0)) > 5;
    const key: []const u8 = if (is_v6) &crypto.aes_key_v6 else &crypto.aes_key_v5;

    // Decrypt everything after the unencrypted Version field.
    crypto.aesCbcDecrypt(key, is_v6, null, response[version_size..], response_size - version_size);

    // PKCS#7 padding must be 1..16 and uniform.
    const last_pad = response[response_size - 1];
    if (last_pad == 0 or last_pad > 16) {
        result.decrypt_success = false;
        return result;
    }
    for (response[response_size - last_pad .. response_size - 1]) |b| {
        if (b != last_pad) {
            result.decrypt_success = false;
            return result;
        }
    }

    const pid_size_raw = readLe(u32, response, 24);
    const pid_size: usize = @min(pid_size_raw, pid_buffer_size * 2);

    const copy_size1 = v6_pre_epid_size + pid_size;
    @memcpy(std.mem.asBytes(out)[0..copy_size1], response[0..copy_size1]);
    out.base.kms_pid[pid_buffer_size - 1] = 0;

    const copy_size2: usize = if (is_v6) v6_post_epid_size else v5_post_epid_size;
    @memcpy(
        std.mem.asBytes(out)[response_base_offset + cmid_offset ..][0..copy_size2],
        response[copy_size1..][0..copy_size2],
    );

    // Decrypt the request in place so its base fields are readable.
    crypto.aesCbcDecrypt(key, is_v6, null, std.mem.asBytes(raw_request)[4..], v6_decrypt_size);

    result.version_ok =
        raw_request.version == out.base.version and
        raw_request.version == out.version and
        raw_request.version == raw_request.base.version;

    result.pid_length_ok = checkPidLength(&out.base);
    result.timestamp_ok = std.mem.eql(u8, std.mem.asBytes(&out.base.client_time), std.mem.asBytes(&raw_request.base.client_time));
    result.client_machine_id_ok = guidEqual(&out.base.cmid, &raw_request.base.cmid);

    // Rebuild the random key and verify its hash.
    var random_key: [16]u8 = undefined;
    @memcpy(&random_key, &raw_request.iv);
    xorBlock(&out.random_xored_ivs, &random_key);
    var hash_verify: [32]u8 = undefined;
    crypto.sha256(&random_key, &hash_verify);
    result.hash_ok = std.mem.eql(u8, &out.hash, &hash_verify);

    result.correct_response_size = @intCast((if (is_v6) response_v6_size else response_v5_size) - pid_buffer_size * 2 + pid_size);

    if (is_v6) {
        if (hwid) |h| @memcpy(h, &out.hwid);
        verifyResponseV6(&result, out, raw_request, response);
    } else {
        verifyResponseV5(&result, raw_request, @ptrCast(out));
    }

    // Add the padding length that was stripped by the decrypt.
    const pre_pad = result.correct_response_size - version_size;
    const pad: usize = if (pre_pad % 16 == 0) 16 else 16 - (pre_pad % 16);
    result.correct_response_size = @intCast(@as(usize, result.correct_response_size) + pad);

    return result;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "filetime conversion" {
    try std.testing.expectEqual(@as(u64, 116_444_736_000_000_000), unixTimeToFileTime(0));
    try std.testing.expectEqual(@as(i64, 0), fileTimeToUnixTime(116_444_736_000_000_000));
    try std.testing.expectEqual(@as(i64, 1_700_000_000), fileTimeToUnixTime(unixTimeToFileTime(1_700_000_000)));
}

const TestData = struct {
    raw: []u8,
    data: kmsdata.KmsData,

    fn deinit(self: *TestData, allocator: std.mem.Allocator) void {
        self.data.deinit(allocator);
        allocator.free(self.raw);
    }
};

fn loadTestData(allocator: std.mem.Allocator) !TestData {
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const raw = try std.Io.Dir.readFileAlloc(std.Io.Dir.cwd(), io, "reference/vlmcsd.kmd", allocator, .unlimited);
    errdefer allocator.free(raw);
    const data = try kmsdata.parse(allocator, raw);
    return .{ .raw = raw, .data = data };
}

fn makeBase(data: *const kmsdata.KmsData, version: u32) Request {
    var base: Request = std.mem.zeroes(Request);
    base.version = version;
    base.vm_info = 0;
    base.license_status = 1;
    base.kms_id = data.kms()[0].guid;
    base.app_id = data.apps()[0].guid;
    base.act_id = data.kms()[0].guid;
    base.cmid = [16]u8{ 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 };
    base.n_policy = 25;
    base.client_time = u64ToFileTime(unixTimeToFileTime(1_700_000_000));
    for ("test-host", 0..) |c, i| base.workstation_name[i] = c;
    return base;
}

test "v4 request/response round-trip" {
    const alloc = std.testing.allocator;
    var td = try loadTestData(alloc);
    defer td.deinit(alloc);

    var cfg = ServerConfig{ .data = &td.data };
    const base = makeBase(&td.data, 4 << 16);

    var request: RequestV4 = undefined;
    createRequestV4(&request, &base);

    var out: [max_response_size]u8 align(4) = undefined;
    const resp_len = try createResponseV4(&request, &out, &cfg, 1_700_000_000);

    var resp: ResponseV4 = undefined;
    const result = decryptResponseV4(&resp, resp_len, out[0..resp_len], &request);
    try std.testing.expect(result.ok());
    try std.testing.expectEqual(resp.base.version, base.version);
    try std.testing.expect(guidEqual(&resp.base.cmid, &base.cmid));
}

test "v5 request/response round-trip" {
    const alloc = std.testing.allocator;
    var td = try loadTestData(alloc);
    defer td.deinit(alloc);

    var cfg = ServerConfig{ .data = &td.data };
    const base = makeBase(&td.data, 5 << 16);

    var prng = std.Random.DefaultPrng.init(0x1234_5678);
    const rng = prng.random();

    var request_sent: RequestV6 = undefined;
    createRequestV6(&request_sent, &base, rng);

    var request_server = request_sent;
    var request_client = request_sent;

    var out: [max_response_size]u8 align(4) = undefined;
    const resp_len = try createResponseV6(&request_server, &out, &cfg, rng, 1_700_000_000);

    var resp: ResponseV6 = undefined;
    const result = decryptResponseV6(&resp, resp_len, out[0..resp_len], &request_client, null);
    try std.testing.expect(result.ok());
}

test "v6 request/response round-trip" {
    const alloc = std.testing.allocator;
    var td = try loadTestData(alloc);
    defer td.deinit(alloc);

    var cfg = ServerConfig{ .data = &td.data };
    const base = makeBase(&td.data, 6 << 16);

    var prng = std.Random.DefaultPrng.init(0x9e37_79b9);
    const rng = prng.random();

    var request_sent: RequestV6 = undefined;
    createRequestV6(&request_sent, &base, rng);

    var request_server = request_sent;
    var request_client = request_sent;

    var out: [max_response_size]u8 align(4) = undefined;
    const resp_len = try createResponseV6(&request_server, &out, &cfg, rng, 1_700_000_000);

    var resp: ResponseV6 = undefined;
    var hwid: [8]u8 = undefined;
    const result = decryptResponseV6(&resp, resp_len, out[0..resp_len], &request_client, &hwid);
    try std.testing.expect(result.ok());
    try std.testing.expectEqual(cfg.hwid, hwid);
    try std.testing.expectEqual(base.version, resp.base.version);
    try std.testing.expect(guidEqual(&resp.base.cmid, &base.cmid));
}
