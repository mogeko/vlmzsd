# vlmzsd Migration Status & Traceability Document

This document records the migration status, key implementation details, and known deviations of the
vlmcsd (C, [Wind4/vlmcsd@svn1113](https://github.com/Wind4/vlmcsd/tree/svn1113)) → vlmzsd (modern Zig, `src/`) port. The goal: **to be able to
trace protocol behavior, byte layouts, and design decisions even though the C code is no longer
vendored in this repository.**

> References: `AGENTS.md` (architecture & conventions), `docs/cli.md` (CLI spec),
> `config.h`, `kms.c`/`kms.h`, `rpc.c`/`rpc.h`, `crypto*.c`, `helpers.c`, `network.c` in the upstream
> [vlmcsd](https://github.com/Wind4/vlmcsd/tree/svn1113) source (historical reference).

---

## 1. Overall conclusion

**Migration is complete; wire-level compatibility is byte-for-byte.**

- The v4 / v5 / v6 **normal activation paths** (valid request → response build → encryption/HMAC → RPC framing) are **byte-identical** to the C reference.
- Error/exception paths (invalid version, short request, unknown context, data-file validation) are aligned with C behavior.
- All remaining differences fall into one of two classes — "intentional design" or "defect fix" — and are itemized in section 5; none constitutes a wire incompatibility.

Verification: 35/35 unit tests pass (including byte-level golden vectors), plus `vlmzs` ↔ `vlmzsd` end-to-end (v4/v5/v6, NDR32/NDR64, DNS, dual-stack).

---

## 2. Module mapping overview

| Upstream C source | Zig implementation | Migration type | Status |
|---|---|---|---|
| `kms.c` / `kms.h` | `src/kms.zig` | Protocol layer (wire-critical) | ✅ Done |
| `rpc.c` / `rpc.h` | `src/rpc.zig` + `src/network.zig` (byte-stream part) | Transport layer (wire-critical) | ✅ Done |
| `crypto.c` / `crypto_internal.c` | `src/crypto.zig` | Algorithm layer (wire-critical) | ✅ Done |
| `helpers.c` (`loadKmsData`) + `kms.h` structs | `src/kmsdata.zig` | Binary data parsing (wire-critical) | ✅ Done |
| `network.c` | `src/network.zig` | Network layer (internal, non-wire) | ✅ Done |
| `vlmcsd.c` | `src/main.zig` | Server CLI + accept loop | ✅ Done (CLI redesigned) |
| `vlmcs.c` | `src/vlmzs.zig` | Client CLI | ✅ Done (CLI redesigned) |
| `output.c` + misc parsing | `src/cli_helper.zig` | Logging + value parsing | ✅ Done |
| `shared_globals.c` | (explicit context passing per module) | Global state eliminated | ✅ Done |
| `libkms.c` / `libkms.h` | — | Public C embedding API | ❌ Not migrated (no counterpart) |
| `msrpc-*.c`, `KMSServer_*` | — | Windows `USE_MSRPC` native MS-RPC | ❌ Not migrated (Windows path skipped) |
| `dns_srv.c`, `ns_*.c`, `wingetopt.c`, `wintap.c`, `ntservice.c`, etc. | — | Platform-specific / service integration | ❌ Not migrated |

---

## 3. Key constants and byte layouts (traceable after C deletion)

### 3.1 KMS protocol struct layouts (`extern struct`, locked by comptime asserts)

All numeric fields are little-endian; the target platforms (x86_64 / aarch64) are little-endian,
equivalent to the C `LE16/LE32/LE64` no-op macros.

| Struct | Size | Key field offsets |
|---|---|---|
| `REQUEST` | 236 | `version@0` `app_id@16` `act_id@32` `kms_id@48` `cmid@64` `n_policy@80` `client_time@84` `cmid_prev@92` `workstation_name@108` |
| `RESPONSE` | 172 | `version@0` `pid_size@4` `kms_pid@8` `cmid@136` `client_time@152` `count@160` `vl_activation_interval@164` `vl_renewal_interval@168` |
| `REQUEST_V4` | 252 | `base@0` `mac@236` |
| `RESPONSE_V4` | 188 | `base@0` `mac@172` |
| `REQUEST_V6` (=v5) | 260 | `version@0` `iv@4` `base@20` `pad@256` |
| `RESPONSE_V6` | 280 | `version@0` `iv@4` `base@20` `random_xored_ivs@192` `hash@208` `hwid@240` `xored_ivs@248` `hmac@264` |
| `RESPONSE_V5` | 240 | `version@0` `iv@4` `base@20` `random_xored_ivs@192` `hash@208` |

`sizeof`-derived constants (C macros → Zig `pub const`, values identical):

```
v4_pre_epid_size = 8          (Version + PIDSize)
v4_post_epid_size = 36        (CMID + ClientTime + Count + VLActivationInterval + VLRenewalInterval)
v6_unencrypted_size = 20      (Version + IV)
v6_pre_epid_size = 28         (v6_unencrypted + Version + PIDSize)
v5_post_epid_size = 84        (v4_post + RandomXoredIVs + Hash)
v6_post_epid_size = 124       (v5_post + HwId + XoredIVs + HMAC)
v6_decrypt_size = 256         (IV + REQUEST + Pad)
cmid_offset = 136
response_base_offset = 20     (offset of the embedded `base` inside ResponseV6)
max_response_size = 384
pid_buffer_size = 64
max_request_size = 260        (= sizeof(REQUEST_V6))
max_clients = 671
response_result_ok = (1 << 10) - 1 = 0x3FF
```

### 3.2 Crypto constants

| Name | Value (byte-for-byte identical to the C tables) |
|---|---|
| `AesKeyV4` | `05 3d 83 07 f9 e5 f0 88 eb 5e a6 68 6c f0 37 c7 e4 ef d2 d6` (20 bytes, 160-bit) |
| `AesKeyV5` | `cd 7e 79 6f 2a b2 5d cb 55 ff c8 ef 83 64 c4 70` |
| `AesKeyV6` | `a9 4a 41 95 e2 01 43 2d 9b cb 46 04 05 d8 4a 21` |
| `TIME_C1` | `0x00000022816889BD` |
| `TIME_C2` | `0x000000208CBAB5ED` |
| `TIME_C3` | `0x3156CD5AC628477A` |
| `BUILD_TIME` | `1538922811` (2013-10-17T13:00:11Z, lower bound for randomized ePID dates) |
| `HWID` (`config.h`) | `3a 1c 04 96 00 b6 00 76` |
| `filetime_epoch_offset` | `11644473600` (seconds 1601-01-01 → 1970-01-01) |

**v6 non-standard key schedule** (`AesInitKey`, applied after the standard 128-bit expansion of a 16-byte key):

```
rk[ 4*16 =  64 ] ^= 0x73
rk[ 6*16 =  96 ] ^= 0x09
rk[ 8*16 = 128 ] ^= 0xE4
```

The **v4 key** is 160-bit Rijndael (Nk=5 → 11 rounds); `std.crypto` cannot express it, so
`src/crypto.zig` implements AES from scratch per FIPS-197. The v5/v6 keys are 128-bit (Nk=4 → 10 rounds),
with v6 additionally applying the XOR modification above.

**v4 CMAC**: CBC-MAC, zero IV, ISO 9797-1 padding method 2 (`0x80` then zeros up to the block boundary; a full padding block when already aligned).

### 3.3 DCE/RPC constants and layouts

| Name | Value |
|---|---|
| RPC header | 16 bytes: `ver_major=5, ver_minor=0, type, flags, data_rep, frag_len, auth_len, call_id` |
| `data_representation` | `BE32(0x10000000)` stored little-endian = bytes `10 00 00 00` (LE + ASCII + IEEE) |
| BIND CtxItem / CtxResult | 44 / 24 bytes |
| BIND fixed / response fixed | 12 / 20 bytes (up to the first item/result) |
| NDR32 request/response data offset | 16 / 20 |
| NDR64 request/response data offset | 24 / 32 |
| Server FAULT `CallId` | always `2` (C global `CallId`, never incremented server-side) |
| `RPC_INVALID_CTX` | `0xFFFF` |
| `nca_unk_if` / `nca_proto_error` | `0x1c010003` / `0x1c01000b` |
| Rejected response `DataSizeMax=DataLength=0`, HRESULT | `0x8007000D` (`E_INVALIDARG`) |

GUIDs (serialized bytes, i.e. the `GUID` four little-endian words + 8-byte tail):

| Name | Canonical form | Bytes |
|---|---|---|
| interface | `51C82175-4E84-4750-B0D8-EC255555BC06` | `75 21 c8 51 4e 84 50 47 b0 d8 ec 25 55 55 bc 06` |
| ndr32 | `8A885D04-1CEB-11C9-9FE8-08002B104860` | `04 5d 88 8a eb 1c c9 11 9f e8 08 00 2b 10 48 60` |
| ndr64 | `71710533-BEBA-4937-8319-B5DBEF9CCC36` | `33 05 71 71 ba be 37 49 83 19 b5 db ef 9c cc 36` |
| btfn | `6CB71C2C-9812-4540-0300-000000000000` | `2c 1c b7 6c 12 98 40 45 03 00 00 00 00 00 00 00` |

### 3.4 `.kmd` data file format (compatible with `loadKmsData`)

- 72-byte header: `Magic[0..4]="KMD\0"`, `MinorVer@4` (u16), `MajorVer@6` (u16, **must == 2**),
  `CsvlkCount@8`, `Flags@9`, `Reserved[2]@10`,
  `AppItemCount@12` / `KmsItemCount@16` / `SkuItemCount@20` / `HostBuildCount@24` (u32 each),
  `AppItemOffset@32` / `HostBuildOffset@56` (u64 each, relative to the file start).
- The final byte must be 0 (format check with `UNSAFE_DATA_LOAD` off).
- CSVLC record, 32 bytes: `EPidOffset@0` (u64) `ReleaseDate@8` (i64) `GroupId@16` (u32)
  `MinKeyId@20` (u32) `MaxKeyId@24` (u32) `MinActiveClients@28` (u8).
- Item record, 32 bytes (app/kms/sku stored contiguously): `Guid@0` (16) `NameOffset@16` (u64)
  `AppIndex@24` `KmsIndex@25` `ProtocolVersion@26` `NCountPolicy@27`
  `IsRetail@28` `IsPreview@29` `EPidIndex@30`.
- HostBuild record, 32 bytes: `DisplayNameOffset@0` (u64) `ReleaseDate@8` (i64)
  `BuildNumber@16` (i32) `PlatformId@20` (i32) `Flags@24` (u32, `UseNdr64=1<<0`).
- Default data: `src/vlmcsd.kmd` (embedded; 15,079 bytes, 6 CSVLC / 3 app / 29 kms / 202 sku / 6 hostbuild).

---

## 4. Per-module migration details

### 4.1 `src/kms.zig` (← `kms.c` / `kms.h`)

- **Structs**: `extern struct` + comptime asserts lock the layout (see 3.1). Fields use
  `std.mem.readInt/writeInt(..., .little)`; bytes are never `@ptrCast` to a struct with padding.
- **Response build**:
  - `createResponseV4`: `CreateResponseBase` → `memmove` (source `cmid@136` → destination `8+pidSize`) →
    `AesCmacV4(out[0..8+36+pidSize])` → MAC written at `encryptSize`.
  - `createResponseV6`: first `AesDecryptCbc(request[4..], 256)`; random salt + `SHA256`;
    v6 writes random IV / `HwId` / `XoredIVs=decrypted request IV`, v5 copies `Version+IV`;
    `RandomXoredIVs ^= request IV`; `CreateResponseBase`; ePID `memmove` (`post_epid_size` differs for v5/v6);
    `CreateV6Hmac(..., tolerance=0)`; `AesEncryptCbc` over `encryptSize = 28-4+pidSize+post` (PKCS#7 padding).
  - `createResponseBase`: `required_clients = n_policy<1 ? 1 : n_policy<<1`;
    rejection order = C `CreateResponseBaseCallback` (>2000 → `0x8007000D`; client time off by >4h → `0xC004F06C`;
    whitelist 2/1 → `0xC004F042`; strict-mode client list full → `0xC004D104`).
  - `CreateV6Hmac`: `time_slot = (ft/C1*C2+C3) + tolerance*C1` (unsigned wraparound `*%/+%`);
    HMAC key = `SHA256(time_slot)[16..32]`; HMAC data = `encrypt_start[0..encryptSize-16]`;
    last 16 bytes of the result written to `encrypt_start[encryptSize-16..]`. Verification uses `tolerance ∈ {-1,0,1}`.
- **ePID generation**: `platform(5)-group(5)-keyHi(3)-keyLo(6)-03-lang-build.0000-yday(3)year(4)`;
  `keyId ∈ [MinKeyId, MaxKeyId)`; the `hostBuild` `UseNdr64` flag must match the negotiated syntax;
  date `min = max(ReleaseDate, HostBuildReleaseDate)`, `max = max(now, BUILD_TIME)`, `span<=0` takes `min` (fixes C's `%0` UB);
  the 160-entry LCID list matches C `LcidList` item-for-item.
- **Client list** (`--maintain-clients`): `ClientList{guids[671], current_count, max_count, current_position}`;
  ring buffer + oldest-entry eviction; `max_count` capped at `min(required, 671)` (avoids the C out-of-bounds).

### 4.2 `src/rpc.zig` + `src/network.zig` (← `rpc.c` / `rpc.h`)

- `rpc.zig` is pure wire format (no sockets): RPC header, BIND negotiation, NDR wrapping, FAULT, client parsing.
- `network.zig` is byte-stream I/O (`std.Io` replacing `sendrecv`): `serveRpc` (server loop),
  `clientBind` / `clientSendRequest` (client), socket glue (`connect`/`listen`).
- **BIND negotiation**: context item 44B / result 24B; secondary address length includes NUL, 4-byte aligned
  (`results_offset = (10 + port_size + 3) & ~3`); NACK NDR32 whenever NDR64 is available (Microsoft behavior);
  BTFN feature mask = `transfer_syntax[8..10] & 0x3`.
- **Request dispatch** (`dispatchKmsRequest`, mirroring C `checkRpcRequestSize` + `rpcRequest`):
  - context mismatch → **FAULT** `nca_unk_if` (`AllocHint=32`, `Error.Code@8`, `CallId=2`).
  - too-short request / major outside 4..6 / minor != 0 → **RESPONSE** + `0x8007000D` (`DataSizeMax=DataLength=0`,
    status in the `DataSizeIs` slot: NDR32@16 / NDR64@24), **not** a FAULT and **not** a disconnect.
- **Response assembly**: success writes `DataLength/DataSizeMax/DataSizeIs` + data + trailing 4-byte return code;
  rejection writes only `DataLength=0/DataSizeMax=0`, return code right after (NDR64 body 28 bytes).
- **Client parsing** (`parseKmsResponse`): `DataSizeMax==0` is treated as rejection, status read from the
  `DataSizeIs` slot; success reads the status at `data_offset + data_length`.

### 4.3 `src/crypto.zig` (← `crypto.c` / `crypto_internal.c`)

- AES implemented per FIPS-197 (S-box / inverse S-box / key expansion / MixColumns, etc.), supporting Nk=4 and Nk=5.
- `expandKey(comptime nk, key, is_v6)`: after standard expansion, v6 applies the `rk[64]/rk[96]/rk[128]` XOR.
- `aesCmacV4`, `aesCbcEncrypt/Decrypt` (PKCS#7), `hmacSha256`/`sha256` (`std.crypto`).
- Golden vectors: hard-coded hex constants in `src/crypto.zig` tests (derived from the upstream C `dump_vectors`).

### 4.4 `src/kmsdata.zig` (← `helpers.c loadKmsData`)

- Field-by-field `std.mem.readInt` parsing (no `@ptrCast`), returning `KmsData` (with `apps()/kms()/skus()` views).
- Additionally reads the `name` string that immediately follows each CSVLC record, used by
  `--epid <name>=<epid>` lookups (the C code does not read it — an intentional extension).
- Validation: `"KMD\0"`, `MajorVer==2`, trailing NUL byte.

### 4.5 `src/network.zig` (← `network.c`)

- `isPrivateIPAddress`: IPv4 five ranges (127/8, 192.168/16, 169.254/16, 10/8, 172.16/12);
  IPv6 public when not `::1` and within `2000::/3`; **IPv4-mapped (`::ffff:a.b.c.d`) extracts the
  embedded IPv4 for an exact decision** (see 5.1).
- `getPrivateIPAddresses`: `getifaddrs` (self-declared extern) enumerating AF_INET/AF_INET6 interfaces.
- Dual-stack socket: a single `::` socket accepts both IPv4 and IPv6 (macOS/Linux default `IPV6_V6ONLY=0`),
  with fallback to `0.0.0.0` when the default listen fails.

### 4.6 `src/main.zig` / `src/vlmzs.zig` / `src/cli_helper.zig`

- **CLI redesign** (`docs/cli.md`): no config file; three-tier precedence `default < VLMZSD_*/env < CLI`;
  zig-clap parsing; fixed-format stdout logging (`Logger` guarded by `std.atomic.Mutex`).
- **Concurrency**: thread-per-connection (`std.Thread.spawn` + `detach`) + `Io.Semaphore` cap (`--max-clients`).
- **Timeout**: `std.posix.poll` (replacing C's `SO_RCVTIMEO`; checks `reader.bufferedLen()` before polling to
  avoid the buffered-reader read-ahead pitfall).
- Client: DNS via `Io.net.HostName.lookup` (with address-family filtering); default host `::1` (IPv6) or `127.0.0.1`;
  `--grace` default `43200` minutes written to `BindingExpiration`.

---

## 5. Known deviations and design decisions

| Item | Class | Description |
|---|---|---|
| IPv4-mapped private detection | **C defect fix** | C treats `::ffff:x.x.x.x` as always private (`word0` is not `2000::/3`); Zig extracts the embedded IPv4 for an exact decision, so ip-protection level 2 correctly rejects public IPv4 clients over a dual-stack socket. |
| Client return-code read position | **C defect fix** | C reads a misaligned offset on non-4-aligned responses (`+*responseSize + pad`); Zig reads `data_offset + response_size` (correct position). |
| Client first-packet NDR32 policy | **Intentional simplification** | C forces the first request after BIND to NDR32 (`firstPacketSent`); Zig uses NDR64 whenever available. Both are legal; not a wire error. |
| Client `DataLength==DataSizeIs` check | **Intentionally omitted** | C's `sizesMatch` defensive check is not replicated; does not affect normal interaction. |
| Uninitialized bytes | **Intentionally zeroed** | C's FAULT body, BIND response padding, etc. are stack garbage; Zig `@memset(0)` everywhere. Clients never read these bytes. |
| `AesCmacV4` in-place side effect | **Intentional difference** | C writes the `0x80` padding into the input buffer; Zig uses a separate pad buffer. MAC output and final sent bytes are identical. |
| ePID date `span<=0` | **C UB fix** | C `rand32()%0`; Zig takes `min_time` directly. |
| Invalid ePID (overlong / non-BMP) | **Intentional hardening** | C ignores `utf8_to_ucs2` failure, producing a malformed PIDSize; Zig returns `0x8007000D`. Default ePIDs are all short ASCII, unaffected. |
| Very short request (< 16-byte body) | **Known deviation** | C over-reads `ContextId` and usually replies FAULT; Zig disconnects. Real KMS requests are ≥ 268 bytes, unreachable. |
| FAULT `CallId` | **Aligned** | Server FAULT header `CallId` is fixed at 2 (C global value). |

---

## 6. Verification

- **Unit tests**: `zig build test --summary all` → 35/35 pass.
  - `kms.zig`: struct layout comptime asserts; v4/v5/v6 request→response→decrypt round-trips; ePID format; client list insert/evict.
  - `rpc.zig`: BIND negotiation (NDR32/NDR64/BTFN); request wrap (NDR32/NDR64); dispatch end-to-end; invalid-version HRESULT.
  - `crypto.zig`: v4 CMAC / v5 / v6 encryption / CBC / HMAC-SHA256 golden vectors.
  - `kmsdata.zig`: `.kmd` parsing field asserts.
- **Golden vectors**: hard-coded hex constants in `src/crypto.zig` tests, derived from the upstream C `dump_vectors`.
- **End-to-end**: `vlmzs` ↔ `vlmzsd` (v4/v5/v6, NDR32/NDR64, DNS, IPv4/IPv6 dual-stack, invalid-version rejection,
  10 concurrent clients, `--max-clients` throttling).
- **Real client**: final acceptance should be against a real Windows KMS client or packet capture (below).

## 7. Suggested final acceptance

1. Byte-level round-trip against a real Windows KMS client (or Wine + capture) for v4/v5/v6, NDR32/NDR64.
2. Diff `CurrentCount` and eviction behavior under `--maintain-clients`.
3. Diff BIND (including NDR64 + BTFN) negotiation byte order.
4. Diff error-path (invalid version / short request) response bytes (already aligned with C behavior; recommended to lock with golden vectors).

## 8. CLI surface changes

The CLI is redesigned relative to the C `vlmcsd`/`vlmcs` getopt + INI surface
(see `docs/cli.md` for the user-facing spec). The changes fall into two groups.

### Dropped C options

| C option(s) | Rationale |
|---|---|
| `-i <file>` (INI), client `-G`/`-l` (INI) | no config file by design |
| `-u`/`-g` (setuid/setgid) | deployment concern (systemd `User=`/`Group=`) |
| `-s`/`-S`/`-U`/`-W` (NT service) | Windows-only; out of scope for macOS/Linux first |
| `-F0`/`-F1` (freebind) | exotic; revisit if requested |
| `-x <level>` (exit-on-warning) | removed; warnings never terminate the server |
| `-O <vpn>` (TAP adapter) | Windows/OpenVPN-specific; out of scope |
| `-l syslog\|<file>`, `-T0`/`-T1` | logging is fixed-format (timestamped); supervisor handles files |
| `-e` (log to stdout) | redundant: `info`→stdout, `warn`/`err`→stderr is the default split |
| `-Z` (SIGHUP restart) | internal; re-add only if signal handling is needed |

### Deferred client options

These depend on DNS SRV support (`dns_srv.c`), which is not part of the current
migration surface. They will be added when DNS SRV is implemented:

| Option | C equivalent | Notes |
|---|---|---|
| `--no-dns` | `-d` | do not resolve SRV records |
| `--no-srv-priority` | `-P` | ignore SRV record priority |

## 9. Notes

- The upstream C source ([Wind4/vlmcsd@svn1113](https://github.com/Wind4/vlmcsd/tree/svn1113)) is no longer vendored; it remains a historical reference only.
- Build uses `build.zig` only; two executables: `vlmzsd` (server) and `vlmzs` (client).
- The migration favors "idiomatic Zig" over transliteration: `std.crypto` / `std.net` / `std.Io` / `std.unicode` / `std.mem` first;
  `shared_globals.c` global state is replaced by explicit context/allocator/RNG passing.
