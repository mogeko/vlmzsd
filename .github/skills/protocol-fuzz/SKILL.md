---
name: protocol-fuzz
description: 'Construct malformed KMS/RPC inputs and boundary cases to test the vlmzsd KMS emulator error paths, pinning behavior to the known deviations recorded in docs/migration.md §5. Use when adding error-path/negative tests, hardening input validation, or verifying a fix for a documented deviation — invalid KMS version (RESPONSE + HRESULT 0x8007000D, not FAULT), non-zero minor version, too-short request (< 16-byte body → disconnect), unknown RPC context (FAULT nca_unk_if, CallId=2), NDR64 rejection 28-byte body (DataSizeIs no-overrun), required_clients > 2000, client-time off by >4h (0xC004F06C), whitelist rejection (0xC004F042), client-list full (0xC004D104), overlong/non-BMP ePID (0x8007000D), ePID date span<=0, IPv4-mapped address private detection, AesCmacV4 in-place side effect. Keywords: fuzz, malformed input, boundary test, negative test, error path, invalid version, short request, FAULT, HRESULT, NDR64, IPv4-mapped, ePID, known deviation.'
argument-hint: '<target: version|short-request|context|ndr64|ip|epid|time|whitelist|all>'
---

# Protocol Fuzz & Boundary Testing

Construct malformed and boundary inputs to verify the vlmzsd error paths behave exactly as
`docs/migration.md` §5 documents — the **negative-path counterpart** to `wire-regression`
(which pins the *valid* wire contract). Whereas wire-regression asserts correct bytes, this skill
asserts correct *rejections*: which HRESULT, FAULT, or disconnect a malformed input produces.

## When to Use

- You changed error-handling in `src/rpc.zig`, `src/kms.zig`, `src/crypto.zig`, or `src/network.zig`.
- You added input validation or a protocol feature with new rejection branches.
- You want to lock a §5 deviation (e.g. "too-short request disconnects") against regression.
- A bug report shows an unexpected crash/panic on a malformed request.

## The Deviation Contract (source of truth: `docs/migration.md` §5)

Treat §5 as authoritative. Every boundary test must assert the documented outcome, not "whatever
the code happens to do". If the documented outcome itself is wrong, fix §5 first.

| # | Deviation path | Triggering input | Expected outcome |
|---|---|---|---|
| 1 | Invalid major version | `version >> 16` outside 4..6 | RESPONSE + `0x8007000D` — **not** FAULT, **not** disconnect |
| 2 | Non-zero minor version | `version & 0xffff != 0` | RESPONSE + `0x8007000D` |
| 3 | Too-short request | `request_body.len < 16` (`request32_fixed_size`) | `error.InvalidRequest` → caller disconnects (C replied FAULT; Zig deviates) |
| 4 | Unknown context | `context_id` ∉ {`ndr_ctx`, `ndr64_ctx`} | FAULT `nca_unk_if` (`0x1c010003`); FAULT header `CallId` = 2 |
| 5 | NDR64 rejection layout | NDR64 context + invalid version | body = 28 bytes; `DataLength=0`@8, `DataSizeMax=0`@16, HRESULT@24; `DataSizeIs` **not** written (no overrun) |
| 6 | `required_clients > 2000` | `n_policy > 1000` | `0x8007000D` (`hresult.invalid_arg`) |
| 7 | Client time off by > 4 h | `client_time` vs `now` > 4 h | `0xC004F06C` (`hresult.client_time_mismatch`) |
| 8 | Whitelist rejection | whitelist level 1/2 + unauthorized product | `0xC004F042` (`hresult.product_rejected`) |
| 9 | Client list full | `--maintain-clients` + list at cap | `0xC004D104` (`hresult.too_many_clients`) |
| 10 | Overlong / non-BMP ePID | ePID > 32 UCS-2 chars (or non-BMP) | `0x8007000D` (Zig hardening; C emitted a malformed PIDSize) |
| 11 | ePID date `span <= 0` | `ReleaseDate >= now` | take `min_time` directly — never `%0` (C UB fix) |
| 12 | IPv4-mapped peer | `::ffff:8.8.8.8` vs `::ffff:10.0.0.1` | extract embedded IPv4: public → not private, private → private (C defect fix) |
| 13 | `AesCmacV4` side effect | verify input buffer after MAC | input unchanged, MAC identical (C wrote `0x80` into the input) |

## Boundary Inputs — how to construct each case

All construction is **field-by-field** (`std.mem.writeInt(..., .little)`); never `@ptrCast` bytes to
a padded struct.

### 1–2. Invalid / non-zero-minor version

Build a normal v6 request, then corrupt the version word before dispatch:

```zig
var base = makeBase(&td.data);            // 6<<16
base.version = (7 << 16) | 1;            // invalid major AND non-zero minor
var request: kms.RequestV6 = undefined;
kms.createRequestV6(&request, &base, rng);
const rpc_request = try rpc.wrapKmsRequest(alloc, std.mem.asBytes(&request), true, 2);
const dispatch = try rpc.dispatchKmsRequest(alloc, rpc_request[rpc.header_size..], &negotiation, &cfg, rng, now);
// expect: dispatch.kind == .response, dispatch.response_size == @bitCast(@as(u32, 0x8007000D)), dispatch.major_version == 0
```

### 3. Too-short request

Call `dispatchKmsRequest` with a body shorter than 16 bytes:

```zig
try std.testing.expectError(error.InvalidRequest,
    rpc.dispatchKmsRequest(alloc, &[_]u8{0} ** 8, &negotiation, &cfg, rng, now));
```

### 4. Unknown context

Send a request whose `context_id` (bytes 4..6 of the body) matches neither negotiated id:

```zig
var body: [16]u8 = [_]u8{0} ** 16;
std.mem.writeInt(u16, body[4..6], 0xEEEE, .little); // neither ndr_ctx nor ndr64_ctx
const dispatch = try rpc.dispatchKmsRequest(alloc, &body, &negotiation, &cfg, rng, now);
// expect: dispatch.kind == .fault == rpc.nca_unk_if
```

The FAULT *header* `CallId=2` lives in `network.serveRpc` (not `rpc.zig`); assert it at the
`serveRpc` boundary or note it as a §5 invariant.

### 5. NDR64 rejection layout

Same as #1 but assert the raw body bytes (regression: `DataSizeIs` used to be written past the
28-byte body):

```zig
// body.len == 28
try std.testing.expectEqual(@as(u64, 0), readLe(u64, body, 8));   // DataLength
try std.testing.expectEqual(@as(u64, 0), readLe(u64, body, 16));  // DataSizeMax
try std.testing.expectEqual(@as(u32, 0x8007000D), readLe(u32, body, 24)); // HRESULT
```

### 6–9. `createResponseBase` rejection order

`kms.createResponseBase(cfg, &base, &resp, rng, now_unix)` returns the HRESULT directly — the
cheapest way to exercise each rejection branch:

```zig
var cfg = kms.ServerConfig{ .data = &td.data };
// 6: n_policy = 1001 → required_clients = 2002 > 2000
// 7: base.client_time = u64ToFileTime(unixTimeToFileTime(now + 5 * 3600))
// 8: cfg.whitelisting_level = 1;  base.app_id = unknown guid
// 9: cfg.maintain_clients = true; pre-fill the list to max_count
const hr = kms.createResponseBase(&cfg, &base, &resp, rng, now);
try std.testing.expectEqual(hresult.invalid_arg /* or ... */, hr);
```

Assert the **order** too: a request that trips both the >2000 and the client-time checks must
return `0x8007000D`, not `0xC004F06C` (§4.1 rejection order).

### 10. Overlong / non-BMP ePID

Build a `KmsData` variant **in memory** (no disk file): allocate the slices and set one CSVLC's
`epid` to > 32 UCS-2 chars (or a non-BMP code point). Then `createResponseV6` must return
`0x8007000D` (via `setEpid` failing), not a malformed `pid_size`.

### 11. ePID date `span <= 0`

In-memory `KmsData` variant with a CSVLC whose `release_date >= now_unix`; `generateRandomPid`
must return a valid ePID (date = `min_time`) without panic — the C `rand32() % 0` UB fix.

### 12. IPv4-mapped peer

`network.isPrivateIPAddress(addr: *const std.posix.sockaddr)` is pure — build a `sockaddr_in6`
with a `::ffff:` prefix and assert both directions:

```zig
var s6 = std.mem.zeroes(std.posix.sockaddr.in6);
s6.family = std.posix.AF.INET6;
@memcpy(&s6.addr, &mapped(8, 8, 8, 8));   // public
try std.testing.expect(!network.isPrivateIPAddress(@ptrCast(&s6)));
```

### 13. `AesCmacV4` side effect

Copy the input, call `crypto.aesCmacV4`, and assert the input bytes are unchanged while the MAC
matches the golden vector — pins §5's "separate pad buffer" deviation.

## Where Tests Live

Boundary tests are **dispersed next to the code they exercise** (same layout as `wire-regression`):

| Deviation paths | Test file | Entry point |
|---|---|---|
| 1, 2, 3, 4, 5 | `src/rpc.zig` | `dispatchKmsRequest` (path 1/2/5 partially covered — extend, don't duplicate) |
| 6, 7, 8, 9 | `src/kms.zig` | `createResponseBase` |
| 10, 11 | `src/kms.zig` | `createResponseV6` / `generateRandomPid` |
| 12 | `src/network.zig` | `isPrivateIPAddress` |
| 13 | `src/crypto.zig` | `aesCmacV4` |

## Test Patterns

- **Return-value assert** — preferred for pure functions (`createResponseBase` HRESULT,
  `isPrivateIPAddress` bool). One `expectEqual` per branch.
- **`DispatchResult` switch** — for `dispatchKmsRequest`, switch on `dispatch.kind` and assert the
  `.response`/`.fault` payload plus `major_version`/`response_size` metadata.
- **Raw byte assert** — for wire layouts of rejection bodies (`readLe` at documented offsets).
- **Round-trip corrupt-then-dispatch** — wrap a valid request, flip one byte, dispatch, assert the
  documented rejection (see `rpc.zig` "dispatch unsupported KMS version returns HRESULT").

## Procedure

1. **Read the deviation.** Open `docs/migration.md` §5 (and §4.1 rejection order), note the
   expected outcome for the path under test.
2. **Locate the pure entry point.** Prefer `rpc.dispatchKmsRequest`, `kms.createResponseBase`,
   `network.isPrivateIPAddress`, `crypto.aesCmacV4` — they need no socket.
3. **Construct the malformed input** field-by-field (little-endian `readInt`/`writeInt`), never
   `@ptrCast` to padded structs.
4. **Assert the documented outcome** — the exact HRESULT, FAULT code, `error.InvalidRequest`, or
   bool — with a `// from docs/migration.md §5` provenance comment.
5. **Run.** `zig build test --summary all`; all tests pass. If the code disagrees with §5, resolve
   which is authoritative before changing either.

## Checklist

- [ ] Each boundary test asserts the §5-documented outcome, with a `§5` provenance comment.
- [ ] Invalid version asserts RESPONSE + `0x8007000D` (not FAULT, not disconnect).
- [ ] Too-short request asserts `error.InvalidRequest` (Zig disconnects).
- [ ] NDR64 rejection body asserts 28 bytes and `DataSizeIs` not overrun.
- [ ] Rejection **order** is covered (>2000 beats client-time, per §4.1).
- [ ] IPv4-mapped case asserts both public and private embedded addresses.
- [ ] No `@ptrCast` to padded structs; endianness is explicit.
- [ ] `zig fmt` + `zig build test --summary all` pass.

## Related

- Wire contract & §5 deviations: `docs/migration.md`
- Positive-path byte pinning: `.github/skills/wire-regression/SKILL.md`
- Test helpers (`expectBytes`, `hexDump`): `src/testutil.zig`
