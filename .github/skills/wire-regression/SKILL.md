---
name: wire-regression
description: 'Generate or update byte-level regression tests for the vlmzsd KMS emulator, pinning the wire contract to the values documented in docs/migration.md. Use when changing src/kms.zig, src/rpc.zig, src/crypto.zig, or src/kmsdata.zig, adding a protocol feature, or fixing a wire-format bug, to lock KMS v4/v5/v6 struct layouts, DCE/RPC framing (BIND/NDR32/NDR64/FAULT), AES/CMAC/HMAC vectors, and .kmd parsing to their documented bytes. Keywords: wire regression test, byte-level test, golden vector, KMS protocol, DCE/RPC, struct layout, endianness, packed struct, NDR32, NDR64, CMAC, HMAC, .kmd parsing.'
argument-hint: '<module: kms|rpc|crypto|kmsdata|all>'
---

# Wire Regression Testing

Generate byte-level regression tests that pin the vlmzsd wire contract to the values extracted in
`docs/migration.md`. This is the replacement for the old C-diff audit: instead of comparing against
the (now deleted) C reference, tests assert against the documented byte layouts and constants.

## When to Use

- You changed `src/kms.zig`, `src/rpc.zig`, `src/crypto.zig`, or `src/kmsdata.zig`.
- You added a protocol feature, changed a struct/constant, or fixed a wire-format bug.
- You want to guard against endianness, padding/alignment, or algorithm-parameter regressions.

## The Wire Contract (source of truth: `docs/migration.md`)

| Contract | Section | Assert |
|---|---|---|
| KMS struct sizes & field offsets | §3.1 | `@sizeOf` / `@offsetOf` comptime asserts |
| `sizeof`-derived constants | §3.1 | `v4_pre_epid_size` … `response_result_ok` |
| Crypto keys & algorithm constants | §3.2 | `aes_key_v4/v5/v6`, `TIME_C1/2/3`, v6 key-schedule XOR |
| DCE/RPC constants & GUID bytes | §3.3 | RPC header, NDR offsets, GUIDs, FAULT/HRESULT |
| `.kmd` binary format | §3.4 | header fields, record layouts, default-data counts |

Treat the tables in `docs/migration.md` as authoritative — never assert against "whatever the code
happens to produce today"; assert against the documented value, and update the doc if the contract
itself is being changed.

## Procedure

1. **Read the contract.** Open `docs/migration.md`, find the section for the module you changed
   (§3.1–§3.4), and note the exact byte values / offsets / constants involved.

2. **Locate existing coverage.** The wire surface is already partly covered; extend, don't duplicate:
   - `src/kms.zig` — struct-layout `comptime` asserts + v4/v5/v6 request→response→verify round-trips.
   - `src/rpc.zig` — BIND negotiation (NDR32/NDR64/BTFN), request wrap/dispatch, error-path HRESULT.
   - `src/crypto.zig` — golden hex vectors (hard-coded) for v4 CMAC / v5 / v6 / CBC / HMAC-SHA256.
   - `src/kmsdata.zig` — `.kmd` parsing field asserts.
   - `src/testutil.zig` — `expectBytes` (hex-diff on mismatch) and `hexDump` helpers.

3. **Write or update the test** using the pattern that matches the change (below). Each assertion
   must cite its provenance — a `// from docs/migration.md §3.x` comment — so the value stays
   traceable.

4. **Run.** `zig build test --summary all`; all tests must pass. Add or adjust a golden value only
   together with its provenance comment.

## Test Patterns

### Struct layout — compile-time, zero runtime cost

```zig
comptime {
    std.debug.assert(@sizeOf(Request) == 236);
    std.debug.assert(@offsetOf(Request, "cmid") == 64);
}
```

### Golden vector — hex compare

```zig
test "v4 CMAC golden vector" {
    const alloc = std.testing.allocator;
    var msg = [_]u8{0} ** 32;
    var mac: [16]u8 = undefined;
    aesCmacV4(&msg, &mac);
    const hex = try testutil.hexDump(alloc, &mac);
    defer alloc.free(hex);
    try testutil.expectBytes(hex, "1c3cb37a2a7283b1f2158220eb321c46"); // from docs/migration.md §3.2
}
```

### Round-trip — request → response → verify

```zig
var request: kms.RequestV6 = undefined;
kms.createRequestV6(&request, &base, rng);
const len = kms.createResponseV6(&request, &out, &cfg, rng, now);
// assert the returned byte length, then decrypt/verify against the request
```

### Field-by-field wire bytes — explicit endianness

Use `std.mem.readInt/writeInt(..., .little)` and compare the serialized buffer against expected
bytes; never `@ptrCast` bytes to a struct that may contain padding.

## Checklist

- [ ] Every changed struct/constant has a byte-level assert against `docs/migration.md`.
- [ ] New golden vectors carry a provenance comment (`// from docs/migration.md §3.x`).
- [ ] Endianness is explicit; no `@ptrCast` to padded structs.
- [ ] `zig fmt` and `zig build test --summary all` pass.
