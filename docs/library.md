# Using vlmzsd as a library

The core protocol layer of `vlmzsd` is exposed as a Zig library module named
`vlmzsd`. It is pure logic — no `std.Io`, no libc — so it can be embedded in
any Zig project (including freestanding targets).

The `network` and `cli_helper` modules are internal to the `vlmzsd`/`vlmzs`
binaries and are **not** part of the public API.

> **Stability**: the public API is 0.x and may change between minor releases.

## Public modules

| Module | Contents |
|---|---|
| `crypto` | From-scratch AES (v4 160-bit key, v6 key-schedule XOR), CMAC, HMAC-SHA256 |
| `kmsdata` | `.kmd` binary data parsing and serialization ([`docs/kmd-format.md`](./kmd-format.md)) |
| `kms` | KMS v4/v5/v6 protocol: request/response structs, ePID generation, response build & decrypt |
| `rpc` | Hand-written DCE/RPC: BIND, NDR32/NDR64, FAULT framing |

## Adding the dependency

Add it with `zig fetch --save` — Zig resolves the URL and fills in the `url`
and `hash` for you:

```sh
zig fetch --save git+https://github.com/mogeko/vlmzsd.git#v0.2.4
```

## Wiring it into `build.zig`

```zig
const vlmzsd_dep = b.dependency("vlmzsd", .{
    .target = target,
    .optimize = optimize,
});
exe.root_module.addImport("vlmzsd", vlmzsd_dep.module("vlmzsd"));
```

## Example

```zig
const std = @import("std");
const vlmzsd = @import("vlmzsd");

pub fn main() !void {
    var dbg = std.heap.DebugAllocator(.{}).init;
    defer _ = dbg.deinit();
    const allocator = dbg.allocator();

    // Parse a .kmd data file. Copy `src/vlmcsd.kmd` from this repo, or supply
    // your own (see docs/kmd-format.md).
    const raw = @embedFile("vlmcsd.kmd");
    var data = try vlmzsd.kmsdata.parse(allocator, raw);
    defer data.deinit(allocator);

    std.debug.print("{d} CSVLC records, {d} apps\n", .{ data.csvlk.len, data.app_count });
}
```

## Getting started

Each module below gets one sentence of purpose plus its entry points. Full
signatures and semantics live in the source doc comments — read them with your
editor's autocomplete rather than expecting this page to enumerate the API.

- `crypto` — the KMS crypto primitives (AES / CMAC / HMAC-SHA256). Start from
  `aesCmacV4` (v4 CMAC) or `aesCbcEncrypt` (v5/v6 CBC).
- `kmsdata` — parse and serialize `.kmd` binary data. Start from `parse` and
  `write`.
- `kms` — the KMS v4/v5/v6 protocol itself. Start from `createResponseV6`
  (server side) or `decryptResponseV6` (client side).
- `rpc` — hand-written DCE/RPC framing. Start from `dispatchKmsRequest`
  (server side) or `wrapKmsRequest` (client side).

## Contract and pitfalls

Rules you must know before calling into the library — they are not visible
from type signatures alone:

- **Ownership.** `kmsdata.parse` allocates every slice inside the returned
  `KmsData` with the allocator you pass in. Call `data.deinit(allocator)`
  exactly once, or you leak / double-free.
- **Wire compatibility is the invariant.** Every KMS struct is packed
  little-endian and byte-for-byte compatible with the C `vlmcsd`. Never reorder
  fields, add padding, or "improve" a field's type — clients are real Windows
  machines.
- **No global state.** Anything needing memory or randomness takes an
  allocator / RNG parameter explicitly.
- **Freestanding-friendly.** The four public modules use neither `std.Io` nor
  libc, so they link into freestanding targets too.

Byte-level behavior is pinned by the wire-regression tests; see
[`docs/migration.md`](./migration.md) for the canonical layouts extracted from
the C reference.
