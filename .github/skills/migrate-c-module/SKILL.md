---
name: migrate-c-module
description: 'Migrate one vlmcsd C component (kms, rpc, crypto, network, helpers, kmsdata, vlmcsd, vlmcs) to idiomatic Zig for the vlmzsd project. Use when porting a module from the read-only reference C code in src/ to modern Zig, reimplementing wire/binary-compatible behavior with the Zig standard library (std.crypto, std.net, std.mem, std.unicode) instead of transliterating C, and verifying byte-for-byte compatibility. Keywords: C to Zig migration, port module, KMS protocol, DCE/RPC, wire compatibility, packed structs, endianness.'
argument-hint: '<component: kms|rpc|crypto|network|helpers|kmsdata|vlmcsd|vlmcs>'
---

# Migrate C Module to Zig

Migrate a single vlmcsd C component into idiomatic Zig. The C sources in `src/` are a **read-only reference** for wire format and algorithm behavior — never edit or build them.

## When to Use

- Porting one component (KMS protocol, RPC transport, crypto, network, data loading, server/client CLI) from C to Zig.
- After a migration is drafted, verifying wire compatibility against the reference.
- Planning the migration order of remaining C components.

## Preconditions

- Read `AGENTS.md` first (build commands, architecture table, migration conventions).
- Zig `>= 0.16.0`; code uses `std.process.Init` / `std.Io`. Build only via `build.zig` — never `make`/`gmake` or `src/GNUmakefile`.

## Component Map

| Component | C reference | Zig standard-library mapping |
|-----------|-------------|------------------------------|
| KMS protocol | `src/kms.c` / `src/kms.h` | `std.mem.readInt`/`writeInt` (little), `extern struct` or field-by-field de/serialization |
| RPC transport | `src/rpc.c` / `src/rpc.h` | `std.net`, manual DCE/RPC framing |
| Crypto | `src/crypto*.c` | `std.crypto` (AES, SHA-256, HMAC-SHA256) |
| Network | `src/network.c` | `std.net` |
| Data loading | `src/kmsdata*.c`, `src/helpers.c` (`loadKmsData`) | `std.fs.File`, `std.mem.readInt`, explicit structs |
| Server/client | `src/vlmcsd.c`, `src/vlmcs.c`, `src/vlmcsdmulti.c` | redesigned CLI (subcommands), `std.process` arg parsing |

## Procedure

1. **Identify the boundary.** Confirm the component and its C reference files from the table above; note whether it is protocol-level (wire bytes must match) or internal (free to be idiomatic).

2. **Extract the contract.** Read the C reference and relevant man pages (`man/vlmcsd.8`, `man/vlmcs.1`, `man/vlmcsdmulti.1`, `man/vlmcsd.ini.5`). Record:
   - Packed struct layouts, field order, and endianness.
   - Algorithm parameters (e.g. v4 160-bit AES CMAC; v6 non-standard HMAC with timestamp tolerance in `CreateV6Hmac`).
   - Binary formats that must stay compatible (`etc/vlmcsd.kmd`).

3. **Map to the Zig standard library.** Replace C-style logic with `std.crypto`, `std.net`, `std.unicode`, `std.mem.readInt(..., .little)`. Do not transliterate `crypto_internal.c` or `endian.h`; reimplement *behavior* so output matches byte-for-byte.

4. **Implement in Zig.** Create new files under `src/` (do not modify the C files). Use `extern struct` or field-by-field de/serialization — never `@ptrCast` bytes to a Zig struct with padding. Replace `shared_globals.c` global state with explicit context/allocator passing.

5. **Add tests.** Write unit tests next to the code; include at least one wire-format round-trip or known-byte vector per struct/algorithm.

6. **Verify wire compatibility.** Compare against captured reference bytes or a real KMS client. Do **not** rely on building the C code to verify.

7. **Build and format.** Run `zig fmt`, then `zig build`, then `zig build test`. Fix all errors before moving to the next module.

## Decision Points

- **Protocol-level vs internal:** KMS structs, DCE/RPC framing, v4/v6 crypto, and `.kmd` parsing must be byte-identical. Everything else (CLI, logging, config) can be redesigned idiomatically.
- **v4 vs v6:** v4 uses 160-bit AES CMAC; v6 uses a non-standard HMAC with timestamp tolerance. Reimplement both with `std.crypto` primitives, matching wire output exactly — do not port `crypto_internal.c` literally.
- **Scope:** Target macOS/Linux (`rpc.c` + `network.c` path) first; skip the `USE_MSRPC` Windows path initially.

## Completion Checklist

- [ ] No C files modified or built.
- [ ] Structs use `extern struct` or explicit `std.mem.readInt`/`writeInt`; no `@ptrCast` to padded structs.
- [ ] Zig standard library used instead of C-style logic where applicable.
- [ ] Unit tests cover each struct/algorithm, with at least one byte-vector assertion.
- [ ] Wire compatibility verified against captured bytes or a real client.
- [ ] `zig fmt`, `zig build`, and `zig build test` all pass.

## References

- Project conventions and architecture: `AGENTS.md`
- Feature switches enabled by `FEATURES=full`: `src/config.h`
- Protocol semantics and legacy CLI behavior: `man/vlmcsd.8`, `man/vlmcs.1`, `man/vlmcsdmulti.1`, `man/vlmcsd.ini.5`
- Sample data: `etc/vlmcsd.kmd`; legacy sample config (reference only): `etc/vlmcsd.ini`
