# AGENTS.md

Guidance for AI coding agents working in this repository.

## Project

`vlmzsd` is a modern-Zig reimplementation of the [vlmcsd](https://github.com/Wind4/vlmcsd) KMS (Key Management Service) emulator. The original C sources live in `reference/vlmcsd-src/` and are kept strictly as a **read-only reference** for wire-format and algorithm behavior; they are never built.

Goals:
- Idiomatic, modern Zig that leverages the Zig ecosystem (`std.crypto`, `std.net`, `std.unicode`, …) rather than transliterating C.
- A redesigned CLI (single binary, subcommands, modern argument parsing) — not a port of the C getopt/INI surface.
- Zig build system only — no `make`/`gmake`.

- **Toolchain**: Zig `>= 0.16.0` (see `build.zig.zon`). The Zig code uses the WIP `std.process.Init` / `std.Io` APIs — do not regress to the older `std.process.argsAlloc` style.
- **Package**: module `vlmzsd` (root `src/root.zig`), executable `src/main.zig`.

## Build / test

- `zig build` — build the `vlmzsd` executable into `zig-out/`
- `zig build run -- <args>` — build and run
- `zig build test` — run unit tests (module + executable)
- `build.zig` is the **only** build entrypoint. Never invoke `make`/`gmake` or `reference/vlmcsd-src/GNUmakefile`; the C sources are reference-only and are not compiled. (The `reference/Makefile` is a separate, one-time bootstrap for dumping reference vectors — see `reference/README.md`; it is not part of the Zig build.)

## Architecture

The original C component boundaries (under `reference/vlmcsd-src/`) define the reimplementation surface — reimplement these in Zig, do not transliterate:

| Layer | C source | Role |
|-------|----------|------|
| KMS protocol | `kms.c` / `kms.h` | REQUEST/RESPONSE v4/v5/v6 binary structs, ePID generation, product GUID tables |
| RPC transport | `rpc.c` | Hand-written DCE/RPC (BIND, NDR32/NDR64, fragmentation) |
| Windows RPC | `msrpc-*.c`, `KMSServer_*` | Native MS-RPC via rpcrt4 — **not** part of the Zig port |
| Network | `network.c` | Cross-platform sockets |
| Crypto | `crypto*.c` | AES/CMAC + SHA-256/HMAC-SHA256 (internal/OpenSSL/PolarSSL/Windows backends) |
| Data | `kmsdata*.c`, `helpers.c` (`loadKmsData`) | Embedded/external `.kmd` binary data |
| Server/CLI | `vlmcsd.c`, `vlmcs.c`, `vlmcsdmulti.c` | CLI, config, daemon, client |
| Library | `libkms.c` / `libkms.h` | Public C API for embedding |

The C build outputs (`bin/vlmcsd`, `bin/vlmcs`, `bin/vlmcsdmulti`, `lib/libkms.*`) are legacy artifacts — the Zig project does not reproduce that build layout.

## Migration conventions

- The C code in `reference/vlmcsd-src/` is the **reference**, not the target. Write idiomatic Zig; use the standard library before reaching for C-style logic:
  - Crypto: `std.crypto` for SHA-256 / HMAC-SHA256. AES is implemented from scratch in `src/crypto.zig` (FIPS-197) because the reference uses a 160-bit key (v4, Nk=5 → 11 rounds) and a non-standard post-XOR key schedule (v6: XOR 0x73/0x09/0xE4 into the first byte of round keys 4/6/8) that `std.crypto` cannot express. Note `AesCmacV4` is in-place — it writes the 0x80 padding into its input buffer.
  - Network: `std.net` instead of `network.c`.
  - Text/unicode: `std.unicode` instead of the UCS-2 converters in `helpers.c`.
  - Byte access: `std.mem.readInt(..., .little)` / `std.mem.writeInt` instead of the `endian.h` macros.
- Preserve wire/binary compatibility (inherent to interoperating with Windows KMS clients):
  - All KMS protocol structs are packed little-endian — use `extern struct` or field-by-field de/serialization with `std.mem.readInt(..., .little)`. Never `@ptrCast` bytes to a Zig struct with padding.
  - `reference/vlmcsd.kmd` binary format must stay compatible (reimplement `loadKmsData` parsing). Embed the default via `@embedFile` and also support loading an external file at runtime (parity with the C embedded/external modes).
  - v4 uses 160-bit AES CMAC; v6 uses a non-standard HMAC with timestamp tolerance (`CreateV6Hmac`). Reimplement their *behavior* with `std.crypto` primitives so output matches byte-for-byte — do not transliterate `crypto_internal.c`.
  - DCE/RPC wire format in `reference/vlmcsd-src/rpc.c` must match (BIND negotiation, fragmentation, opnums).
- Replace `shared_globals.c` global state with explicit context/allocator passing.
- **CLI redesign**: a single `vlmzsd` binary with subcommands (server/client) and standard argument parsing — do not port the C getopt/INI surface. Configuration format is a design decision to make in Zig; do not copy the INI parser.
- **Testing**: byte-level fixtures live in `testdata/`; compare with `src/testutil.zig` (`expectBytes`, hex diff). The `.kmd` header is `"KMD\0"` followed by a little-endian version DWORD (`MajorVer == 2`).
- Target macOS/Linux first (the `rpc.c` + `network.c` path); skip the `USE_MSRPC` Windows path initially.

## Key files

- Feature switches (what the C build's `FEATURES=full` enables): `reference/vlmcsd-src/config.h`
- Reference behavior (protocol semantics, legacy CLI options): `reference/vlmcsd-src/*.c` / `*.h`
- Sample data: `reference/vlmcsd.kmd`
- Zig entry points: `src/root.zig` (module), `src/main.zig` (executable/CLI), `build.zig`

## Pitfalls

- Test coverage is minimal (a `.kmd` fixture smoke test in `src/root.zig`). Add tests as you go; verify wire compatibility against captured reference bytes or a real KMS client — do not rely on building the C code.
- `std.Io` / `std.process.Init` are WIP in 0.16 — consult current stdlib source rather than older tutorials.
  - In 0.16 `std.fs.cwd` is gone; file I/O goes through an `Io` instance: `std.Io.Threaded.init(alloc, .{})` → `.io()`, then `std.Io.Dir.openFile` / `std.Io.Dir.readFileAlloc` (the latter takes `(dir, io, path, gpa, .unlimited)`).
  - `@embedFile` can only reference files inside the module's package path (`src/`); for fixtures under `etc/`/`testdata/` load them at runtime via `std.Io.Dir`.
- `minimum_zig_version` is `0.16.0`; keep `build.zig` APIs in line with that version.
- Do not add `make`/`gmake` targets or shell out to the C toolchain; keep everything in `build.zig`.
