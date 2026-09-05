# AGENTS.md

Guidance for AI coding agents working in this repository.

## Project

`vlmzsd` is a KMS (Key Management Service) emulator written in idiomatic Zig. It serves real
Windows KMS clients by speaking the KMS protocol (v4/v5/v6) over hand-written DCE/RPC. The goal is
the best Zig KMS emulator — interoperable, idiomatic, and well-tested.

The upstream C project [vlmcsd](https://github.com/Wind4/vlmcsd/tree/svn1113) is a historical
reference only (the Zig code was originally migrated from it); it is no longer vendored in this
repo. See `docs/migration.md` for the protocol byte layouts and algorithm constants extracted from it.

- **Toolchain**: Zig `>= 0.16.0` (see `build.zig.zon`). The code uses the WIP `std.process.Init` /
  `std.Io` APIs — do not regress to the older `std.process.argsAlloc` style.
- **Package**: module `vlmzsd` (root `src/root.zig`), executables `src/main.zig` (`vlmzsd` server)
  and `src/vlmzs.zig` (`vlmzs` client).
- **Dependencies**: none — std-only.

## Build / test

- `zig build` — build both binaries into `zig-out/`
- `zig build run -- <args>` — build and run `vlmzsd`
- `zig build test` — run unit tests (module + both executables)
- `build.zig` is the only build entrypoint — never add `make`/`gmake` targets.

## Architecture

| Module | File | Role |
|---|---|---|
| KMS protocol | `src/kms.zig` | v4/v5/v6 REQUEST/RESPONSE structs, ePID generation, response build & decrypt |
| RPC transport | `src/rpc.zig` | Hand-written DCE/RPC: BIND, NDR32/NDR64, FAULT, framing |
| Crypto | `src/crypto.zig` | From-scratch AES (FIPS-197) + `std.crypto` SHA-256 / HMAC-SHA256 |
| Data | `src/kmsdata.zig` | `.kmd` binary data parsing (embedded `src/vlmcsd.kmd`) |
| Network | `src/network.zig` | `std.Io` sockets: server loop, client connect (DNS), private-IP detection |
| Server | `src/main.zig` | `vlmzsd` CLI + accept loop + thread-per-connection |
| Client | `src/vlmzs.zig` | `vlmzs` activation client |
| Shared | `src/cli_helper.zig` | data-driven CLI parser (Opt table → parse/help/validate), value parsers (duration/bool/GUID), timestamped logger |
| Tests | `src/testutil.zig` | byte-compare / hex-diff helpers |

## Wire compatibility (core invariant)

KMS clients are real Windows machines; every byte on the wire must be exact. The canonical
reference for layout and algorithm behavior is `docs/migration.md` (extracted from the upstream C
source linked above).

- All KMS structs are packed little-endian — use `extern struct` or field-by-field
  `std.mem.readInt/writeInt(..., .little)`. Never `@ptrCast` bytes to a struct with padding.
- SHA-256 / HMAC-SHA256 come from `std.crypto`; AES is implemented from scratch in `src/crypto.zig`
  because v4 uses a 160-bit key (Nk=5 → 11 rounds) and v6 XORs 0x73/0x09/0xE4 into the first byte of
  round keys 4/6/8 — neither is expressible with `std.crypto`.
- DCE/RPC: single-fragment packets, BIND/ALTER-CONTEXT negotiation, NDR32/NDR64 wrapping, FAULT
  with `CallId=2`. Invalid requests return a RESPONSE with HRESULT `0x8007000D`, not a disconnect.
- The embedded default data is `src/vlmcsd.kmd` (`@embedFile`); external `.kmd` files load at
  runtime via `--data`.

## Conventions

- Idiomatic Zig first: `std.crypto`, `std.Io` / `std.net`, `std.unicode`, `std.mem` — not C-style logic.
- No global state: pass context / allocator / RNG explicitly.
- CLI: two binaries, no config file — `docs/cli.md` is the authoritative spec. Three-tier
  precedence `default < VLMZSD_*/env < CLI`.
- Logging: fixed format with a UTC timestamp; `debug`/`info` → stdout, `warn`/`err` → stderr.
  `--verbose` enables `debug`, `--quiet` drops `info` (see `docs/cli.md`).
- Tests: byte-level round-trips and golden hex vectors (hard-coded in `src/crypto.zig`).

## CLI implementation decisions

- **Argument parsing: data-driven, std-only.** Both binaries parse their CLI with `src/cli_helper.zig`
  — a hand-written parser where a single `Opt` table drives parsing, `--help` rendering, and
  validation (so the parse logic and help text cannot drift apart). The three-tier env-var
  precedence is implemented as a thin layer on top of the parsed result — independent of the
  parser choice.
- **Two entry points share one module.** `src/main.zig` (`vlmzsd`) and `src/vlmzs.zig` (`vlmzs`)
  both import the `vlmzsd` module; argument parsing and option-to-config mapping live in shared
  code (e.g. `src/cli_helper.zig`).
- **Logging: no external library.** Zig has no community-standard log library, and `std.log` does
  not match the "fixed format, timestamped, stdout/stderr split" requirement. The server uses a
  hand-written `cli_helper.Logger`; the client (`vlmzs`) is a CLI debugging tool and writes a bare
  `Output` (stdout/stderr, no timestamp) instead.

## Pitfalls

- `std.Io` / `std.process.Init` are WIP in 0.16 — consult current stdlib source, not older tutorials.
  - `std.fs.cwd` is gone; file I/O goes through an `Io` instance: `std.Io.Threaded.init(alloc, .{})` → `.io()`.
  - `@embedFile` only reaches files inside the module's package path (`src/`).
- `minimum_zig_version` is `0.16.0`; keep `build.zig` in line with that version.
- **Container builds must use `-Dcpu=baseline`.** `zig build` defaults to the *native* CPU model;
  a CI ARM runner (e.g. Graviton) then emits SVE instructions that crash with SIGILL on CPUs
  without SVE (e.g. Apple Silicon). The `Dockerfile` pins `-Dcpu=baseline` for portability.
- The `zig-fmt` (PostToolUse) and `zig-build-test` (Stop) hooks auto-format and run tests; keep
  `.zig` files formatted and tests green.
