# AGENTS.md

Guidance for AI coding agents working in this repository.

## Project

`vlmzsd` is a KMS (Key Management Service) emulator written in idiomatic Zig. It serves real
Windows KMS clients by speaking the KMS protocol (v4/v5/v6) over hand-written DCE/RPC. The goal is
the best Zig KMS emulator — interoperable, idiomatic, and well-tested.

The upstream C project [vlmcsd](https://github.com/Wind4/vlmcsd/tree/svn1113) is a historical
reference only (the Zig code was originally migrated from it); it is no longer vendored in this
repo. See `docs/migration.md` for the protocol byte layouts and algorithm constants extracted from it.

- **Toolchain**: Zig `>= 0.17.0` (see `build.zig.zon`). The code uses the WIP `std.process.Init` /
  `std.Io` APIs — do not regress to the older `std.process.argsAlloc` style.
- **Package**: module `vlmzsd` (root `src/root.zig`), executables `src/main.zig` (`vlmzsd` server)
  and `src/vlmzs.zig` (`vlmzs` client).
- **Dependencies**: none — std-only.

## Build / test

- `zig build` — build both binaries into `zig-out/`
- `zig build run -- <args>` — build and run `vlmzsd`
- `zig build test` — run unit tests (the module, both executables, `kmdconv`, and the internal
  `network` / `cli_helper` / `line_queue` roots)
- `build.zig` is the only build entrypoint — never add `make`/`gmake` targets.

## Architecture

| Module | File | Role |
|---|---|---|
| KMS protocol | `src/kms.zig` | v4/v5/v6 REQUEST/RESPONSE structs, ePID generation, response build & decrypt |
| RPC transport | `src/rpc.zig` | Hand-written DCE/RPC: BIND, NDR32/NDR64, FAULT, framing |
| Crypto | `src/crypto.zig` | From-scratch AES (FIPS-197) + `std.crypto` SHA-256 / HMAC-SHA256 |
| Data | `src/kmsdata.zig` | `.kmd` binary data parsing (embedded `src/vlmcsd.kmd`); format spec in `docs/kmd-format.md` |
| Network | `src/network.zig` | `std.Io` sockets: server loop, client connect (DNS), private-IP detection |
| Server | `src/main.zig` | `vlmzsd` CLI + accept loop + `Io.Group` task dispatch onto the `std.Io.Threaded` pool |
| Client | `src/vlmzs.zig` | `vlmzs` activation client |
| Shared | `src/cli_helper.zig` | data-driven CLI parser (Opt table → parse/help/validate), value parsers (duration/bool/GUID), timestamped logger |
| Log queue | `src/line_queue.zig` | bounded, lossy MPSC FIFO for log lines (preallocated, internal) |
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
  runtime via `--data`. The `.kmd` layout is specified in `docs/kmd-format.md`.

## Conventions

- Idiomatic Zig first: `std.crypto`, `std.Io` / `std.net`, `std.unicode`, `std.mem` — not C-style logic.
- No global state: pass context / allocator / RNG explicitly.
- CLI: two binaries, no config file — `docs/cli.md` is the authoritative spec. Three-tier
  precedence `default < VLMZSD_*/env < CLI`.
- Logging: fixed format with a UTC timestamp; `debug`/`info` → stdout, `warn`/`err` → stderr.
  `--verbose` enables `debug`, `--quiet` drops `info` (see `docs/cli.md`). Lines are handed to a
  bounded, **lossy** queue (`src/line_queue.zig`) and written by a dedicated writer task; a full
  queue drops the line (counted, and reported on stderr as a per-period delta when the writer goes
  idle and as the run's total at shutdown) instead of blocking a worker. Shutdown order
  is `conn_group.cancel` → `log.shutdown` → `log_group.cancel` → `log.deinit`, so lines logged while
  connections stop are still flushed. A second `SIGINT`/`SIGTERM` skips that drain and `_exit`s with
  `128 + signum`, so a blocked log sink cannot wedge a stop (see `docs/cli.md`). On a fatal startup
  path use `fatal(...)` — `std.process.exit` skips the `defer`s that would drain the queue.
- Tests: byte-level round-trips and golden hex vectors (hard-coded in `src/crypto.zig`).
- Concurrency: one `std.Io.Group` for the process lifetime; each accepted connection is one
  `Group.concurrent` task on the `std.Io.Threaded` pool (threads are spawned on demand and reused,
  never `std.Thread.spawn`/`detach`). `--max-clients` is enforced by an atomic in-flight counter
  (`InFlight`) checked *before* `accept`: while at the cap the listen sockets leave the poll set, so
  excess connections queue in the kernel backlog. The pool itself never shrinks (a worker lives until
  `deinit`), so this gate is what keeps threads at `min(peak clients, cap) + 2`. `Group.cancel` joins
  in-flight tasks at shutdown, and connection reads are `Io` operations
  (`io.operateTimeout(.{ .net_receive = … })` in `network.readSome`), whose wait is a backend
  cancelation point — so SIGINT/SIGTERM ends a parked read with `error.Canceled` at once, with no
  self-pipe. Per-connection state (PRNG, 4 KiB read/write buffers) stays
  task-local; shared mutable state uses `Io.Mutex` (logger) or `std.atomic.Mutex` (client lists).

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

- `std.Io` / `std.process.Init` are WIP in 0.17 — consult current stdlib source, not older tutorials.
  - `std.fs.cwd` is gone; file I/O goes through an `Io` instance: `std.Io.Threaded.init(alloc, .{})` → `.io()`.
  - `@embedFile` only reaches files inside the module's package path (`src/`).
- `minimum_zig_version` is `0.17.0`; keep `build.zig` in line with that version.
- **`build.zig` must stay 0.17-shaped.** `b.args` is gone — `run_cmd.addPassthruArgs()` passes the
  `zig build run -- …` tail through. And because 0.17 now caches the configure phase (and can skip
  `build.zig` altogether), a build script that reads state the cache cannot see must declare it:
  `build.zig` embeds the git hash and the build date, so it calls `b.graph.poisonCache()`. Remove
  that call and `--version` silently reports the previous run's hash and date.
- **Container builds must use `-Dcpu=baseline`.** `zig build` defaults to the *native* CPU model;
  a CI ARM runner (e.g. Graviton) then emits SVE instructions that crash with SIGILL on CPUs
  without SVE (e.g. Apple Silicon). The `Dockerfile` pins `-Dcpu=baseline` for portability.
- **Module code must not reference `std.c`.** `build.zig` sets `link_libc = false` for the `vlmzsd`
  module; only the `vlmzsd` executable links libc (for `std.c.pipe`/`fcntl`/`getpid` in
  `src/main.zig`). A `std.c` reference in a module file — including inside a `test` block, which is
  compiled only for test artifacts, so `zig build vlmzsd …` still passes — fails to *compile* on
  Linux with `dependency on libc must be explicitly specified`. macOS hides it (libSystem is always
  linked). Reach for `std.posix` / `std.Io` / `Io.net` instead — a TCP connection whose both ends the
  test owns is a portable wake fd — and pre-check with
  `zig test -ODebug --dep vlmzsd -Mroot=src/network.zig -Mvlmzsd=src/root.zig -target x86_64-linux-gnu --test-no-exec`.
- The `zig-fmt` (PostToolUse) and `zig-build-test` (Stop) hooks auto-format and run tests; keep
  `.zig` files formatted and tests green.
- **Never write to the real stdout/stderr from a test.** `zig build test` runs each test binary with
  `--listen=-`, where stdout carries the runner's protocol: a stray write to fd 1 corrupts it and
  deadlocks the build. A standalone `zig test <file>` stays green (human mode), so it looks like a
  deadlock in the code under test. Inject a sink instead — see `Logger.direct_out`/`direct_err`.
