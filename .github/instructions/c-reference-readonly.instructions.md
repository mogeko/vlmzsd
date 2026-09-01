---
description: "Use when reading, editing, or referencing the original vlmcsd C sources under reference/vlmcsd-src/ (*.c, *.h). Declares these files read-only reference for wire format and algorithm behavior during the vlmzsd C-to-Zig migration. Keywords: C reference, read-only, vlmcsd C sources, kms.c, rpc.c, crypto.c, port C to Zig, wire compatibility."
applyTo: "reference/vlmcsd-src/**/*.c, reference/vlmcsd-src/**/*.h"
---

# C Reference Files (Read-Only)

The original C sources in `reference/vlmcsd-src/` are the **read-only reference** for the vlmzsd migration. They are never built and never modified by the Zig project.

## Rules

- NEVER edit, modify, or delete `reference/vlmcsd-src/*.c` / `*.h`.
- NEVER build or compile them as part of the Zig build — no `make`/`gmake`/`reference/vlmcsd-src/GNUmakefile`. (The `reference/Makefile` is a separate, one-time bootstrap for dumping reference vectors; see `reference/README.md`.)
- Use them ONLY as reference for:
  - Wire/binary formats: packed little-endian KMS structs, DCE/RPC framing.
  - Algorithm behavior: v4 160-bit AES CMAC, v6 non-standard HMAC with timestamp tolerance.
  - Binary data layout: `etc/vlmcsd.kmd` parsing (`loadKmsData`).
- When porting a component, create NEW Zig files under `src/`; do not transliterate or rewrite the C.

See `AGENTS.md` for architecture, build commands, and migration conventions.
