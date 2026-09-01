---
description: "Use when reading, editing, or referencing the original vlmcsd C sources under src/ (*.c, *.h). Declares these files read-only reference for wire format and algorithm behavior during the vlmzsd C-to-Zig migration. Keywords: C reference, read-only, vlmcsd C sources, kms.c, rpc.c, crypto.c, port C to Zig, wire compatibility."
applyTo: "src/**/*.c, src/**/*.h"
---

# C Reference Files (Read-Only)

The original C sources in `src/` are the **read-only reference** for the vlmzsd migration. They are never built and never modified.

## Rules

- NEVER edit, modify, or delete `src/*.c` / `src/*.h`.
- NEVER build or compile them — no `make`/`gmake`/`src/GNUmakefile`.
- Use them ONLY as reference for:
  - Wire/binary formats: packed little-endian KMS structs, DCE/RPC framing.
  - Algorithm behavior: v4 160-bit AES CMAC, v6 non-standard HMAC with timestamp tolerance.
  - Binary data layout: `etc/vlmcsd.kmd` parsing (`loadKmsData`).
- When porting a component, create NEW Zig files under `src/`; do not transliterate or rewrite the C.

See `AGENTS.md` for architecture, build commands, and migration conventions.
