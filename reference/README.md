# Reference

This directory holds the **read-only C reference** for the vlmzsd Zig migration.
Nothing here is part of the Zig build; it exists only as the authoritative source
for wire-format and algorithm behavior.

## `vlmcsd-src/`

The original [vlmcsd](https://github.com/Wind4/vlmcsd) C sources (moved here
from `src/`). They are never built or modified by the Zig project — see
`.github/instructions/c-reference-readonly.instructions.md`.

## `dump_vectors.c` + `Makefile`

A one-time bootstrap tool that compiles the C reference crypto implementation
(`vlmcsd-src/crypto.c`, `crypto_internal.c`, `endian.c`) and prints byte-exact
outputs of the vlmcsd crypto functions. Those outputs are committed as golden
fixtures under `testdata/crypto/`.

Build and run, from this directory:

    make
    ./dump_vectors

or from the repository root:

    make -C reference
    ./reference/dump_vectors

This is the only place `make` is used, and only as a bootstrap for generating
reference vectors — the Zig project itself builds exclusively with `zig build`.
