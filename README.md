# vlmzsd

[![Build & Test](https://github.com/mogeko/vlmzsd/actions/workflows/build+test.yml/badge.svg)](https://github.com/mogeko/vlmzsd/actions/workflows/build+test.yml)
[![Image Size](https://img.shields.io/docker/image-size/mogeko/vlmzsd?logo=docker)](https://github.com/users/mogeko/packages/container/package/vlmzsd)
[![License](https://img.shields.io/github/license/mogeko/vlmzsd)](./LICENSE)

A [KMS](https://en.wikipedia.org/wiki/Key_Management_Service) emulator written
in idiomatic Zig. It serves real Windows KMS clients over the v4/v5/v6 protocol
with a hand-written DCE/RPC stack, byte-for-byte compatible with the wire format
of the C [vlmcsd](https://github.com/Wind4/vlmcsd) (no longer maintained).

## Features

- KMS v4 / v5 / v6 with ePID generation and randomization
- Hand-written DCE/RPC: BIND, NDR32/NDR64, FAULT
- From-scratch AES (v4 160-bit key, v6 key-schedule XOR)
- `std.Io.Threaded` concurrency with a `--max-clients` cap
- No config file — CLI + `VLMZSD_*` environment variables

## Run with Docker

```sh
docker run --rm -p 1688:1688 ghcr.io/mogeko/vlmzsd:latest
```

The server runs in the foreground and logs to stdout.

## Build from source

Requires [Zig](https://ziglang.org/download) `>= 0.16.0`.

```sh
git clone https://github.com/mogeko/vlmzsd.git
cd vlmzsd
zig build
zig-out/bin/vlmzsd --verbose   # starts the server on :1688
```

Send a test activation from another shell:

```sh
zig-out/bin/vlmzs localhost:1688
# Sending activation request (KMS V6) -> <ePID> (<hwid>)
```

## Documentation

- [docs/cli.md](./docs/cli.md) — CLI reference (options, env vars, logging)
- [docs/migration.md](./docs/migration.md) — byte layouts and known deviations from the C reference

## License

The code in this project is released under the [GPL-3.0](./LICENSE).
