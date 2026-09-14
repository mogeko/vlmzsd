---
description: "Zig code style for vlmzsd, informed by TigerBeetle's Tiger Style. Use when writing, editing, or reviewing Zig in src/ — covers explicitness, naming, assertions, comments, formatting, and the wire-compatibility invariant."
applyTo: "src/**/*.zig"
---

# Zig Style (Tiger Style-informed)

Code style for `src/`, adapted from [Tiger Style](https://github.com/tigerbeetle/tigerbeetle/blob/main/docs/TIGER_STYLE.md) to fit vlmzsd. Safety and correctness first, then clarity.

## Explicitness

- Annotate types explicitly: `var group: Io.Group = .init;` over `var group = Io.Group.init;`.
- Exception: when the initializer returns an error union (e.g. `std.unicode.Utf8View.init`), keep the `Type.init(...)` call — the `.init` shorthand requires the init to return the type itself.
- Prefer explicitly-sized integer types (`u32`, `u64`) over `usize` unless a stdlib signature requires it.
- Pass options explicitly at call sites instead of relying on defaults.

## Naming

- `snake_case` for functions, variables, and files.
- No abbreviations beyond conventional ones (`gpa`, `cfg`, `log`, `io`, `ctx`); spell out everything else.
- Put units/qualifiers last, sorted by descending significance: `timeout_seconds`, not `seconds_timeout`.
- Prefer nouns over adjectives: `BIND negotiation`, not `negotiating`.

## Assertions

- Assert both the positive space (what you expect) and the negative space (what you reject).
- Pin struct sizes and constant relationships with comptime asserts (see `src/kmsdata.zig`).
- Split compound asserts: `assert(a); assert(b);` over `assert(a and b);`.

## Scope and function shape

- Aim for functions around 70 lines — a recommendation, not a hard limit. When a
  function grows beyond it, split into helpers: keep control flow (`if`/`switch`)
  in the parent and push `for`s down into leaf functions.
- Declare variables at the smallest possible scope, and minimize the number of
  variables in scope.
- Calculate or check variables close to where they are used; don't introduce them
  before they are needed.

## Comments

- Comments are sentences: space after `//`, capital first letter, full stop.
- Say why, not what. When a value pins a wire/format detail, cite provenance: `// from docs/migration.md §3.x`.
- Tests explain their goal and methodology at the top.

## Formatting

- Run `zig fmt` before committing.
- 4-space indent; hard 100-column line limit.
- Braces on `if`/`else` unless the whole statement fits on one line.

## Zero dependencies

- std-only. No third-party packages — AES, DCE/RPC, and the CLI parser are hand-written.

## Wire compatibility (core invariant)

- Every wire-visible byte is pinned by tests and `docs/migration.md`.
- Read/write fields one at a time with `std.mem.readInt/writeInt(..., .little)`; never `@ptrCast` bytes to a padded struct.
