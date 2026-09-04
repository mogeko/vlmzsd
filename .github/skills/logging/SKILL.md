---
name: logging
description: 'Design and review log statements in the vlmzsd codebase using community best practices and the project Logger contract (Level enum, UTC ISO-8601 timestamp, stdout/stderr split, min_level filtering). Use when adding, changing, or reviewing log calls, choosing a log level, deciding what context to include, or auditing log noise. Keywords: logging, log level, best practice, Logger, debug, info, warn, err, timestamp, stdout, stderr, log message, structured logging.'
argument-hint: '<scope: main|vlmzs|network|kms|rpc|all>'
---

# Logging Design

Guide for writing effective, consistent log statements in vlmzsd. Combines the project's
Logger contract with widely-agreed logging best practices.

## The Logger Contract (source of truth: `src/cli_helper.zig`, `docs/cli.md`)

- **Levels** (most→least verbose): `debug` < `info` < `warn` < `err`. No `trace` — do not add one
  unless a concrete need appears.
- **Destination**: `debug`/`info` → stdout; `warn`/`err` → stderr (Unix convention).
- **Format**: every line is prefixed with a UTC ISO-8601 timestamp (`YYYY-MM-DDTHH:MM:SSZ`); the
  format is fixed and has no CLI surface.
- **Filtering**: `min_level`; `--verbose` → `.debug`, `--quiet` → `.warn`, default `.info`.
- The `Logger` writes via `Io.Mutex` (blocking), so a log call in a hot path is a real lock +
  flush cost — see "Cost".

## Choosing a Level

| Level | Use for | Example |
|---|---|---|
| `debug` | Diagnostic detail useful when troubleshooting; off by default | per-connection accept/reject, negotiation detail |
| `info` | Normal, notable runtime events | "listening on port", activation result |
| `warn` | Recoverable anomaly that does not stop the service | failed accept, malformed config entry, client error |
| `err` | A failure that prevents the intended action | failed listen, failed data load |

Rule of thumb: if an operator does not need it to run the service, it is `debug`, not `info`.

## What to Log

- **Actionable, specific messages.** State what happened and the decisive context, e.g.
  `failed to listen on {addr}:{port}: {error_name}` — never a bare "failed".
- **Include the error name** via `{@errorName(e)}`, not a hand-written summary.
- **Enough context to correlate.** For connection/request logs, include whatever identifies the
  peer or request (currently the protocol version / status; add client address when available).
- **One line, one event.** No multi-line messages — keep every line independently greppable.

## What NOT to Log

- **Secrets or sensitive material.** Never log keys, tokens, or credentials. KMS GUIDs/ePIDs are
  protocol data, not secrets, but treat any future credentials as off-limits.
- **Hot-path spam at `info`.** Per-connection or per-request chatter is `debug`, not `info`.
  A busy server must not flood stdout with routine events.
- **Redundant duplication.** Log once at the boundary (accept loop, dispatch, connect), not again
  at every layer for the same event.

## Cost

A log call takes the `Logger` mutex and flushes (`w.flush()`) — a blocking syscall. On the
thread-pool backend this blocks the worker thread. Keep `info`/`warn`/`err` out of per-packet or
per-client tight loops; use `debug` (filtered out by default) there.

## Procedure

1. **Identify the event** you want to record and its severity (is it normal, anomalous, or fatal?).
2. **Pick the level** using the table above.
3. **Write the message** as `verb + subject + key context`, ending with `{@errorName(e)}` when an
   error is involved.
4. **Check the destination** is correct (info/debug on stdout, warn/err on stderr) and the level is
   not filtered out by the default `min_level`.
5. **Run.** `zig build test --summary all`; visually confirm the new line's timestamp/level/stream.

## Checklist

- [ ] Level matches severity (not every event is `info`; hot paths use `debug`).
- [ ] Message is actionable and specific, with `{@errorName(e)}` on errors.
- [ ] No secrets or credentials in the message.
- [ ] Destination correct: debug/info → stdout, warn/err → stderr.
- [ ] Not a duplicate of a log at another layer for the same event.
- [ ] `zig fmt` + `zig build test --summary all` pass.

## Related

- Logger implementation: `src/cli_helper.zig`
- Logging spec (format, levels, CLI surface): `docs/cli.md` → "Logging"
- Concurrency context: `.github/skills/io-async/SKILL.md`
