---
name: logging
description: 'Design and review log statements in the vlmzsd codebase using community best practices and the project Logger contract (Level enum, UTC ISO-8601 timestamp, stdout/stderr split, min_level filtering). Use when adding, changing, or reviewing log calls, choosing a log level, deciding what context to include, or auditing log noise. Keywords: logging, log level, best practice, Logger, trace, debug, info, warn, err, timestamp, stdout, stderr, log message, structured logging.'
argument-hint: '<scope: main|vlmzs|network|kms|rpc|all>'
---

# Logging Design

Guide for writing effective, consistent log statements in vlmzsd. Combines the project's
Logger contract with widely-agreed logging best practices.

## The Logger Contract (source of truth: `src/cli_helper.zig`, `docs/cli.md`)

- **Levels** (most→least verbose): `trace` < `debug` < `info` < `warn` < `err`. `trace` is for
  detail that is only meaningful while chasing a specific problem; most diagnostics are `debug`.
- **Destination**: `trace`/`debug`/`info` → stdout; `warn`/`err` → stderr (Unix convention).
- **Format**: every line is prefixed with a UTC ISO-8601 timestamp (`YYYY-MM-DDTHH:MM:SSZ`); the
  format is fixed and has no CLI surface.
- **Filtering**: `min_level`, default `.info`. The level comes from the repeatable `-v`/`-q` flags
  (`-v` `.debug`, `-vv`+ `.trace`; `-q` `.warn`, `-qq`+ `.err`; any `-q` wins over `-v`), from
  `VLMZSD_LOG_LEVEL`, or — deprecated — from `VLMZSD_VERBOSE`/`VLMZSD_QUIET`.
- **Delivery**: asynchronous. A log call formats the line on the calling thread and hands it to a
  bounded, **lossy** FIFO (`src/line_queue.zig`); a dedicated writer task owns the blocking
  `write`/`flush`.

## Pipeline, ordering, and loss

`Logger` (producer) → `LineQueue` (bounded FIFO, 1024 × 256 B, preallocated at startup) → writer task
(single consumer, `log_group`) → stdout/stderr.

- **Filtered lines cost nothing**: the `min_level` check happens before formatting, locking, or
  enqueuing.
- **Ordering is *arrival* order, not event order.** Within one thread (one connection) lines keep
  program order. Across threads there is no total order: whoever wins the queue lock is written
  first, and the timestamp is taken by the producer at call time — so in a rare preemption window a
  line's timestamp may be smaller than its predecessor's. Never infer cross-thread causality from
  log order.
- **A log call returning does not mean the line is on disk.** It sits in the queue until the writer
  drains it. Only `log.shutdown(io)` — run after the connection tasks are joined and before
  `Group.cancel` cancels the writer — guarantees that everything accepted has been flushed.
- **Loss is explicit and counted.** Producers never block: when the queue is full the line is
  dropped. At shutdown the writer prints one
  `warning: logging: dropped N line(s), truncated M line(s)` line on stderr when either counter is
  non-zero. Lines longer than 255 bytes are truncated to a single greppable line.
- **`std.process.exit` skips `defer`s.** On a fatal startup path use `fatal(log, io, ...)` in
  `src/main.zig`, never a bare `log.err(...)` + `exit`, or the message dies in the queue.

## Choosing a Level

| Level | Use for | Example |
|---|---|---|
| `trace` | Verbose detail meaningful only while chasing a specific problem; off by default | per-packet field dumps |
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

The producer's cost is one `@memcpy` into a preallocated slot plus one uncontended `Io.Mutex` CAS —
no syscall, no allocation. The blocking `write`/`flush` belongs to the writer task, so a slow
consumer (a full pipe) can no longer stall a worker: it fills the queue, and then lines are dropped
(and counted) rather than blocking the data plane.

This does not make logging free — every emitted line still costs a format plus a copy, and the single
writer task serializes all output. Keep `info`/`warn`/`err` out of per-packet or per-client tight
loops; use `debug` (filtered out by default, and then truly zero cost).

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
- [ ] No code assumes a line is on disk when the call returns (the writer flushes asynchronously).
- [ ] New fatal-exit paths use `fatal(...)` (`main.zig`), so the queue is drained before `exit`.
- [ ] `zig fmt` + `zig build test --summary all` pass.

## Related

- Logger implementation: `src/cli_helper.zig`
- Logging spec (format, levels, CLI surface): `docs/cli.md` → "Logging"
- Concurrency context: `.github/skills/io-async/SKILL.md`
