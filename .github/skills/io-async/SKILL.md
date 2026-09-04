---
name: io-async
description: 'Modernize the vlmzsd concurrency model using the stable std.Io.Threaded backend (thread pool + Future/Group/Semaphore), replacing hand-rolled std.Thread.spawn thread-per-connection. Use when improving server/client concurrency, capping parallel work, replacing manual thread management, or tuning async_limit/concurrent_limit. Keywords: std.Io.Threaded, async, concurrent, Future, Group, Semaphore, thread pool, concurrency, cancelation, Io.Limit.'
argument-hint: '<scope: server|client|all>'
---

# Asynchronous I/O with std.Io.Threaded

**Goal: replace the hand-rolled thread-per-connection model (`std.Thread.spawn` + `detach`) with
the `std.Io.Threaded` task model — `Io.concurrent` for parallel work, `Io.async` for inline work,
and `Future`/`Group` for lifecycle.** Zig 0.16 also ships experimental fiber/evented backends
(`std.Io.fiber`, `std.Io.Dispatch` over `Kqueue`/`Uring`), but those are WIP and poorly documented —
**do not use them here**. `std.Io.Threaded` is the thread-pool backend the project already uses;
this skill is about using its task model correctly.

## When to Use

- Replacing the current thread-per-connection model (`std.Thread.spawn` + `detach` in `src/main.zig`).
- Capping parallel work with `async_limit` / `concurrent_limit` or `Io.Semaphore`.
- Adding any fire-and-forget or parallel-request work in `src/main.zig` / `src/vlmzs.zig`.

## Key APIs (all WIP in 0.16 — verify against the stdlib source, not older tutorials)

| Primitive | Signature | Purpose |
|---|---|---|
| Init | `std.Io.Threaded.init(gpa, .{ .async_limit = ?, .concurrent_limit = ?, .stack_size = ? })` | thread-pool backend; `async_limit` defaults to `cpu_count - 1`, `concurrent_limit` defaults to `.unlimited` |
| Task | `Io.async(io, fn, args) → Future(Result)` | may run inline or spawn a pool thread; portable |
| Task | `Io.concurrent(io, fn, args) → ConcurrentError!Future(Result)` | guarantees a pool thread; returns `error.ConcurrencyUnavailable` past `concurrent_limit` |
| Wait | `Future.await(io)` / `Future.cancel(io)` | both idempotent, not thread-safe |
| Batch | `Group.async` / `Group.concurrent` / `Group.await` / `Group.cancel` | unordered task set, awaited/canceled as a whole |
| Limit | `Io.Limit` = `.nothing` / `.unlimited` / `.limited(n)` | bound on pool size |
| Semaphore | `Io.Semaphore{ .permits = n }` + `wait(io)` / `waitUncancelable(io)` / `post(io)` | counting gate (already used for `--max-clients`) |

## Procedure

1. **Locate the thread boundary.** Find each `std.Thread.spawn(.{}, fn, .{args})` + `th.detach()`
   (currently `serveClientThread` in `src/main.zig`).

2. **Choose `async` vs `concurrent`.** Use `concurrent` when the task must progress in parallel
   while the main loop keeps accepting; prefer `async` when inline execution is acceptable and the
   task just must not block the caller. Both return a `Future` that must eventually be
   `await`ed or `cancel`ed — an ignored `Future` leaks its task.

3. **Shape the task as a closure.** Extract the worker body into a function returning
   `Cancelable!void` (or any `Result`), passing context by value. Never capture stack state beyond
   the closure args.

4. **Bound concurrency.** The core model is `Future`/`Group`; layer limits on top of it:
   - fixed cap on all I/O parallelism → `InitOptions.async_limit` / `concurrent_limit`;
   - per-connection cap (`--max-clients`) → keep the existing `Io.Semaphore` as a gate in front of
     the task submission, or bound a `Group` before `Group.await`.

5. **Collect results.** `await` each `Future` (or the `Group`) at shutdown so tasks join; otherwise
   the process exits with work still queued.

6. **Run.** `zig build test --summary all`; concurrency changes must keep the 35-test suite green
   and pass a multi-client smoke test (`vlmzs` against `vlmzsd`).

## Patterns

```zig
// Spawn a worker on the Threaded pool and block until it finishes.
const future = try Io.concurrent(io, serveClient, .{ctx});
defer _ = future.cancel(io); // cancel if the surrounding scope is abandoned
const result = future.await(io);

// Bounded batch: submit N tasks, wait for all. This is the target shape for the
// server accept loop replacing `serveClientThread`.
var group = Io.Group.init;
for (clients) |c| Io.Group.concurrent(&group, io, handleClient, .{c});
try group.await(io);
```

## Pitfalls

- **`Future`/`Group` resources are released when awaited/canceled.** A `Future` that is neither
  awaited nor canceled leaks; a `Group` with pending tasks that is never awaited leaks.
- **Cancelation points.** `Io` functions that can return `error.Canceled` (see `Future.cancel`
  docs) are cancelation points. Ignoring `error.Canceled` is usually a bug — propagate it or use
  `Io.recancel` / `CancelProtection` deliberately.
- **`concurrent` can fail.** `error.ConcurrencyUnavailable` means the `concurrent_limit` was hit;
  either raise the limit, use `async`, or handle the error.
- **No `std.time.sleep`/`std.posix.nanosleep` in 0.16.** Sleep via `Io.sleep(io, .{ .nanoseconds = n }, .real)`.
- **`Io.Mutex` vs `std.atomic.Mutex`.** `Io.Mutex` needs an `Io`; use `std.atomic.Mutex` for locks
  that must work without one.

## Checklist

- [ ] No new `std.Thread.spawn`; tasks go through `Io.async`/`Io.concurrent` or a `Group`.
- [ ] Every `Future`/`Group` is awaited or canceled on all paths.
- [ ] `error.Canceled` and `error.ConcurrencyUnavailable` are handled, not silently swallowed.
- [ ] Concurrency bounds are explicit (`async_limit`/`concurrent_limit`/`Semaphore`).
- [ ] `zig fmt` and `zig build test --summary all` pass; multi-client smoke test succeeds.
