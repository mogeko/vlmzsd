---
name: io-async
description: 'Concurrency model of vlmzsd: the stable std.Io.Threaded backend (thread pool + Future/Group/Semaphore) instead of hand-rolled std.Thread.spawn. Use when adding or changing server/client concurrency, capping parallel work, joining tasks at shutdown, or tuning async_limit/concurrent_limit/--max-clients. Keywords: std.Io.Threaded, async, concurrent, Future, Group, Semaphore, thread pool, concurrency, cancelation, Io.Limit.'
argument-hint: '<scope: server|client|all>'
---

# Asynchronous I/O with std.Io.Threaded

**The migration is already done.** `src/main.zig` and `src/vlmzs.zig` run on the `std.Io.Threaded`
task model: `Io.Group.concurrent` for per-connection / per-request work, `Group.await` / `Group.cancel`
for lifecycle, and an atomic in-flight gate (`InFlight`) checked before `accept` for the
`--max-clients` cap. There is **no `std.Thread.spawn` + `detach` in `src/`** — do
not reintroduce it. Zig 0.16 also ships experimental fiber/evented backends (`std.Io.fiber`,
`std.Io.Dispatch` over `Kqueue`/`Uring`), but those are WIP and poorly documented — **do not use them
here**. This skill is about using the `Threaded` task model correctly and not regressing it.

## When to Use

- Adding or changing per-connection work in `src/main.zig` (the accept loop) or per-request work in
  `src/vlmzs.zig`.
- Capping parallel work with `async_limit` / `concurrent_limit`, or with an in-flight gate in the
  accept loop.
- Auditing why a task leaks, never runs, or does not stop at shutdown.

## Key APIs (all WIP in 0.16 — verify against the stdlib source, not older tutorials)

| Primitive | Signature | Purpose |
|---|---|---|
| Init | `std.Io.Threaded.init(gpa, .{ .async_limit = ?, .concurrent_limit = ?, .stack_size = ? })` | thread-pool backend; `async_limit` defaults to `cpu_count - 1`, `concurrent_limit` defaults to `.unlimited` |
| Task | `Io.async(io, fn, args) → Future(Result)` | may run inline or spawn a pool thread; portable |
| Task | `Io.concurrent(io, fn, args) → ConcurrentError!Future(Result)` | guarantees a pool thread; returns `error.ConcurrencyUnavailable` past `concurrent_limit` |
| Wait | `Future.await(io)` / `Future.cancel(io)` | both idempotent, not thread-safe |
| Batch | `Group.async` / `Group.concurrent` / `Group.await` / `Group.cancel` | unordered task set, awaited/canceled as a whole |
| Limit | `Io.Limit` = `.nothing` / `.unlimited` / `.limited(n)` | bound on pool size |
| Semaphore | `Io.Semaphore{ .permits = n }` + `wait(io)` / `waitUncancelable(io)` / `post(io)` | counting gate; **not** used for `--max-clients` (it has no non-blocking query, so the accept loop cannot ask "is there room?" before `accept`) |

## Procedure

1. **Locate the task boundary.** The dispatch sites are `ServerContext.run` →
   `self.group.concurrent(self.io, serveClientThread, .{ctx})` in `src/main.zig`, and
   `group.concurrent(init.io, sendRequestTask, .{...})` in `src/vlmzs.zig`.

2. **Choose the unit and its lifetime.** The server's unit is one **accepted connection**, not one
   request: `serveClientThread` loops over `network.serveRpc` until the peer closes, times out, or
   `--disconnect-per-request` fires. Do not dispatch per-RPC unless you also handle the connection's
   reader/writer state.

3. **Choose `async` vs `concurrent`.** Use `Group.concurrent` when the task must make progress while
   the caller keeps running (the accept loop); it guarantees a pool thread. `Group.async` may run
   inline and is not guaranteed to run until `await` — avoid it for connection work.

4. **Shape the task as a closure.** The task function's return type must coerce to `Cancelable!void`;
   pass context by value (the closure is copied into the pool's allocation). Never capture stack
   state beyond the args. Own heap context explicitly: `gpa.create` before dispatch, `destroy` in the
   task's `defer` (see `serveClientThread`).

5. **Bound concurrency.** `concurrent_limit` defaults to `.unlimited`, and `async_limit` does *not*
   apply to `Group.concurrent`, so by default every concurrent connection grows the pool — and an
   idle worker is never reclaimed (it lives until `deinit`). Bound the work in *our* code:
   - per-connection cap (`--max-clients`) → the `InFlight` gate in `src/main.zig`, queried with
     `atCap()` *before* polling the listen sockets. While at the cap the listen sockets stay out of
     the poll set, so excess connections queue in the kernel backlog (TCP backpressure) instead of
     occupying a worker; the loop then polls only the shutdown pipe with a short timeout so a freed
     slot (and SIGINT) is still noticed.
   - a global cap → `InitOptions.concurrent_limit` (only settable when you construct the `Threaded`
     yourself, not via `std.process.Init`), or another atomic gate. Prefer the gate: an
     over-limit `Group.concurrent` *fails* with `error.ConcurrencyUnavailable`, it does not wait.

6. **Join at shutdown.** A long-lived `Group` is legal and does not leak, but it must be
   `await`ed or `cancel`ed before the process exits — `main.zig` does `defer group.cancel(init.io)`.
   For a finite batch (`vlmzs --reconnect-per-request`), submit then `group.await(init.io)`.

7. **Run.** `zig build test --summary all`; concurrency changes must keep the suite green and pass a
   multi-client smoke test (`vlmzs` against `vlmzsd`, e.g. `-n 32 --reconnect-per-request`).

## Patterns

```zig
// Long-lived group (src/main.zig): each accepted connection is one task on the pool.
var group: Io.Group = .init;
defer group.cancel(io); // request cancelation + block until in-flight tasks finish
for (clients) |c| group.concurrent(io, handleClient, .{c}) catch |e| handle(e);

// Finite batch (src/vlmzs.zig --reconnect-per-request): submit N, then join.
var group: Io.Group = .init;
for (requests) |r| group.concurrent(io, sendRequestTask, .{r}) catch |e| handle(e);
group.await(io) catch |e| handle(e);
```

## Pitfalls

- **Group lifetime.** Per-task resources are released as soon as that task returns, so a long-lived
  group that tasks are repeatedly added to is *not* a leak (stdlib `Group` docs). The one real leak
  is a group with pending tasks that is never awaited nor canceled. An ignored `Future` does leak.
- **`concurrent` can fail.** `error.ConcurrencyUnavailable` means `concurrent_limit` was hit (or the
  thread spawn failed) — release whatever you reserved and drop the work (see `main.zig`'s
  `Group.concurrent(...) catch`).
- **Cancelation is delivered by signaling the thread.** `Threaded.init` installs a `SIG.IO` handler
  precisely so a cancelation request can interrupt a blocked syscall; `Group.cancel` then blocks
  until every member returns. Tasks that are not at a cancelation point keep running to completion.
- **Repo gotcha: cancelation surfaces as `error.ReadFailed`.** `Io.net.Stream.Reader.readVec`
  catches *every* socket error — including `error.Canceled` — and rewrites it as
  `error.ReadFailed`, stashing the real error in `Stream.Reader.err`. A connection canceled at
  shutdown therefore looks like a read failure. If you log errors at the `*Io.Reader` level you
  cannot tell them apart; do not report "canceled at shutdown" as a `warn`. (A connection parked in
  the read wait is woken through `IdleTimeout.wake_fd` and unwinds as `error.Canceled` before ever
  reaching `readVec`, so `serveClientThread` handles it at `debug`; a `ReadFailed` warn now means a
  failure *inside* a read.)
- **`std.posix.poll` is not a cancelation point — poll the shutdown pipe instead.** It is interrupted
  by `SIG.IO` but retried, so a worker parked in `waitReadable` would only notice cancelation once its
  poll deadline expired (bounding shutdown latency by `--timeout`). The server therefore passes the
  read end of its shutdown pipe as `IdleTimeout.wake_fd`; the wait then ends with `error.Canceled` the
  moment the signal handler writes its byte — including for `--timeout 0` connections. Anything new
  that parks on a socket must be woken the same way, and the pipe must outlive the joins: that is why
  the pipe-close `defer` is declared *before* `conn_group.cancel`'s (defers run in reverse).
- **The accept loop must never block on a limit.** A `Semaphore.waitUncancelable` in front of the
  dispatch is not a cancelation point, so SIGINT would not be honored until a task posted a permit —
  and it accepts connections it cannot serve, hiding backpressure from the kernel. `InFlight`
  (`tryAcquire`/`release`/`atCap`) is the non-blocking alternative; `release()` must be the last step
  of the task's `defer`, with the gate pointer copied out before `destroy(ctx)`.
- **`Io.Mutex` vs `std.atomic.Mutex`.** `Io.Mutex` needs an `Io` and blocks on a futex — use it for
  locks held across I/O (the logger). Use `std.atomic.Mutex` for short, `io`-free critical sections
  (the KMS client lists) — it spins via `std.atomic.spinLoopHint`.
- **No `std.time.sleep`/`std.posix.nanosleep` in 0.16.** Sleep via `Io.sleep(io, .{ .nanoseconds = n }, .real)`.

## Checklist

- [ ] No `std.Thread.spawn`; parallel work goes through a `Group` (`Group.concurrent`).
- [ ] The group is awaited or canceled on every exit path; anything that parks on a socket is woken
      at shutdown (`IdleTimeout.wake_fd`), and that wake fd outlives the joins.
- [ ] `error.ConcurrencyUnavailable` handled; per-task heap context freed in the task's `defer`.
- [ ] Concurrency bounds are explicit (the `InFlight` gate for `--max-clients`, or `concurrent_limit`).
- [ ] Shared mutable state is locked (`Io.Mutex` / `std.atomic.Mutex`); per-connection PRNG and
      buffers stay task-local.
- [ ] `error.Canceled` is not misreported as a failure (see the `ReadFailed` pitfall).
- [ ] `zig fmt` and `zig build test --summary all` pass; multi-client smoke test succeeds.
