---
name: io-async
description: 'How to write async and concurrent I/O in Zig 0.16 with std.Io: the task/Group/Future/Select/Operation model, what the Threaded backend can and cannot do, cooperative cancelation and shutdown, bounding parallel work, and the pitfalls that make tasks hang, leak, or outlive the process. Use when adding or changing server/client concurrency, spawning parallel work, waiting on sockets with deadlines, capping parallel work, or debugging a task that never stops, never starts, or ignores shutdown. Keywords: std.Io, std.Io.Threaded, async, concurrent, Future, Group, Select, Operation, net_receive, Timeout, cancelation, cancelation point, checkCancel, Semaphore, Mutex, thread pool, shutdown, wake fd, thread-per-connection.'
argument-hint: '<what you are changing: accept loop | client request | shutdown | limits>'
---

# Async I/O with `std.Io` (Zig 0.16)

## The model

`std.Io` is Zig's interface for everything that can block: sockets, files, the clock, sleeping. Code
does not call `read(2)`/`nanosleep` directly; it goes through an `Io` handle, and the **backend**
behind that handle decides how to block. In Zig 0.16 that handle arrives once at startup (from
`std.process.Init`) and is then passed around explicitly: one handle, one backend. The backend this
skill assumes is `std.Io.Threaded` — a **thread pool**.

The unit of work is a **task**: a function whose return type coerces to `Io.Cancelable!void`,
dispatched with `Io.async` / `Io.concurrent` and composed with `Future`, `Group`, `Select`. Tasks
wait on each other through `Io` primitives (mutex, semaphore, event, queue, timeout) instead of
through OS threads you manage yourself.

Two properties drive every decision below:

- **Concurrency is cheap to ask for and expensive to bound.** The pool grows on demand, and it never
  shrinks.
- **Cancelation is cooperative.** A task stops only where it checks — either at an `Io` call that
  checks for it, or at a check you placed yourself.

Signatures, semantics, and the evidence behind every claim below live in
[references/std-io-0.16.md](./references/std-io-0.16.md).

## When to Use

- Adding parallel work (per-connection, per-request, fan-out), or waiting on more than one thing.
- Bounding parallel work, or answering "how many threads will this use?".
- Anything about shutdown: tasks that keep running, reads that ignore SIGINT, processes that hang.
- Auditing sleep/retry/deadline code.

## What you can do

| You want to… | Use | Notes |
|---|---|---|
| Run a task in parallel, guaranteed a unit of concurrency | `Io.concurrent(io, f, args)`, `Group.concurrent` | Fails `error.ConcurrencyUnavailable` at the pool limit — it does *not* queue |
| Run a task that may execute inline before returning | `Io.async`, `Group.async` | May already be complete when it returns; no parallelism guarantee |
| Await one task / a whole batch | `Future.await(io)`, `Group.await(io)` | Block until finished |
| Stop a task / a batch | `Future.cancel(io)`, `Group.cancel(io)` | Request cancelation, then block until the task returns |
| Re-raise a cancelation already observed | `Io.recancel(io)` | For a cleanup path that caught `error.Canceled` and wants the next cancelation point to return it again |
| Wait for the **first** of several tasks | `Io.Select(U)`: `init`, `async`/`concurrent`, `await`, `awaitMany`, `cancel` | Built on `Queue(U)` + tasks; you supply the result buffer |
| Ask "was I canceled?" | `Io.checkCancel(io)` → `error.Canceled` | Meaningful only inside a task |
| Shield a critical region from cancelation | `Io.swapCancelProtection(io, .blocked/.unblocked)` | Restore the previous value when done |
| Bound how long a blocking call may take | `Io.Timeout` (`.none`/`.duration`/`.deadline`) with `operateTimeout`, or `Clock.Duration.sleep` | `Timeout` is the standard way to express a deadline |
| Issue a typed I/O operation with cancelation/timeout semantics | `Io.Operation` (`net_receive`, `file_read_streaming`, `file_write_streaming`, `device_io_control`) via `Io.operate` / `operateTimeout` | Portable across backends; on `Threaded` the op still blocks *this* thread |
| Sleep | `Io.sleep(io, .{ .nanoseconds = n }, clock)` | `Clock` = `.real`, `.awake`, `.boot`, `.cpu_process`, `.cpu_thread` (**no `.monotonic`**) |
| Deadline a wait you own | `Io.futexWaitTimeout`, `Io.Event`, `Io.Condition` | For synchronization you hand-roll |
| Synchronize | `Io.Mutex` (held across I/O), `std.atomic.Mutex` (short, io-free), `Io.RwLock`, `Io.Semaphore`, `Io.Event`, `Io.Queue(T)` | Prefer `Io` primitives inside tasks |
| Entropy / timestamps | `Io.random`, `Io.randomSecure`, `Clock.now(clock, io)` | `Io.Timestamp.durationTo` for elapsed time |

## What you cannot do

| Constraint | Why it matters |
|---|---|
| **No `std.Thread.spawn`, no `detach`.** | Those threads bypass cancelation, the shutdown join, and the pool's accounting. |
| **The pool cannot be sized through `std.process.Init`.** | `Threaded.InitOptions` (`async_limit`, `concurrent_limit`, `stack_size`) exist only if you construct the backend yourself. Limits must be your own invariant. |
| **A dispatch limit is not a queue.** | At the limit, `concurrent` *fails*; it never waits. Backpressure must come from your own gate. |
| **Pool threads are never reclaimed.** | Thread count ≈ *peak* concurrent tasks, for the life of the process. Concurrency you allow once, you allow forever. |
| **`async` may run inline.** | Never assume a task has started — or is parallel — after dispatching. |
| **Cancelation is not preemption.** | A loop that never blocks, or a wait parked in raw `std.posix.poll`/`read`/`Semaphore.waitUncancelable`, will not stop. If you hand-roll a wait, hand-roll the wakeup too. |
| **`std.posix.poll` swallows `EINTR` and retries.** | The signal that announces cancelation does not end a `poll`; only a deadline or a second fd does. |
| **No connect deadline.** | `IpAddress.ConnectOptions.timeout` panics (`TODO implement`); an unreachable host is bounded only by the kernel's SYN timeout. |
| **No `std.time.sleep`, no `SO_RCVTIMEO`.** | Sleep with `Io.sleep`; a socket timeout surfaces as `EAGAIN`, which `std.Io` treats as a bug and panics on in debug builds. Use a deadline. |
| **Evented backends are not ready.** | `Io.Kqueue` / `Io.Uring` / `Io.Dispatch` / `fiber` are WIP; `Threaded` is the supported model here. |

## Choosing (in order)

1. **Does it have to be parallel?** If not, use a deadline or a single task — no group needed.
2. **Parallel, all must finish** → `Group` + `await`. **Parallel, first one wins** → `Io.Select`.
3. **Must outlive the caller** → long-lived `Group`, canceled on shutdown; otherwise `await` immediately.
4. **Waiting on a socket** → a deadline *plus* a wake fd (a pipe the shutdown path writes to). A bare
   `poll` is neither cancelable nor interruptible.
5. **Capping** → decide in the accept path (refuse and let the kernel queue, or drop), never in the
   pool.

## Principles

1. **Pick the smallest unit of concurrency that matches the resource.** One connection is one task;
   a request is not, unless the connection is discarded per request. A task owns whatever it allocates.
2. **Bound work where you decide, not where you dispatch.** The limit that matters (thread count,
   client count) is an invariant of your loop, not a pool setting you do not control.
3. **Every task has an owner and a join.** A `Group`/`Select` dropped while tasks are pending leaks;
   every exit path must reach an `await` or `cancel`.
4. **Design the wake path together with the wait.** Every hand-rolled blocking wait needs something
   that can end it: a deadline, a second fd, or a cancelation check the code actually reaches.
5. **Shutdown is a feature with a case of its own.** Test it: SIGINT while saturated, a peer that
   never answers, a client that stops reading. "It exits eventually" is a bug report.
6. **Keep mutable state task-local, or lock it.** Per-task buffers and RNGs by default; `Io.Mutex`
   when the critical section can block, `std.atomic.Mutex` when it cannot.
7. **Verify against the installed stdlib.** `std.Io` is WIP in 0.16 and moves between builds: read the
   local `Io.zig` / `Io/Threaded.zig`, and pin behavior with tests rather than trusting tutorials.

## Anti-patterns

- A raw `poll`/`read` loop with no wake fd — permanent if the deadline is disabled.
- Waiting on a limit (`Semaphore.waitUncancelable`) in the accept path: it hides backpressure from the
  kernel and ignores signals.
- Logging `error.Canceled` (or the `ReadFailed` that can wrap it) as a failure.
- Assuming threads are freed when tasks finish, or that `deinit` will be reached on every path.
- Dispatching per request when one connection is one task — or accepting every connection when the
  pool cannot absorb the peak.

## Verify

Beyond the test suite (`zig build test`), exercise the **exit** path live — the part unit tests
usually miss:

1. drive concurrency up to the limit you allow, then SIGINT/SIGTERM: the process must exit promptly,
   not after the longest deadline among its parked waits;
2. connect a peer that never answers and confirm the deadline fires as configured;
3. re-read every hand-rolled wait and name the thing that ends it (deadline, wake fd, or a
   cancelation point the code actually reaches).

The shipped probe `./scripts/select_probe.zig` (5 self-contained `zig test` cases) re-checks the
`Io.Select` contract — completion order, `cancel`/drain semantics, the buffer-size trap, and the fact
that `Select` cannot interrupt a raw `poll`. Point it at your own toolchain before relying on any of
it.

## Checklist

- [ ] Parallel work goes through `Io`/`Group`/`Select`; no `std.Thread.spawn`.
- [ ] Every group/future is awaited or canceled on every exit path.
- [ ] The number of simultaneously live tasks is bounded by an invariant you own, and you can state it.
- [ ] Every blocking wait has a way out: a deadline, a wake fd, or a cancelation point it reaches.
- [ ] `error.Canceled` is handled as a normal shutdown, not reported as a failure.
- [ ] Shared mutable state is task-local, or locked with the right mutex.
- [ ] Behavior is pinned by a test, and the APIs were checked against the *installed* stdlib.
