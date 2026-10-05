# `std.Io` in Zig 0.17.0 — signatures and verified behavior

Evidence layer for [SKILL.md](../SKILL.md). Everything below was checked against the **installed**
0.17.0 stdlib (`std/Io.zig`, `std/Io/Threaded.zig`, `std/Io/Semaphore.zig`) — not against upstream
`master` or tutorials, which differ in places. `std.Io` is WIP: re-verify against your own toolchain
before relying on a detail, and pin behavior with tests.

## Backends

| Type | Status |
|---|---|
| `Io.Threaded` | The thread-pool backend; what `std.process.Init` hands you. Intended for this use. |
| `Io.Evented` / `Io.Dispatch` / `Io.Kqueue` / `Io.Uring` | Experimental; APIs still moving. Do not build on them yet. |
| `Io.failing` | Test double that returns fixed failures; its `checkCancel`, `cancel`, … are `unreachable`. |

`Threaded`'s vtable implements: `async`, `concurrent`, `await`, `cancel`, `groupAsync`,
`groupConcurrent`, `groupAwait`, `groupCancel`, `recancel`, `checkCancel`, `swapCancelProtection`,
`futexWait`/`futexWaitUncancelable`/`futexWake`, `operate`, `now`, `sleep`, `random`, `randomSecure`,
plus the file/dir/net operations. It does **not** implement any `select`: `Io.Select` is a
task-level combinator built on `Queue` + a `Group` (see below), not a backend operation.

## Threads and limits

```zig
// std/Io/Threaded.zig
pub const InitOptions = struct {
    stack_size: usize = std.Thread.SpawnConfig.default_stack_size,
    /// Maximum pool size (excluding the main thread) for `Io.async` tasks. Until the limit,
    /// calling `async` while every thread is busy spawns a thread that is *permanently* added
    /// to the pool; past it, such calls run the task immediately (inline).
    async_limit: ?Io.Limit = null,          // null → one less than the logical CPU count
    /// Maximum pool size for `Io.concurrent` tasks. Past it, `concurrent` returns
    /// `error.ConcurrencyUnavailable` — it does not queue and it does not run inline.
    concurrent_limit: Io.Limit = .unlimited,
    argv0: Argv0 = .empty,
    // …environ, disable_memory_mapping
};
pub fn init(gpa: Allocator, options: InitOptions) Threaded;
```

- Workers are spawned on demand and **never reclaimed**: the worker loop exits only when the backend
  is deinitialized (`join_requested`). A process's thread count therefore tracks the *peak* number of
  simultaneously live `concurrent` tasks, not the current one.
- `async_limit` and `concurrent_limit` are **not** interchangeable: the first degrades to inline
  execution, the second fails. Neither provides backpressure for the caller.
- `std.process.Init` exposes the finished `Io` handle but **not** `InitOptions`, so a limit expressed
  through the pool is unavailable to code that did not construct the backend itself.
- `ConcurrentError = error{ConcurrencyUnavailable}`.

`Io.Limit` is `enum(usize) { nothing, unlimited, _ }` with `limited(n)` / `limited64(n)` helpers.

## Tasks

```zig
pub fn async(io: Io, function: anytype, args: ArgsTuple) Future(Result);           // may run inline
pub fn concurrent(io: Io, function: anytype, args: ArgsTuple) ConcurrentError!Future(Result);

pub fn Future(Result: type) type = struct {
    pub fn await(f: *@This(), io: Io) Result;   // block until done;        idempotent, not threadsafe
    pub fn cancel(f: *@This(), io: Io) Result;  // request cancelation, then block
};

pub const Group = struct {
    pub const init: Group = …;
    pub fn async(g: *Group, io: Io, function: anytype, args: ArgsTuple) void;              // → Cancelable!void
    pub fn concurrent(g: *Group, io: Io, function: anytype, args: ArgsTuple) ConcurrentError!void;
    pub fn await(g: *Group, io: Io) Cancelable!void;
    pub fn cancel(g: *Group, io: Io) void;
};
```

- A task's return type must coerce to `Cancelable!void`; returning `error.Canceled` from it is a
  no-op (it is a propagation boundary).
- Per-task resources are released **when that task returns**, so a long-lived group that tasks are
  repeatedly added to is not a leak. A group that is never awaited nor canceled *does* leak, and
  `Group.async` tasks are not guaranteed to have run before that point.
- `Group.cancel` requests cancelation and blocks until every member has returned.

### Cancelation is one-shot

> "After cancelation of a task is requested, only the next cancelation point in that task will return
> `error.Canceled`: future points will not re-signal the cancelation." — `Future.cancel` doc comment

```zig
pub fn checkCancel(io: Io) Cancelable!void;                    // "is there a pending request?"
pub fn recancel(io: Io) void;                                  // re-arm it for the next point
pub const CancelProtection = enum(u1) { … };                   // .blocked / .unblocked
pub fn swapCancelProtection(io: Io, new: CancelProtection) CancelProtection;
```

`checkCancel` reads the *calling task's* state; called from a thread that is not running a task it
is a no-op.

## Waiting, deadlines, and what is *not* a cancelation point

```zig
pub const Timeout = union(enum) { none, duration: Clock.Duration, deadline: Clock.Timestamp };
pub fn operateTimeout(io: Io, operation: Operation, timeout: Timeout) OperateTimeoutError!Operation.Result;
// OperateTimeoutError = Cancelable || error{Timeout} || ConcurrentError

pub const Clock = enum { real, awake, boot, cpu_process, cpu_thread };   // NOTE: no `.monotonic`
pub fn sleep(io: Io, duration: Duration, clock: Clock) Cancelable!void;
pub fn Clock.now(clock: Clock, io: Io) Io.Timestamp;                     // .nanoseconds: i96
pub fn Io.Timestamp.durationTo(from: Timestamp, to: Timestamp) Duration; // to - from
```

A **cancelation point** is a call into `Io` that can return `error.Canceled`. These are *not* points,
so a task parked on them ignores a cancelation request no matter how long it waits:

| Not a cancelation point | Consequence |
|---|---|
| raw `std.posix.read` / `write` / `poll` / `accept` | `poll` also swallows `EINTR` and retries, so the cancelation signal cannot end it — a deadline or a second fd must |
| `Semaphore.waitUncancelable`, `Mutex.lockUncancelable`, `Condition.waitUncancelable`, `Event.waitUncancelable`, `Io.futexWaitUncancelable` | deliberate: these are for critical sections, not for waiting out a shutdown |
| `Timeout.none` waits | nothing will end them |

Practical rule: every hand-rolled wait needs an independent way out — a deadline *and*, if it must
react to a shutdown signal, a wake fd it polls alongside (`std.posix.poll` on a self-pipe).

## Synchronization

| Primitive | API | Notes |
|---|---|---|
| `Io.Mutex` | `init`, `tryLock() bool`, `lock(io) Cancelable!void`, `lockUncancelable(io) void`, `unlock(io) void` | futex-based; use when the critical section can block |
| `std.atomic.Mutex` | `tryLock() bool`, `unlock()` | spins; short, `io`-free sections (`std.Thread.Mutex` was removed in 0.16) |
| `Io.RwLock` | `lock*` / `unlock*` variants | |
| `Io.Semaphore` | `{ .permits = n }`, `wait(io)`, `waitUncancelable(io)`, `post(io)` | counting gate; **no** `tryWait`/`available`, `permits` is mutex-guarded — you cannot peek at it |
| `Io.Condition` | `wait(io, mutex)`, `waitUncancelable(io, mutex)`, `signal(io)`, `broadcast(io)` | |
| `Io.Event` | `isSet()`, `wait(io)`, `waitUncancelable(io)`, `waitTimeout(io, timeout)`, `set(io)`, `reset()` | sticky; `reset` requires no pending waiter |
| `Io.Queue(T)` | `init(buffer)`, `put/putAll/putUncancelable/putOne/putOneUncancelable`, `get/getUncancelable/getOne/getOneUncancelable`, `close(io)`, `capacity()` | fixed buffer supplied at init; `error.Closed` after close |
| `Io.futexWait / futexWaitTimeout / futexWaitUncancelable / futexWake` | | building block for your own primitives |

## Waiting for the first of several: `Io.Select(U)`

```zig
pub fn Select(comptime U: type) type = struct {
    pub fn init(io: Io, buffer: []U) S;
    pub fn async(s: *S, comptime field: Field, function: anytype, args: ArgsTuple) void;       // may run inline
    pub fn concurrent(s: *S, comptime field: Field, function: anytype, args: ArgsTuple) ConcurrentError!void;
    pub fn await(s: *S) Cancelable!U;                                   // first to complete
    pub fn awaitMany(s: *S, buffer: []U, min: usize) Cancelable!usize;
    pub fn cancel(s: *S) ?U;
    pub fn cancelDiscard(s: *S) void;
};
```

Each task's result is tagged into the union `U`; `await`/`cancel` must be called before the select is
deinitialized. This is a *task* combinator — it cannot wait on a set of file descriptors.

**It is usable on `Threaded`** (verified by running [select_probe.zig](../scripts/select_probe.zig),
5/5 green, Zig 0.17.0 on macOS; re-run it on your toolchain — one command, self-contained):

| Observation | Measured |
|---|---|
| `await` returns the first task to **complete**, not the first dispatched (slow one dispatched first, 400 ms vs 20 ms) | returned the fast one after **25 ms** |
| `await` may be called again, and tasks may be added in between (docs: legal) | second `await` on the same select worked |
| `cancel` interrupts tasks parked in a cancelation point (`Io.sleep`), then blocks until they finish | returned in **0 ms** for two 10 s sleepers; both reported the canceled path |
| Draining: call `cancel` until it returns `null` (idempotent) | `0x77, 0x77, null, null` |
| `awaitMany(buf, min)` returns ≥ `min` results in completion order, without waiting for the rest | `min=2` of 3 tasks (10/40/90 ms) → 2 results after **44 ms**: `.a, .b` |
| `cancel` cannot interrupt a task parked in a raw `std.posix.poll` | still blocked after 300 ms; returned **302 ms**, only once the fd became readable |

Two sharp edges the probe pins down:

- **Buffer size is a correctness parameter.** `init(io, buffer)` must have room for every task that
  can finish before you drain, otherwise a finished task parks inside `queue.putOneUncancelable`
  (uncancelable — the queue is full) and `cancel`/`group.cancel` waits for it: the std docs' "a
  deadlock occurs". Controlled probe: 2 tasks + 2 slots → `cancel` drained cleanly in 0 ms; 2 tasks +
  **1** slot → `cancel` still blocked after 300 ms until a slot was freed by hand.
- **Task return types are the union field, not `Cancelable!void`.** A `Select` task has nowhere to
  propagate `error.Canceled`, so it must handle cancelation itself (e.g. `io.sleep(...) catch return
  canceled_value`). And because the wait quality is inherited from the task, `Select` does not by
  itself give "react to N sockets at once" — each task's own wait must be cancelable or wakeable.

## Typed operations

```zig
pub const Operation = union(enum) {
    file_read_streaming, file_write_streaming, device_io_control, net_receive,
};
pub fn operate(io: Io, operation: Operation) Cancelable!Operation.Result;
```

`Threaded` implements `operate` **synchronously on the calling thread** (with cancelation handling):
it buys portability across backends plus uniform cancelation/timeout semantics, *not* extra
concurrency. `net_receive`'s result is `struct { ?net.Socket.ReceiveError, usize }`.

`operateTimeout(io, op, timeout)` is `Batch` + `awaitConcurrent`, and on `Threaded`
(`batchAwaitConcurrent`) that means: try the operation non-blocking, and on `WouldBlock` poll the
operation's fds **inline on the calling thread** until the deadline. Verified by running
[operate_probe.zig](../scripts/operate_probe.zig) — 5/5 green, Zig 0.17.0 on macOS:

| Property | Measured |
|---|---|
| Deadline is the backend's: a silent peer returns `error.Timeout` at the requested deadline | **200 ms** for a 200 ms timeout |
| Cancelation ends a parked wait with no wake fd, no self-pipe | `Group.cancel` → task returned **0 ms** later with `error.Canceled` |
| No thread is dispatched to wait: it works with a **pool of zero workers** (`concurrent_limit = .nothing`) | `error.Timeout` after **199 ms** (never `error.ConcurrencyUnavailable`) |
| Bytes arrive over the caller's own buffer (no read-ahead copy) | 1 message, `data = "abc"` |
| EOF is explicit: a closed peer yields **one message with `data.len == 0`** | returned in **0 ms** |

So on `Threaded` this is the thread-parks-anyway situation — but expressed in `Io` terms, which is
what a reactor backend would need to stop parking a thread, and which removes the need to hand-roll
`poll` + wake-fd + cancelation plumbing. Two caveats found by the probe:

- **`Io.net.Socket.createPair` is not usable on macOS**: its default `family = .ip4` socketpair is
  Linux-only, and it aborts with `unexpectedErrno` (the probe builds a connected TCP pair instead).
- `Operation` has **no send variant** (`net_receive` only), so the *write* path cannot be expressed
  as an operation today; it stays on `Io.Writer` → `netWrite`.

## Known gaps in 0.17.0

| Gap | Detail |
|---|---|
| No connect deadline | `IpAddress.ConnectOptions.timeout` exists but `netConnectIpPosix/Windows` `@panic("TODO implement … with timeout")`. An unreachable host is bounded by the kernel's SYN timeout only. |
| No `std.time.sleep` / `std.posix.nanosleep` | Sleep through `Io.sleep`. |
| `SO_RCVTIMEO` is unusable | A socket read timeout surfaces as `EAGAIN`, which `std.Io` treats as an internal bug (`errnoBug`) and panics on in debug builds. Express deadlines with `Timeout`/`poll` instead. |
| No `std.Thread.Mutex` | Use `Io.Mutex` (cancelable futex) or `std.atomic.Mutex` (short, spinning). |
| Pool not configurable via `std.process.Init` | `InitOptions` only when you construct `Threaded` yourself. |

## How these claims were checked

`grep`/read of the installed sources (`std/Io.zig`, `std/Io/Threaded.zig`, `std/Io/Semaphore.zig`) for
every signature above, plus runtime observation of the Threaded backend on macOS: thread count
tracking peak concurrent tasks and never falling, `ConcurrencyUnavailable` past a low
`concurrent_limit`, prompt `error.Canceled` only where a wait polls a wake fd, and `--timeout`-style
deadlines firing as configured. Prefer repeating such a measurement over trusting this file.
