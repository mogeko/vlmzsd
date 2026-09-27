//! Probe: is `Io.Select(U)` usable in Zig 0.16.0 on the Threaded backend?
//!
//! Run standalone (human mode, no `--listen=-` harness):
//!     zig test .github/skills/io-async/scripts/select_probe.zig
//!
//! Every case prints its measurement to stderr so the numbers can be quoted, and
//! asserts the *documented* semantics so a surprise fails the run instead of
//! passing silently. Cases are designed never to hang: where the std docs warn
//! about a deadlock, the blocking call runs in its own task and the main thread
//! rescues it after a fixed delay.
//!
//! Hypotheses under test (H) and the case that checks each:
//!   H1  `Select` type-checks and runs on `Threaded`              -> all cases
//!   H2  `await` returns the first *completed* task              -> case 1
//!   H3  tasks may be added after an `await`                     -> case 1
//!   H4  `cancel` interrupts cancelable waits, drains to null     -> case 2
//!   H5  `awaitMany(buf, m)` returns the m fastest, in order      -> case 3
//!   H6  an undersized buffer makes `cancel` deadlock (doc claim) -> case 4
//!   H7  `cancel` cannot interrupt a raw `std.posix.poll`         -> case 5

const std = @import("std");
const Io = std.Io;

// Compile-time probe: these symbols must resolve at all in the installed stdlib.
comptime {
    _ = Io.Select;
    _ = Io.Operation;
    _ = Io.operate;
    _ = Io.operateTimeout;
    _ = Io.checkCancel;
    _ = Io.swapCancelProtection;
    _ = Io.recancel;
}

const ms: i96 = 1_000_000;

fn elapsedMs(from: Io.Timestamp, io: Io) i96 {
    return @divTrunc(from.durationTo(Io.Timestamp.now(io, .awake)).nanoseconds, ms);
}

/// Sleep that swallows cancelation: a `Select` task's return type is the union
/// field, so it has nowhere to propagate `error.Canceled` to.
fn sleepMs(n: u64, io: Io) bool {
    io.sleep(.{ .nanoseconds = @as(i96, n) * ms }, .awake) catch return false;
    return true;
}

const Outcome = union(enum) { fast: u32, slow: u32 };

fn slowTask(io: Io) u32 {
    _ = sleepMs(400, io);
    return 0x51;
}

fn fastTask(io: Io) u32 {
    _ = sleepMs(20, io);
    return 0xFA;
}

// H1, H2, H3: the winner is the first to *complete*, in either dispatch order;
// `await` may be called repeatedly, and new tasks may be added in between.
test "await returns the first completed task, not the first dispatched" {
    const gpa = std.testing.allocator;
    var threaded: Io.Threaded = .init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var buf: [2]Outcome = undefined;
    var sel: Io.Select(Outcome) = .init(io, &buf);
    defer sel.cancelDiscard();

    // Slow one dispatched first: "first completed" must still win.
    sel.async(.slow, slowTask, .{io});
    sel.async(.fast, fastTask, .{io});

    const t0 = Io.Timestamp.now(io, .awake);
    const got = try sel.await();
    const dt = elapsedMs(t0, io);
    std.debug.print("[1] await -> .{s} ({d}) after {d} ms (slow task needs 400 ms)\n", .{
        @tagName(got), got.fast, dt,
    });

    try std.testing.expect(got == .fast);
    try std.testing.expectEqual(@as(u32, 0xFA), got.fast);
    try std.testing.expect(dt < 200);

    // H3: reuse the same select for a task added after the first await.
    sel.async(.fast, fastTask, .{io});
    const again = try sel.await();
    std.debug.print("[1] second await on the same select -> .{s} ({d})\n", .{
        @tagName(again), again.fast,
    });
    try std.testing.expectEqual(@as(u32, 0xFA), again.fast);
}

const Sleeper = union(enum) { woke: u32 };

/// `Io.sleep` is a cancelation point, so a cancelation request must cut it short;
/// the task reports which path it took (1 = slept through, 0 = canceled).
fn longSleeper(io: Io) u32 {
    if (sleepMs(10_000, io)) return 1;
    return 0;
}

// H4: `cancel` requests cancelation on the remaining tasks, blocks until they
// finish, and is drained by calling it until it returns null.
test "cancel interrupts a cancelable wait and drains to null" {
    const gpa = std.testing.allocator;
    var threaded: Io.Threaded = .init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var buf: [2]Sleeper = undefined;
    var sel: Io.Select(Sleeper) = .init(io, &buf);

    sel.async(.woke, longSleeper, .{io});
    sel.async(.woke, longSleeper, .{io});

    const t0 = Io.Timestamp.now(io, .awake);
    const first = sel.cancel();
    const dt = elapsedMs(t0, io);
    const second = sel.cancel();
    const third = sel.cancel();
    std.debug.print("[2] cancel -> {d} ms, values: first={any} second={any} third={any}\n", .{
        dt,
        if (first) |v| v.woke else null,
        if (second) |v| v.woke else null,
        if (third) |v| v.woke else null,
    });

    // Both tasks were sleeping 10 s: cancel must beat that by a lot...
    try std.testing.expect(dt < 1_000);
    // ...and both must have observed `error.Canceled` (0), not slept through (1).
    try std.testing.expectEqual(@as(?u32, 0), if (first) |v| v.woke else null);
    try std.testing.expectEqual(@as(?u32, 0), if (second) |v| v.woke else null);
    try std.testing.expect(third == null); // drained
    try std.testing.expect(sel.cancel() == null); // idempotent
}

const Trio = union(enum) { a: u32, b: u32, c: u32 };

fn taskA(io: Io) u32 {
    _ = sleepMs(10, io);
    return 0xA;
}
fn taskB(io: Io) u32 {
    _ = sleepMs(40, io);
    return 0xB;
}
fn taskC(io: Io) u32 {
    _ = sleepMs(90, io);
    return 0xC;
}

// H5: `awaitMany` blocks until at least `min` results are queued, and hands them
// back in completion order.
test "awaitMany returns the m fastest results in completion order" {
    const gpa = std.testing.allocator;
    var threaded: Io.Threaded = .init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var sel_buf: [3]Trio = undefined;
    var sel: Io.Select(Trio) = .init(io, &sel_buf);
    defer sel.cancelDiscard();

    sel.async(.c, taskC, .{io});
    sel.async(.b, taskB, .{io});
    sel.async(.a, taskA, .{io});

    var out: [3]Trio = undefined;
    const t0 = Io.Timestamp.now(io, .awake);
    const n = try sel.awaitMany(&out, 2);
    const dt = elapsedMs(t0, io);
    std.debug.print("[3] awaitMany(min=2) -> {d} results after {d} ms: .{s}, .{s}\n", .{
        n, dt, @tagName(out[0]), @tagName(out[1]),
    });

    try std.testing.expectEqual(@as(usize, 2), n);
    try std.testing.expect(out[0] == .a); // 10 ms
    try std.testing.expect(out[1] == .b); // 40 ms
    try std.testing.expect(dt < 80); // not waiting for .c at 90 ms
}

const Two = union(enum) { v: u32 };

fn quickTask(io: Io) u32 {
    _ = sleepMs(10, io);
    return 0x77;
}

/// Runs `Select.cancel()` on another task so the test thread can observe whether
/// it returned — the point of case 4.
fn cancelProbe(sel: *Io.Select(Two), done: *std.atomic.Value(bool), value: *?Two) Io.Cancelable!void {
    value.* = sel.cancel();
    done.store(true, .release);
}

// H6: the docs warn "If the select was initialized with insufficient buffer space
// for all remaining tasks to finish, a deadlock occurs." Controlled experiment:
// the same two tasks, only the buffer size differs.
//   (a) buffer >= tasks  -> `cancel` drains promptly and cleanly;
//   (b) buffer <  tasks  -> a finished task parks inside
//                          `queue.putOneUncancelable` (uncancelable, queue full),
//                          so `cancel` cannot finish until a slot is freed.
test "buffer size decides whether cancel can drain (documented trap)" {
    const gpa = std.testing.allocator;
    var threaded: Io.Threaded = .init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();

    // (a) control: room for every task.
    {
        var sel_buf: [2]Two = undefined;
        var sel: Io.Select(Two) = .init(io, &sel_buf);
        sel.async(.v, quickTask, .{io});
        sel.async(.v, quickTask, .{io});

        const t0 = Io.Timestamp.now(io, .awake);
        const first = sel.cancel();
        const dt = elapsedMs(t0, io);
        const second = sel.cancel();
        const third = sel.cancel();
        std.debug.print("[4a] 2 slots / 2 tasks: cancel -> {d} ms; drained {any}, {any}, then {any}\n", .{
            dt,
            if (first) |v| v.v else null,
            if (second) |v| v.v else null,
            if (third) |v| v.v else null,
        });
        try std.testing.expect(dt < 200);
        try std.testing.expectEqual(@as(?u32, 0x77), if (first) |v| v.v else null);
        try std.testing.expectEqual(@as(?u32, 0x77), if (second) |v| v.v else null);
        try std.testing.expect(third == null);
    }

    // (b) treatment: one slot short.
    {
        var sel_buf: [1]Two = undefined;
        var sel: Io.Select(Two) = .init(io, &sel_buf);
        sel.async(.v, quickTask, .{io});
        sel.async(.v, quickTask, .{io});

        var done = std.atomic.Value(bool).init(false);
        var value: ?Two = null;
        var outer: Io.Group = .init;
        defer outer.cancel(io);
        try outer.concurrent(io, cancelProbe, .{ &sel, &done, &value });

        _ = sleepMs(300, io);
        const blocked = !done.load(.acquire);
        std.debug.print("[4b] 1 slot / 2 tasks: cancel returned within 300 ms = {}\n", .{!blocked});
        try std.testing.expect(blocked); // the documented trap is real

        // Free exactly one slot: that is what lets the parked put complete and
        // `group.cancel` return. `cancel` then drains the remaining value itself.
        const rescued = try sel.queue.getOneUncancelable(io);
        std.debug.print("[4b] freed one slot, taking {any}; now letting cancel() finish\n", .{rescued.v});
        try outer.await(io);
        std.debug.print("[4b] cancel() returned {any}\n", .{if (value) |v| v.v else null});

        try std.testing.expectEqual(@as(?u32, 0x77), if (value) |v| v.v else null);
        try std.testing.expect(sel.cancel() == null);
    }
}

const Raw = union(enum) { polled: u32 };

/// Parks in a *raw* poll: not a cancelation point, so only data can end it.
fn parkedPoller(io: Io, fd: std.posix.fd_t) u32 {
    _ = io;
    var fds = [1]std.posix.pollfd{.{ .fd = fd, .events = std.posix.POLL.IN, .revents = 0 }};
    _ = std.posix.poll(&fds, -1) catch return 0;
    return 1;
}

// H7: `Select` composes tasks, not file descriptors. A task parked in
// `std.posix.poll` ignores cancelation, so `cancel` waits for the fd — the
// reason `Select` is not a reactor to wait on N sockets with.
test "cancel cannot interrupt a raw poll" {
    const gpa = std.testing.allocator;
    var threaded: Io.Threaded = .init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var pipe_fds: [2]std.posix.fd_t = undefined;
    try std.testing.expectEqual(@as(c_int, 0), std.c.pipe(&pipe_fds));
    defer {
        _ = std.c.close(pipe_fds[0]);
        _ = std.c.close(pipe_fds[1]);
    }

    var sel_buf: [1]Raw = undefined;
    var sel: Io.Select(Raw) = .init(io, &sel_buf);
    defer sel.cancelDiscard();

    sel.async(.polled, parkedPoller, .{ io, pipe_fds[0] });

    var done = std.atomic.Value(bool).init(false);
    var value: ?Raw = null;
    var outer: Io.Group = .init;
    defer outer.cancel(io);
    const started = Io.Timestamp.now(io, .awake);
    try outer.concurrent(io, cancelRawProbe, .{ &sel, &done, &value });

    _ = sleepMs(300, io);
    const blocked = !done.load(.acquire);
    // Only now does the parked poll have a reason to return.
    const byte: [1]u8 = .{1};
    _ = std.c.write(pipe_fds[1], &byte, 1);
    try outer.await(io);
    const dt = elapsedMs(started, io);
    std.debug.print("[5] cancel on a task parked in raw poll: returned within 300 ms = {}, took {d} ms\n", .{ !blocked, dt });
    std.debug.print("[5] the polled task's result reached the select: value = {any}\n", .{if (value) |v| v.polled else null});

    try std.testing.expect(blocked); // cancel was stuck on the raw poll
    try std.testing.expect(dt >= 300);
    try std.testing.expectEqual(@as(?u32, 1), if (value) |v| v.polled else null);
}

fn cancelRawProbe(sel: *Io.Select(Raw), done: *std.atomic.Value(bool), value: *?Raw) Io.Cancelable!void {
    value.* = sel.cancel();
    done.store(true, .release);
}
