//! Bounded, lossy multi-producer / single-consumer FIFO, after Dmitry Vyukov's
//! bounded MPMC queue
//! (<https://sites.google.com/site/1024cores/home/lock-free-algorithms/queues/bounded-mpmc-queue>),
//! specialized to one consumer.
//!
//! Any number of producers may call `tryPush`; exactly one consumer drains with
//! `popCopy`/`popBatch` and waits on `awaitWork`. A push never blocks and never
//! allocates: it either takes a slot or is refused when the ring is full, and
//! every refusal is counted. That is what a log path needs — a full ring must
//! not stall a worker serving a client — so the ring is lock-free: no producer
//! ever waits on a lock held by another thread.
//!
//! The algorithm is Vyukov's. The ring has `capacity` cells (a power of two, so
//! a position maps to a cell by a mask). `head` is the next position a producer
//! may reserve and `tail` the oldest position not yet released; both only grow,
//! and they stay at most `capacity` apart. Each cell carries a sequence naming
//! the lap it is in: `position` while the cell is free, `position + 1` once the
//! payload is published, `position + capacity` once the consumer released it. A
//! producer reserves a position with a CAS on `head`, then publishes by storing
//! the sequence; the consumer decides from the sequence whether the cell at
//! `tail` is published, copies the payload out, and releases the cell for the
//! following lap. Only one consumer may advance `tail`, so its side needs no
//! CAS at all — that is the MPSC specialization of the MPMC original.
//!
//! Two consequences of that design are visible to a caller. A producer can
//! reserve a position and be slow to publish, so `hasWork` (and therefore
//! `popCopy`) can report "empty" while `head` has already moved on; the signal
//! the producer sends after publishing brings the consumer back. And a producer
//! can see "full" while a slot frees a moment later: a wakeup is not lost, but
//! the value is, and the drop counter records it.
//!
//! The consumer parks on a signal counter. It reads the counter, tests the ring
//! and the closed flag, and then waits only while the counter still holds the
//! value it read, so a signal that lands after those tests ends the wait by
//! value. `close` uses the same signal, which is what makes the shutdown
//! handshake safe: a boolean latch would lose it, because re-arming a latch is
//! a plain store that can erase a `close` arriving at the wrong moment, leaving
//! the consumer parked with nothing left to wake it. A counter cannot be erased
//! — every later signal changes the word the consumer waits on.
//!
//! Internal to the `vlmzsd`/`vlmzs` binaries: not part of the public API
//! (see `docs/library.md`).

const std = @import("std");

const Io = std.Io;
const Allocator = std.mem.Allocator;

/// Outcome of `tryPush`. Every value except `accepted` means the value was
/// dropped and counted.
pub const PushResult = enum {
    accepted,
    /// Every slot is in use.
    full,
    /// `close` was called; the producer is expected to stop.
    closed,
};

/// Why `awaitWork` returned.
pub const Wake = enum {
    /// At least one value is published; drain it.
    work,
    /// The queue is closed *and* drained; the consumer is done.
    closed,
};

/// A bounded MPSC FIFO holding up to `capacity` values of type `T` inline.
/// Any number of threads may push; exactly one may pop.
///
/// `capacity` must be a power of two and at least two: a position maps to a cell
/// with a mask, and with a single cell the published marker `position + 1` would
/// coincide with the released marker `position + capacity`.
pub fn Queue(comptime T: type, comptime capacity: usize) type {
    std.debug.assert(capacity >= 2);
    std.debug.assert(std.math.isPowerOfTwo(capacity));

    return struct {
        const Self = @This();

        /// One ring slot. The consumer reads `sequence` before `value` and the
        /// producer writes `value` before `sequence`, so the payload needs no
        /// lock of its own: `sequence` carries both the lap and the handover.
        const Cell = struct {
            /// Lap marker: `position` while free, `position + 1` once published,
            /// `position + capacity` once the consumer released it.
            sequence: std.atomic.Value(usize) = .init(0),
            value: T = undefined,
        };

        /// The ring is a power of two, so a position maps to a cell by a mask.
        const mask: usize = capacity - 1;

        cells: []Cell,
        /// Next position a producer may reserve; only the CAS in `reserve`
        /// writes it. On a cache line of its own: producers hammer it while the
        /// consumer hammers `tail`, and sharing a line would make each side
        /// invalidate the other's.
        head: std.atomic.Value(usize) align(std.atomic.cache_line) = .init(0),
        /// Oldest position not yet released. Only the single consumer writes
        /// it, which is what lets the consumer side skip the CAS.
        tail: std.atomic.Value(usize) align(std.atomic.cache_line) = .init(0),
        /// Bumped by every publish and by `close`. The consumer parks on it, so
        /// the wait ends when the value it read before testing the ring changes.
        /// A `u32` because `Io.futexWait` takes a futex word.
        wake: std.atomic.Value(u32) align(std.atomic.cache_line) = .init(0),
        /// Set while the consumer is parked or about to be. `signal` clears it to
        /// claim the wake, so a burst of pushes behind one park wakes once, and
        /// the common push only *loads* it. An optimization, not a correctness
        /// requirement: `wake` alone ends the park.
        waiting: std.atomic.Value(bool) = .init(false),
        /// Set by `close`; producers then refuse instead of pushing.
        closed: std.atomic.Value(bool) = .init(false),
        /// Refused pushes, full or closed — a monotonic total, never cleared.
        /// Only a producer that is losing its value touches it, so the accepted
        /// path pays nothing for the count. It counts refusals rather than lost
        /// values: the queue cannot know whether the caller retries, so a
        /// retrying producer makes this an upper bound.
        dropped: std.atomic.Value(u64) align(std.atomic.cache_line) = .init(0),

        /// Allocate the ring once, before any producer starts.
        pub fn init(gpa: Allocator) Allocator.Error!Self {
            const cells = try gpa.alloc(Cell, capacity);
            for (cells, 0..) |*cell, index| {
                cell.* = .{ .sequence = .init(index) };
            }
            return .{ .cells = cells };
        }

        /// Release the ring. Only valid once every producer and the consumer
        /// have stopped.
        pub fn deinit(self: *Self, gpa: Allocator) void {
            std.debug.assert(self.cells.len == capacity);
            gpa.free(self.cells);
        }

        /// Append one value at the tail. Never blocks and never allocates: a
        /// value that finds every slot in use is dropped and counted instead.
        pub fn tryPush(self: *Self, io: Io, value: T) PushResult {
            if (self.isClosed()) {
                _ = self.dropped.fetchAdd(1, .monotonic);
                return .closed;
            }
            const position = self.reserve() orelse {
                _ = self.dropped.fetchAdd(1, .monotonic);
                return .full;
            };
            const cell = &self.cells[position & mask];
            cell.value = value;
            // Publish with `release` so whoever acquires the sequence sees the
            // payload. The signal must follow the publish, or a consumer that
            // already tested emptiness could park with this value queued.
            cell.sequence.store(position +% 1, .release);
            self.signal(io);
            return .accepted;
        }

        /// Tell the consumer that the ring changed. The counter is bumped
        /// unconditionally, so no wake can be lost; the wake itself is
        /// optimistic — the swap claims a parked consumer, so of the pushes that
        /// arrive behind one park exactly one enters the kernel and the rest
        /// skip it.
        fn signal(self: *Self, io: Io) void {
            _ = self.wake.fetchAdd(1, .release);
            if (self.waiting.load(.monotonic) and self.waiting.swap(false, .monotonic)) {
                io.futexWake(u32, &self.wake.raw, 1);
            }
        }

        /// Claim the next position for this producer, or `null` when the ring
        /// is full. Other producers may hold earlier positions without having
        /// published them yet; that is not "full", it is "retry the cell".
        fn reserve(self: *Self) ?usize {
            var position = self.head.load(.monotonic);
            while (true) {
                const cell = &self.cells[position & mask];
                const sequence = cell.sequence.load(.acquire);
                // Signed distance, as in Vyukov's `intptr_t` difference: zero
                // means this cell is free at `position`, negative means it is
                // still held from the previous lap (the ring is full), positive
                // means another producer already moved past `position`.
                const distance: isize = @bitCast(sequence -% position);
                if (distance == 0) {
                    if (self.head.cmpxchgWeak(position, position +% 1, .monotonic, .monotonic)) |observed| {
                        position = observed;
                        continue;
                    }
                    return position;
                }
                if (distance < 0) return null;
                position = self.head.load(.monotonic);
            }
        }

        /// Copy the oldest value into `dst` and release its slot; `false` when
        /// nothing is published at `tail`. Single consumer only.
        pub fn popCopy(self: *Self, dst: *T) bool {
            const position = self.tail.load(.monotonic);
            const cell = &self.cells[position & mask];
            // `acquire` pairs with the producer's `release`, so the copy below
            // reads a complete value.
            const sequence = cell.sequence.load(.acquire);
            const distance: isize = @bitCast(sequence -% (position +% 1));
            if (distance != 0) {
                // With one consumer the cell is at most one step behind, and
                // "behind" means unpublished. Anything else would mean a second
                // consumer advancing `tail`, which breaks the algorithm.
                std.debug.assert(distance == -1);
                return false;
            }
            dst.* = cell.value;
            self.tail.store(position +% 1, .monotonic);
            // Free the cell for the next lap. `release` orders the payload copy
            // before the producer's `acquire` on the sequence.
            cell.sequence.store(position +% capacity, .release);
            return true;
        }

        /// Copy out up to `dst.len` values in arrival order; returns the count.
        pub fn popBatch(self: *Self, dst: []T) usize {
            std.debug.assert(dst.len > 0);
            var count: usize = 0;
            while (count < dst.len) : (count += 1) {
                if (!self.popCopy(&dst[count])) break;
            }
            return count;
        }

        /// True when a `popCopy` would succeed. Answers from the published
        /// sequence rather than from `head - tail`: a position can be reserved
        /// and not yet published, and reporting that as work would spin the
        /// consumer on an empty queue.
        pub fn hasWork(self: *const Self) bool {
            const position = self.tail.load(.monotonic);
            const sequence = self.cells[position & mask].sequence.load(.acquire);
            return sequence == position +% 1;
        }

        /// Wait until at least one value is published, or until the queue is
        /// closed with nothing left to drain — whichever comes first, and
        /// without parking when it can answer immediately.
        ///
        /// The ticket is taken *before* the two tests, never after: a signal
        /// that lands between the ticket and the park has already changed
        /// `wake`, so the park returns at once, and one that lands before the
        /// ticket is visible to the tests that follow it. Taking the ticket the
        /// other way round would leave a window where the queue is closed, the
        /// `closed` read is stale, and the park waits for a signal that already
        /// happened.
        ///
        /// A cancelation point: `error.Canceled` means the *wait* was
        /// cancelled, not that the queue closed — whether to drain and stop is
        /// the caller's decision.
        pub fn awaitWork(self: *Self, io: Io) Io.Cancelable!Wake {
            while (true) {
                const ticket = self.wake.load(.acquire);
                if (self.hasWork()) return .work;
                if (self.isClosed()) return .closed;
                self.waiting.store(true, .monotonic);
                io.futexWait(u32, &self.wake.raw, ticket) catch |err| {
                    self.waiting.store(false, .monotonic);
                    return err;
                };
                self.waiting.store(false, .monotonic);
            }
        }

        /// Refuse further pushes and signal the consumer so it can drain and
        /// exit. Call only after every producer has stopped: a push that passed
        /// the `closed` check before this call can still publish afterwards,
        /// and a consumer that already saw `.closed` would leave it behind.
        pub fn close(self: *Self, io: Io) void {
            self.closed.store(true, .release);
            self.signal(io);
        }

        pub fn isClosed(self: *const Self) bool {
            return self.closed.load(.acquire);
        }

        /// Pushes refused since `init`. The total only grows, so a reporter
        /// that wants the loss for one period keeps the value it last saw and
        /// subtracts; the count a late reader sees is always the whole run's.
        pub fn droppedCount(self: *const Self) u64 {
            return self.dropped.load(.monotonic);
        }
    };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

/// Small ring: its two laps are enough to expose an off-by-one in the sequence
/// arithmetic, and filling it is cheap.
const test_capacity = 8;

const TestQueue = Queue(u32, test_capacity);

/// Counts for the threaded tests. The wakeup case's producers retry until their
/// value is accepted, so they only terminate because the consumer keeps draining
/// the ring — which is what the case is there to prove.
const producers = 4;
const lines_per_producer = 200;

// The queue's contract is pinned here in isolation from any caller: arrival
// order (FIFO), the reserved-but-unpublished read as empty, the lossy full-ring
// path with its counter, ring reuse across laps, close/drain semantics, and the
// wakeup protocol. Only the last two cases start threads; the rest drive the
// ring directly on the test thread.
test "push and pop preserve arrival order" {
    const alloc = testing.allocator;
    const io = testing.io;
    var queue = try TestQueue.init(alloc);
    defer queue.deinit(alloc);

    try testing.expect(!queue.hasWork());
    try testing.expectEqual(PushResult.accepted, queue.tryPush(io, 1));
    try testing.expectEqual(PushResult.accepted, queue.tryPush(io, 2));
    try testing.expect(queue.hasWork());

    var batch: [4]u32 = undefined;
    try testing.expectEqual(@as(usize, 2), queue.popBatch(&batch));
    try testing.expectEqual(@as(u32, 1), batch[0]);
    try testing.expectEqual(@as(u32, 2), batch[1]);
    try testing.expect(!queue.hasWork());
    try testing.expectEqual(@as(usize, 0), queue.popBatch(&batch));
    try testing.expectEqual(@as(u64, 0), queue.droppedCount());
}

test "a reserved but unpublished slot reads as empty, not as work" {
    // The hazard the MPSC specialization introduces: a producer has moved `head`
    // but not yet stored the sequence. `hasWork` must answer from the sequence,
    // or a consumer would see "work" and spin on a cell that is not published.
    // The gap is made deterministic here by writing the two fields a `tryPush`
    // writes, in the order it writes them.
    const alloc = testing.allocator;
    const io = testing.io;
    var queue = try TestQueue.init(alloc);
    defer queue.deinit(alloc);

    queue.head.store(1, .monotonic);
    try testing.expect(!queue.hasWork());
    var out: u32 = undefined;
    try testing.expect(!queue.popCopy(&out));

    // Publishing the reserved slot is what makes it work, and the wakeup that a
    // producer sends afterwards is what ends a consumer's park.
    queue.cells[0].value = 42;
    queue.cells[0].sequence.store(1, .release);
    try testing.expect(queue.hasWork());
    try testing.expectEqual(Wake.work, try queue.awaitWork(io));
    try testing.expect(queue.popCopy(&out));
    try testing.expectEqual(@as(u32, 42), out);
    try testing.expect(!queue.hasWork());
}

test "a full ring refuses pushes and counts every drop" {
    const alloc = testing.allocator;
    const io = testing.io;
    var queue = try TestQueue.init(alloc);
    defer queue.deinit(alloc);

    var i: u32 = 0;
    while (i < test_capacity) : (i += 1) {
        try testing.expectEqual(PushResult.accepted, queue.tryPush(io, i));
    }
    try testing.expectEqual(PushResult.full, queue.tryPush(io, 0xdead));
    try testing.expectEqual(PushResult.full, queue.tryPush(io, 0xbeef));
    try testing.expectEqual(@as(u64, 2), queue.droppedCount());

    // The refused values are not in the ring: draining yields exactly what was
    // accepted, in order, and frees the slots again.
    var batch: [test_capacity]u32 = undefined;
    try testing.expectEqual(@as(usize, test_capacity), queue.popBatch(&batch));
    for (batch, 0..) |value, index| try testing.expectEqual(@as(u32, @intCast(index)), value);
    try testing.expectEqual(PushResult.accepted, queue.tryPush(io, 0xfeed));
    try testing.expectEqual(@as(usize, 1), queue.popBatch(&batch));
    try testing.expectEqual(@as(u32, 0xfeed), batch[0]);

    // The total never resets, so a period delta is the reporter's own
    // subtraction: remember the total, and subtract it from the next reading.
    const period_start = queue.droppedCount();
    var j: u32 = 0;
    while (j < test_capacity) : (j += 1) {
        try testing.expectEqual(PushResult.accepted, queue.tryPush(io, j));
    }
    try testing.expectEqual(PushResult.full, queue.tryPush(io, 0xdead));
    try testing.expectEqual(period_start + 1, queue.droppedCount());
}

test "the ring wraps across laps without losing order" {
    const alloc = testing.allocator;
    const io = testing.io;
    var queue = try TestQueue.init(alloc);
    defer queue.deinit(alloc);

    // One value in flight per lap: every push reuses the cell of the pop before
    // it, which is the sequence arithmetic's tightest case.
    var single: [1]u32 = undefined;
    var i: u32 = 0;
    while (i < 3 * test_capacity) : (i += 1) {
        try testing.expectEqual(PushResult.accepted, queue.tryPush(io, i));
        try testing.expectEqual(@as(usize, 1), queue.popBatch(&single));
        try testing.expectEqual(i, single[0]);
    }

    // A refill that straddles the ring's end: fill the ring, drain half, then
    // push into the cells the drain just released while the other half is still
    // queued. The final drain must still yield both halves in order.
    var batch: [test_capacity]u32 = undefined;
    const half = test_capacity / 2;
    i = 0;
    while (i < test_capacity) : (i += 1) try testing.expectEqual(PushResult.accepted, queue.tryPush(io, i));
    try testing.expectEqual(@as(usize, half), queue.popBatch(batch[0..half]));
    for (batch[0..half], 0..) |value, index| try testing.expectEqual(@as(u32, @intCast(index)), value);
    while (i < test_capacity + half) : (i += 1) try testing.expectEqual(PushResult.accepted, queue.tryPush(io, i));
    try testing.expectEqual(@as(usize, test_capacity), queue.popBatch(&batch));
    for (batch, 0..) |value, index| try testing.expectEqual(@as(u32, @intCast(index + half)), value);
    try testing.expectEqual(@as(u64, 0), queue.droppedCount());
}

test "every signal moves the wake word" {
    // The property `awaitWork` rests on, and the reason it parks on a counter
    // rather than a boolean latch: a consumer that took its ticket and is about
    // to park must be released by *any* later signal, including one that leaves
    // the ring exactly as the ticket described. A latch cannot promise that —
    // re-arming it erases a concurrent `close` — so this pins the counter
    // rather than trying to reproduce a schedule.
    const alloc = testing.allocator;
    const io = testing.io;
    var queue = try TestQueue.init(alloc);
    defer queue.deinit(alloc);

    const initial = queue.wake.load(.acquire);
    try testing.expectEqual(PushResult.accepted, queue.tryPush(io, 1));
    const after_push = queue.wake.load(.acquire);
    try testing.expect(after_push != initial);

    // A push that is refused signals nothing: no state changed, so a ticket
    // taken across it still describes an empty ring.
    var i: u32 = 1;
    while (i < test_capacity) : (i += 1) {
        try testing.expectEqual(PushResult.accepted, queue.tryPush(io, i));
    }
    const before_refusal = queue.wake.load(.acquire);
    try testing.expectEqual(PushResult.full, queue.tryPush(io, 0xdead));
    try testing.expectEqual(before_refusal, queue.wake.load(.acquire));

    var batch: [test_capacity]u32 = undefined;
    try testing.expectEqual(@as(usize, test_capacity), queue.popBatch(&batch));

    // `close` moves the word too, which is what makes a ticket taken before it
    // unable to park: the wait returns at once instead of sleeping through the
    // close.
    const before_close = queue.wake.load(.acquire);
    queue.close(io);
    try testing.expect(queue.wake.load(.acquire) != before_close);
    try testing.expectEqual(Wake.closed, try queue.awaitWork(io));
}

test "close refuses pushes and reports closed only once drained" {
    const alloc = testing.allocator;
    const io = testing.io;
    var queue = try TestQueue.init(alloc);
    defer queue.deinit(alloc);

    try testing.expectEqual(PushResult.accepted, queue.tryPush(io, 7));
    queue.close(io);
    try testing.expect(queue.isClosed());
    try testing.expectEqual(PushResult.closed, queue.tryPush(io, 8));
    try testing.expectEqual(@as(u64, 1), queue.droppedCount());

    // Work wins over closed, so a consumer always drains before it stops. Both
    // branches return without parking, which keeps this case deterministic: a
    // regression can only fail an assertion, never hang.
    try testing.expectEqual(Wake.work, try queue.awaitWork(io));
    var batch: [4]u32 = undefined;
    try testing.expectEqual(@as(usize, 1), queue.popBatch(&batch));
    try testing.expectEqual(@as(u32, 7), batch[0]);
    try testing.expectEqual(Wake.closed, try queue.awaitWork(io));
    try testing.expectEqual(@as(usize, 0), queue.popBatch(&batch));
}

test "a parked consumer is woken by a push and by close" {
    // The wakeup path: the consumer parks in `awaitWork` instead of polling, so
    // every value has to arrive through a real wakeup and `close` has to wake it
    // one last time. Push (signal after the publish) and close both race the
    // consumer's ticket/test/wait, which is what `awaitWork` exists to make safe.
    if (@import("builtin").single_threaded) return error.SkipZigTest;
    const alloc = testing.allocator;

    var threaded: std.Io.Threaded = .init(alloc, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var queue = try TestQueue.init(alloc);
    defer queue.deinit(alloc);

    const Consumer = struct {
        queue: *TestQueue,
        io: Io,
        /// Written by the consumer task, read after the group join.
        seen: usize = 0,

        fn run(self: *@This()) void {
            var batch: [16]u32 = undefined;
            while (true) {
                // Nothing cancels this wait: the test stops the consumer with
                // `close`, which is the `.closed` branch below.
                const wake = self.queue.awaitWork(self.io) catch return;
                if (wake == .closed) return;
                var count = self.queue.popBatch(&batch);
                while (count > 0) {
                    self.seen += count;
                    count = self.queue.popBatch(&batch);
                }
            }
        }
    };

    const Producer = struct {
        queue: *TestQueue,
        io: Io,
        id: u32,

        fn run(self: *@This()) void {
            var i: u32 = 0;
            while (i < lines_per_producer) : (i += 1) {
                // Retry instead of dropping: the consumer keeps draining the
                // ring, so a refusal is transient and the value eventually
                // lands. That also makes the consumer's total exact below.
                while (self.queue.tryPush(self.io, self.id << 16 | i) != .accepted) {
                    std.atomic.spinLoopHint();
                }
            }
        }
    };

    // Separate groups: the producers must finish first, and only then does the
    // main thread close the queue — otherwise `prod_group.await` would wait for
    // a consumer that is still parked.
    var prod_group: Io.Group = .init;
    var cons_group: Io.Group = .init;
    var consumer: Consumer = .{ .queue = &queue, .io = io };
    try cons_group.concurrent(io, Consumer.run, .{&consumer});
    var contexts: [producers]Producer = undefined;
    for (&contexts, 0..) |*context, id| {
        context.* = .{ .queue = &queue, .io = io, .id = @intCast(id) };
        try prod_group.concurrent(io, Producer.run, .{context});
    }

    try prod_group.await(io);
    queue.close(io);
    try cons_group.await(io);

    try testing.expectEqual(@as(usize, producers * lines_per_producer), consumer.seen);
    // Every value arrived and none arrived twice, so the consumer left the ring
    // empty. Its drop counter is not necessarily zero: a retrying producer
    // refuses values that it then re-pushes, and the queue counts a refusal
    // when it happens because it cannot know the caller will retry.
    try testing.expect(!queue.hasWork());
}

test "concurrent producers keep per-producer order and account for every push" {
    // Contention plus loss: producers never retry, so the ring overflows and
    // values are dropped. The test pins both halves of the contract — each
    // producer's values that did arrive are still in sequence order, and every
    // attempt is either seen by the consumer or counted as dropped.
    if (@import("builtin").single_threaded) return error.SkipZigTest;
    const alloc = testing.allocator;

    var threaded: std.Io.Threaded = .init(alloc, .{});
    defer threaded.deinit();
    const io = threaded.io();

    // A ring small enough that a drain loop cannot keep up with four producers.
    const Small = Queue(u32, 16);
    var queue = try Small.init(alloc);
    defer queue.deinit(alloc);

    const attempts = 2000;

    const Consumer = struct {
        queue: *Small,
        io: Io,
        /// Last sequence seen per producer, and whether any of them arrived out
        /// of order. Both are written only by the consumer task and read after
        /// the group join.
        last: [producers]?u32 = @splat(null),
        out_of_order: bool = false,
        seen: usize = 0,

        fn run(self: *@This()) void {
            var batch: [8]u32 = undefined;
            while (true) {
                const wake = self.queue.awaitWork(self.io) catch return;
                if (wake == .closed) return;
                var count = self.queue.popBatch(&batch);
                while (count > 0) {
                    for (batch[0..count]) |value| self.accept(value);
                    count = self.queue.popBatch(&batch);
                }
            }
        }

        fn accept(self: *@This(), value: u32) void {
            const id = value >> 16;
            const sequence = value & 0xffff;
            std.debug.assert(id < producers);
            if (self.last[id]) |previous| {
                if (sequence <= previous) self.out_of_order = true;
            }
            self.last[id] = sequence;
            self.seen += 1;
        }
    };

    const Producer = struct {
        queue: *Small,
        io: Io,
        id: u32,

        fn run(self: *@This()) void {
            var i: u32 = 0;
            while (i < attempts) : (i += 1) {
                // No retry: a refusal is the loss this test accounts for.
                _ = self.queue.tryPush(self.io, self.id << 16 | i);
            }
        }
    };

    var prod_group: Io.Group = .init;
    var cons_group: Io.Group = .init;
    var consumer: Consumer = .{ .queue = &queue, .io = io };
    try cons_group.concurrent(io, Consumer.run, .{&consumer});
    var contexts: [producers]Producer = undefined;
    for (&contexts, 0..) |*context, id| {
        context.* = .{ .queue = &queue, .io = io, .id = @intCast(id) };
        try prod_group.concurrent(io, Producer.run, .{context});
    }

    try prod_group.await(io);
    queue.close(io);
    try cons_group.await(io);

    const dropped: usize = @intCast(queue.droppedCount());
    try testing.expect(consumer.seen > 0);
    // The accounting invariant: a push was either taken by the ring and seen by
    // the consumer exactly once, or refused and counted. No value is both.
    try testing.expectEqual(producers * attempts, consumer.seen + dropped);
    try testing.expect(!consumer.out_of_order);
}
