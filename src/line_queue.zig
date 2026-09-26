//! Bounded multi-producer / single-consumer FIFO of fixed-size log lines.
//!
//! Producers (worker threads and the accept loop) must never block on logging,
//! so the queue is deliberately *lossy*: when every slot is in use `tryPush`
//! refuses the line and the caller counts the drop. The single consumer (the
//! logger's writer thread) drains the queue in arrival order and parks on an
//! `Io.Event` while it is empty. All slots are allocated once at startup, so
//! the steady state performs no heap allocation.
//!
//! Internal to the `vlmzsd`/`vlmzs` binaries: not part of the public API
//! (see `docs/library.md`).

const std = @import("std");
const builtin = @import("builtin");
const Io = std.Io;

const Allocator = std.mem.Allocator;

/// Maximum line length in bytes, including the trailing newline.
pub const slot_size = 256;

/// Number of slots. A power of two so the ring index is a mask.
pub const capacity = 1024;

comptime {
    std.debug.assert(std.math.isPowerOfTwo(capacity));
    std.debug.assert(slot_size >= 2);
}

/// One queued line. `err` selects the destination stream (stderr when set,
/// stdout otherwise), which keeps the queue ignorant of log levels and streams.
pub const Slot = struct {
    err: bool,
    /// Length of the valid prefix of `bytes`; at most `slot_size`.
    len: u16,
    bytes: [slot_size]u8,
};

pub const LineQueue = struct {
    slots: []Slot,
    /// Guards `slots`, `head` and `len`. Only ever held across a memory copy,
    /// never across a syscall — that is what keeps the producer path cheap.
    mutex: Io.Mutex = .init,
    /// Latched after a push; reset by the consumer before it re-tests for work.
    /// See the `reset` ordering note in `Logger.runWriter`.
    event: Io.Event = .unset,
    /// Set by `close`. Producers stop pushing; the consumer drains then exits.
    closed: std.atomic.Value(bool) = .init(false),
    /// Ring cursor of the oldest entry; always `0 <= head < capacity`.
    head: usize = 0,
    /// Number of queued entries; always `0 <= len <= capacity`.
    len: usize = 0,

    /// Allocate the ring once, before any producer starts.
    pub fn init(gpa: Allocator) Allocator.Error!LineQueue {
        return .{ .slots = try gpa.alloc(Slot, capacity) };
    }

    /// Release the ring. Only valid after the consumer has stopped.
    pub fn deinit(self: *LineQueue, gpa: Allocator) void {
        std.debug.assert(self.slots.len == capacity);
        gpa.free(self.slots);
    }

    /// Append one line. Returns `false` when the queue is full or closed, in
    /// which case the caller counts a drop; never blocks, never allocates.
    pub fn tryPush(self: *LineQueue, io: Io, bytes: []const u8, err: bool) bool {
        std.debug.assert(bytes.len > 0);
        std.debug.assert(bytes.len <= slot_size);
        if (self.closed.load(.acquire)) return false;

        self.mutex.lockUncancelable(io);
        const pushed = self.len < capacity;
        if (pushed) {
            const slot = &self.slots[(self.head + self.len) & (capacity - 1)];
            slot.err = err;
            slot.len = @intCast(bytes.len);
            @memcpy(slot.bytes[0..bytes.len], bytes);
            self.len += 1;
        }
        self.mutex.unlock(io);
        if (!pushed) return false;

        // Wake outside the lock: `Event.set` raises a futex syscall when the
        // consumer is parked, and the lock must only cover the copy.
        self.event.set(io);
        return true;
    }

    /// Copy out up to `dst.len` lines in arrival order; returns the count.
    pub fn popBatch(self: *LineQueue, io: Io, dst: []Slot) usize {
        std.debug.assert(dst.len > 0);
        self.mutex.lockUncancelable(io);
        defer self.mutex.unlock(io);
        const count = @min(dst.len, self.len);
        for (dst[0..count]) |*out| {
            const slot = &self.slots[self.head];
            out.err = slot.err;
            out.len = slot.len;
            @memcpy(out.bytes[0..slot.len], slot.bytes[0..slot.len]);
            self.head = (self.head + 1) & (capacity - 1);
        }
        self.len -= count;
        return count;
    }

    /// Park until a line arrives. Returns immediately when one is already
    /// queued or the queue is closed. Cancelable so shutdown can stop the
    /// consumer.
    pub fn waitForWork(self: *LineQueue, io: Io) Io.Cancelable!void {
        return self.event.wait(io);
    }

    /// Refuse further pushes and wake the consumer so it can drain and exit.
    /// Call only after every producer has stopped.
    pub fn close(self: *LineQueue, io: Io) void {
        self.closed.store(true, .release);
        self.event.set(io);
    }

    pub fn isClosed(self: *const LineQueue) bool {
        return self.closed.load(.acquire);
    }
};

const testing = std.testing;

/// Counts for the concurrency test; the total stays under `capacity` so its
/// producers never have to drop and the test can assert an exact line count.
const producers = 4;
const lines_per_producer = 200;

// The queue's contract is pinned here in isolation from the logger: arrival
// order (FIFO), the lossy full-queue path, close/drain semantics, and the
// `reset`-before-emptiness-check order that prevents a lost wakeup. All but
// the last case drive the queue directly on the test thread.
test "push and pop preserve arrival order" {
    const alloc = testing.allocator;
    const io = testing.io;
    var queue = try LineQueue.init(alloc);
    defer queue.deinit(alloc);

    try testing.expect(queue.tryPush(io, "first\n", false));
    try testing.expect(queue.tryPush(io, "second\n", true));

    var batch: [4]Slot = undefined;
    try testing.expectEqual(@as(usize, 2), queue.popBatch(io, &batch));
    try testing.expectEqualStrings("first\n", batch[0].bytes[0..batch[0].len]);
    try testing.expect(!batch[0].err);
    try testing.expectEqualStrings("second\n", batch[1].bytes[0..batch[1].len]);
    try testing.expect(batch[1].err);
    try testing.expectEqual(@as(usize, 0), queue.popBatch(io, &batch));
    try testing.expectEqual(@as(usize, 0), queue.len);
}

test "a full queue refuses pushes instead of blocking" {
    const alloc = testing.allocator;
    const io = testing.io;
    var queue = try LineQueue.init(alloc);
    defer queue.deinit(alloc);

    var i: usize = 0;
    while (i < capacity) : (i += 1) {
        try testing.expect(queue.tryPush(io, "x\n", false));
    }
    try testing.expect(!queue.tryPush(io, "overflow\n", false));
    try testing.expectEqual(@as(usize, capacity), queue.len);

    // Draining frees capacity again, and the ring wraps without corruption.
    var batch: [4]Slot = undefined;
    try testing.expectEqual(@as(usize, 4), queue.popBatch(io, &batch));
    try testing.expect(queue.tryPush(io, "y\n", false));
    try testing.expectEqual(@as(usize, capacity - 3), queue.len);
    try testing.expectEqualStrings("y\n", queue.slots[(queue.head + queue.len - 1) & (capacity - 1)].bytes[0..2]);
}

test "close stops pushes and makes waitForWork return" {
    const alloc = testing.allocator;
    const io = testing.io;
    var queue = try LineQueue.init(alloc);
    defer queue.deinit(alloc);

    var batch: [4]Slot = undefined;
    queue.close(io);
    try testing.expect(queue.isClosed());
    try testing.expect(!queue.tryPush(io, "late\n", false));
    // The event is latched by `close`, so the consumer must not park.
    try queue.waitForWork(io);
    try testing.expectEqual(@as(usize, 0), queue.popBatch(io, &batch));
}

test "a push after reset keeps the event latched" {
    // Guards the `reset` -> pop -> wait order used by the writer loop: if the
    // consumer reset the event *after* finding the queue empty, this push would
    // be cleared and the consumer would park with work still queued.
    const alloc = testing.allocator;
    const io = testing.io;
    var queue = try LineQueue.init(alloc);
    defer queue.deinit(alloc);

    var batch: [4]Slot = undefined;
    queue.event.reset();
    try testing.expectEqual(@as(usize, 0), queue.popBatch(io, &batch));
    try testing.expect(!queue.event.isSet());

    try testing.expect(queue.tryPush(io, "late\n", false));
    try testing.expect(queue.event.isSet());
    try queue.waitForWork(io); // Must not park: the event is still latched.
    try testing.expectEqual(@as(usize, 1), queue.popBatch(io, &batch));
}

test "concurrent producers keep per-producer order" {
    if (builtin.single_threaded) return error.SkipZigTest;
    const alloc = testing.allocator;

    var threaded: std.Io.Threaded = .init(alloc, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var queue = try LineQueue.init(alloc);
    defer queue.deinit(alloc);

    const Producer = struct {
        queue: *LineQueue,
        io: Io,
        id: u8,

        fn run(self: *@This()) void {
            var line: [slot_size]u8 = undefined;
            var i: usize = 0;
            while (i < lines_per_producer) : (i += 1) {
                const bytes = std.fmt.bufPrint(&line, "{d}:{d}\n", .{ self.id, i }) catch unreachable;
                // Retry instead of dropping: the producers together stay under
                // `capacity`, so this terminates.
                while (!self.queue.tryPush(self.io, bytes, false)) std.atomic.spinLoopHint();
            }
        }
    };

    var group: Io.Group = .init;
    var contexts: [producers]Producer = undefined;
    for (&contexts, 0..) |*context, id| {
        context.* = .{ .queue = &queue, .io = io, .id = @intCast(id) };
        try group.concurrent(io, Producer.run, .{context});
    }
    try group.await(io);

    // Each producer's lines must be observed in increasing sequence order;
    // that is what pins FIFO arrival order under contention.
    var next: [producers]usize = [_]usize{0} ** producers;
    var batch: [16]Slot = undefined;
    var total: usize = 0;
    while (true) {
        const count = queue.popBatch(io, &batch);
        if (count == 0) break;
        for (batch[0..count]) |slot| {
            const text = std.mem.trimRight(u8, slot.bytes[0..slot.len], "\n");
            var parts = std.mem.splitScalar(u8, text, ':');
            const id = std.fmt.parseInt(usize, parts.next().?, 10) catch unreachable;
            const sequence = std.fmt.parseInt(usize, parts.next().?, 10) catch unreachable;
            try testing.expectEqual(next[id], sequence);
            next[id] += 1;
            total += 1;
        }
    }
    try testing.expectEqual(@as(usize, producers * lines_per_producer), total);
}
