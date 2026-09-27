//! Probe: is `Io.operateTimeout(.net_receive)` a usable *read path* on `Threaded`,
//! and does it make our hand-rolled `poll` + wake-fd machinery unnecessary?
//!
//!     zig test .github/skills/io-async/scripts/operate_probe.zig
//!
//! Source reading says `Threaded.batchAwaitConcurrent` performs a non-blocking
//! `recv` first and, on `WouldBlock`, polls the socket fd inline on the *calling*
//! thread until the deadline. These five checks test that in behaviour — they are
//! what decides whether the read path should be rewritten on `Operation`:
//!   P1  a silent peer produces `error.Timeout` at the requested deadline
//!   P2  a cancelation request ends a parked wait by itself (no wake fd needed)
//!   P3  no extra thread is consumed (works with a pool of zero workers)
//!   P4  arriving bytes come back as one message over the caller's buffer
//!   P4b what EOF looks like
//!
//! Note: `Io.net.Socket.createPair` is *not* usable on macOS (its default
//! `family = .ip4` socketpair is Linux-only, and it panics with
//! `unexpectedErrno`), so the probe builds a connected TCP pair instead.

const std = @import("std");
const Io = std.Io;
const ms: i96 = 1_000_000;

fn elapsedMs(from: Io.Timestamp, io: Io) i96 {
    return @divTrunc(from.durationTo(Io.Timestamp.now(io, .awake)).nanoseconds, ms);
}

fn durationMs(n: u64) Io.Timeout {
    return .{ .duration = .{ .raw = .{ .nanoseconds = @as(i96, n) * ms }, .clock = .awake } };
}

/// Two ends of one TCP connection, both owned by the test: `accepted` is the end
/// we receive from, `client` is how we make it readable.
const TcpPair = struct {
    server: Io.net.Server,
    accepted: Io.net.Stream,
    client: Io.net.Stream,
    client_open: bool = true,

    fn init(io: Io) !TcpPair {
        const addr = try Io.net.IpAddress.parse("127.0.0.1", 0);
        var server = try Io.net.IpAddress.listen(&addr, io, .{ .mode = .stream });
        errdefer server.deinit(io);
        const client = try Io.net.IpAddress.connect(&server.socket.address, io, .{ .mode = .stream });
        errdefer client.close(io);
        const accepted = try server.accept(io);
        return .{ .server = server, .accepted = accepted, .client = client };
    }

    fn closeClient(self: *TcpPair, io: Io) void {
        if (!self.client_open) return;
        self.client.close(io);
        self.client_open = false;
    }

    fn deinit(self: *TcpPair, io: Io) void {
        self.closeClient(io);
        self.accepted.close(io);
        self.server.deinit(io);
    }

    fn send(self: *TcpPair, io: Io, bytes: []const u8) !void {
        var buffer: [32]u8 = undefined;
        var writer = self.client.writer(io, &buffer);
        try writer.interface.writeAll(bytes);
        try writer.interface.flush();
    }
};

/// One `net_receive` through `operateTimeout`; `messages` must outlive the call
/// because the returned `.data` slices point into `buffer`.
fn receive(
    io: Io,
    sock: Io.net.Socket,
    messages: []Io.net.IncomingMessage,
    buffer: []u8,
    timeout: Io.Timeout,
) Io.OperateTimeoutError!Io.Operation.NetReceive.Result {
    const result = try io.operateTimeout(.{ .net_receive = .{
        .socket_handle = sock.handle,
        .message_buffer = messages,
        .data_buffer = buffer,
        .flags = .{},
    } }, timeout);
    return result.net_receive;
}

fn initMessages(messages: []Io.net.IncomingMessage) void {
    for (messages) |*m| m.* = .{ .from = undefined, .data = undefined, .control = &.{}, .flags = undefined };
}

// P1: the deadline must be the backend's, not ours.
test "operateTimeout reports error.Timeout at the requested deadline" {
    const gpa = std.testing.allocator;
    var threaded: Io.Threaded = .init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var pair = try TcpPair.init(io);
    defer pair.deinit(io);

    var messages: [1]Io.net.IncomingMessage = undefined;
    initMessages(&messages);
    var buffer: [64]u8 = undefined;

    const t0 = Io.Timestamp.now(io, .awake);
    const outcome = receive(io, pair.accepted.socket, &messages, &buffer, durationMs(200));
    const dt = elapsedMs(t0, io);
    std.debug.print("[P1] silent peer: timeout={} after {d} ms (asked 200 ms)\n", .{ outcome == error.Timeout, dt });

    try std.testing.expectError(error.Timeout, outcome);
    try std.testing.expect(dt >= 150 and dt < 800);
}

// P3: a pool with zero workers allowed must still be able to wait — proof the
// wait happens on the calling thread and does not dispatch a task.
test "operateTimeout needs no worker thread" {
    const gpa = std.testing.allocator;
    var threaded: Io.Threaded = .init(gpa, .{ .concurrent_limit = .nothing });
    defer threaded.deinit();
    const io = threaded.io();

    var pair = try TcpPair.init(io);
    defer pair.deinit(io);

    var messages: [1]Io.net.IncomingMessage = undefined;
    initMessages(&messages);
    var buffer: [64]u8 = undefined;

    const t0 = Io.Timestamp.now(io, .awake);
    const outcome = receive(io, pair.accepted.socket, &messages, &buffer, durationMs(200));
    std.debug.print("[P3] pool of zero workers: timeout={} after {d} ms\n", .{ outcome == error.Timeout, elapsedMs(t0, io) });

    // `error.ConcurrencyUnavailable` here would mean it tried to dispatch.
    try std.testing.expectError(error.Timeout, outcome);
}

// P4: usable as a read primitive, over the caller's own buffer.
test "operateTimeout fills the caller's buffer when bytes arrive" {
    const gpa = std.testing.allocator;
    var threaded: Io.Threaded = .init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var pair = try TcpPair.init(io);
    defer pair.deinit(io);

    var messages: [1]Io.net.IncomingMessage = undefined;
    initMessages(&messages);
    var buffer: [64]u8 = undefined;

    try pair.send(io, "abc");
    const outcome = try receive(io, pair.accepted.socket, &messages, &buffer, durationMs(500));
    std.debug.print("[P4] got {d} message(s), first = '{s}' ({d} bytes)\n", .{
        outcome[1], messages[0].data, messages[0].data.len,
    });

    try std.testing.expectEqual(@as(usize, 1), outcome[1]);
    try std.testing.expectEqualStrings("abc", messages[0].data);
}

// P4b: what does EOF look like? (informational — only that it returns.)
test "operateTimeout on a peer that closed" {
    const gpa = std.testing.allocator;
    var threaded: Io.Threaded = .init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var pair = try TcpPair.init(io);
    defer pair.deinit(io);
    pair.closeClient(io); // the peer is gone

    var messages: [1]Io.net.IncomingMessage = undefined;
    initMessages(&messages);
    var buffer: [64]u8 = undefined;

    const t0 = Io.Timestamp.now(io, .awake);
    const outcome = receive(io, pair.accepted.socket, &messages, &buffer, durationMs(300));
    const dt = elapsedMs(t0, io);
    if (outcome) |r| {
        std.debug.print("[P4b] closed peer: {d} message(s), data.len = {d}, after {d} ms\n", .{
            r[1], if (r[1] > 0) messages[0].data.len else @as(usize, 0), dt,
        });
    } else |err| {
        std.debug.print("[P4b] closed peer: error {s} after {d} ms\n", .{ @errorName(err), dt });
    }
    // No assertion on the shape: the point is to record it. It must not hang.
    try std.testing.expect(dt < 1_000);
}

/// A task that parks in an unbounded `net_receive`, to test cancelation.
const Waiter = struct {
    io: Io,
    sock: Io.net.Socket,
    messages: *[1]Io.net.IncomingMessage,
    buffer: *[64]u8,
    outcome: *?Io.OperateTimeoutError!Io.Operation.NetReceive.Result,

    fn run(self: Waiter) Io.Cancelable!void {
        self.outcome.* = receive(self.io, self.sock, self.messages, self.buffer, .none);
    }
};

// P2: cancelation must end the wait on its own — our current code needs a wake fd
// polled alongside precisely because `std.posix.poll` ignores the signal.
test "a cancelation request ends the wait without any wake fd" {
    const gpa = std.testing.allocator;
    var threaded: Io.Threaded = .init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var pair = try TcpPair.init(io);
    defer pair.deinit(io);

    var messages: [1]Io.net.IncomingMessage = undefined;
    initMessages(&messages);
    var buffer: [64]u8 = undefined;
    var outcome: ?Io.OperateTimeoutError!Io.Operation.NetReceive.Result = null;

    var group: Io.Group = .init;
    try group.concurrent(io, Waiter.run, .{Waiter{
        .io = io,
        .sock = pair.accepted.socket,
        .messages = &messages,
        .buffer = &buffer,
        .outcome = &outcome,
    }});

    try io.sleep(.{ .nanoseconds = 100 * ms }, .awake);
    const t0 = Io.Timestamp.now(io, .awake);
    group.cancel(io); // requests cancelation, then blocks until the task returns
    const dt = elapsedMs(t0, io);

    const canceled = outcome != null and outcome.? == error.Canceled;
    std.debug.print("[P2] cancel ended a parked net_receive in {d} ms; task saw Canceled = {}\n", .{ dt, canceled });
    try std.testing.expect(dt < 500);
    try std.testing.expectError(error.Canceled, outcome.?);
}
