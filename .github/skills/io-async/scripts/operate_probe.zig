//! Probe: is `Io.operateTimeout(.net_receive)` a usable *read path* on `Threaded`,
//! and does it make our hand-rolled `poll` + wake-fd machinery unnecessary?
//!
//!     zig test .github/skills/io-async/scripts/operate_probe.zig
//!
//! Source reading says `Threaded.batchAwaitConcurrent` performs a non-blocking
//! `recv` first and, on `WouldBlock`, polls the socket fd inline on the *calling*
//! thread until the deadline. These checks test that in behaviour — they are what
//! decides whether the read path should be rewritten on `Operation`:
//!   P1  a silent peer produces `error.Timeout` at the requested deadline
//!   P2  a cancelation request ends a parked wait by itself (no wake fd needed)
//!   P3  no extra thread is consumed (works with a pool of zero workers)
//!   P4  arriving bytes come back as one message over the caller's buffer
//!   P4b what EOF looks like
//!
//! 0.17 moved the socket *write* path onto `Operation` too (`net_send`, and
//! `net_write` which now backs `Io.Writer`), so P5/P6 check the send side as
//! well. Note the asymmetry found there: the deadline is only honoured while
//! *nothing* can be sent — see P6's comment and the reference file.
//!   P5  `net_send` delivers and reports the message count
//!   P6  `net_write` (header + data + splat) delivers, backing `Io.Writer`
//!
//! Note: `Io.net.Socket.createPair` is *not* usable on either platform — its
//! only families are `.ip4`/`.ip6`, which `socketpair(2)` does not implement
//! (errno 95 on Linux, 102 on macOS, for both families) — so the probe builds a
//! connected TCP pair instead.

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

// P5: the write path is an operation too. `net_send` addresses a message list,
// so it can express a send that `net_receive` alone could not (0.16 had no way
// to name this operation at all).
test "operateTimeout(.net_send) delivers over Threaded" {
    const gpa = std.testing.allocator;
    var threaded: Io.Threaded = .init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var pair = try TcpPair.init(io);
    defer pair.deinit(io);

    // `OutgoingMessage` needs a valid address pointer even on a connected
    // socket, where the kernel ignores it (verified on Linux and macOS).
    const peer = pair.accepted.socket.address;
    var outgoing: [1]Io.net.OutgoingMessage = .{.{
        .address = &peer,
        .data_ptr = "hello".ptr,
        .data_len = "hello".len,
    }};

    const t0 = Io.Timestamp.now(io, .awake);
    const sent = try io.operateTimeout(.{ .net_send = .{
        .socket_handle = pair.client.socket.handle,
        .messages = &outgoing,
        .flags = .{},
    } }, durationMs(500));
    const dt = elapsedMs(t0, io);
    std.debug.print("[P5] net_send -> err={any} messages={d} bytes={d} after {d} ms\n", .{
        sent.net_send[0], sent.net_send[1], outgoing[0].data_len, dt,
    });

    // `sent` is a *message* count; per-message progress is `data_len`, which the
    // backend rewrites to the bytes actually accepted (partial sends are legal).
    try std.testing.expect(sent.net_send[0] == null);
    try std.testing.expectEqual(@as(usize, 1), sent.net_send[1]);
    try std.testing.expectEqualStrings("hello", outgoing[0].data_ptr[0..outgoing[0].data_len]);

    var messages: [1]Io.net.IncomingMessage = undefined;
    initMessages(&messages);
    var buffer: [64]u8 = undefined;
    const got = try receive(io, pair.accepted.socket, &messages, &buffer, durationMs(500));
    try std.testing.expectEqual(@as(usize, 1), got[1]);
    try std.testing.expectEqualStrings("hello", messages[0].data);
}

// P6: `Io.net.Stream.Writer` flushes through this exact operation (0.17 gained
// `io.operate(.{ .net_write = ... })` inside `net.zig`), so the shape checked
// here is the one every buffered write on a stream socket takes.
//
// Only the *unblocked* case is asserted. The blocked case is a trap this probe
// must not enter: `batchAwaitConcurrent` re-runs the operation **blocking** once
// `poll` reports the fd ready (`Io/Threaded.zig` poll loop), and `POLLOUT` only
// promises that *some* bytes fit — never that the whole message does. Measured by
// hand: 8 MiB to a peer that never reads, 200 ms deadline. macOS blocked in
// `sendmsg` for 40 s and counting (`sample`: batchAwaitConcurrent -> netSendPosix
// -> __sendmsg); Linux returned after 0 ms with a partial count instead. The
// post-poll blocking retry is the shared mechanism, so chunk your sends on both.
test "operateTimeout(.net_write) delivers header + data over Threaded" {
    const gpa = std.testing.allocator;
    var threaded: Io.Threaded = .init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var pair = try TcpPair.init(io);
    defer pair.deinit(io);

    const t0 = Io.Timestamp.now(io, .awake);
    const wrote = try io.operateTimeout(.{ .net_write = .{
        .socket_handle = pair.client.socket.handle,
        .header = "H:",
        .data = &.{"body"},
        .splat = 1,
        .control = &.{},
    } }, durationMs(500));
    const n = try wrote.net_write;
    const dt = elapsedMs(t0, io);
    std.debug.print("[P6] net_write -> {d} bytes after {d} ms\n", .{ n, dt });

    try std.testing.expectEqual(@as(usize, "H:body".len), n);

    var messages: [1]Io.net.IncomingMessage = undefined;
    initMessages(&messages);
    var buffer: [64]u8 = undefined;
    const got = try receive(io, pair.accepted.socket, &messages, &buffer, durationMs(500));
    std.debug.print("[P6] peer received '{s}' ({d} msg)\n", .{ messages[0].data, got[1] });
    try std.testing.expectEqualStrings("H:body", messages[0].data);
}
