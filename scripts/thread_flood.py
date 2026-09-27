#!/usr/bin/env python3
"""Drive a vlmzsd server's thread pool to its high-water mark.

Why this works
--------------
`vlmzsd` dispatches one `Io.Group.concurrent` task per accepted connection onto
the `std.Io.Threaded` pool. The pool spawns a fresh thread whenever a task is
dispatched and no pool thread happens to be idle, and a worker thread only exits
at `Threaded.deinit` — never while the process lives. So the process's thread
count equals the **peak** number of simultaneously open connections (+2: the
accept loop and the log writer), and it never shrinks again (see
docs/migration.md -> Concurrency).

A connection needs to send nothing: the task blocks in the first packet read
immediately after `accept`, so an idle socket already occupies one thread. This
script therefore just keeps N sockets open at once and reconnects whenever the
server drops one (e.g. on its idle `--timeout`), optionally ramping N up until a
limit is hit.

Usage:
    thread_flood.py [HOST[:PORT]] [--connections N] [--duration SEC]
                    [--ramp] [--max N] [--step N] [--step-seconds SEC] [--quiet]

Watch the server's thread count while it runs (1s interval):
    watch -n1 "ls /proc/\\$(pidof vlmzsd)/task | wc -l"          # same host/ctr
    podman exec <ctr> sh -c 'ls /proc/$(pidof vlmzsd)/task | wc -l'

Reading the result:
    * thread count ≈ peak connections + 2, and it stays after this script exits;
    * a plateau at N+2 means the server caps clients (`--max-clients N`);
    * connect storms that get closed immediately mean the server is refusing to
      dispatch ("failed to dispatch client task" in its log) — its thread/pids
      limit is reached.

Only point this at a server you own: it is a connection flood by design, and the
threads it creates live until that server restarts.
"""

import errno
import resource
import select
import socket
import sys
import time

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 1688
FD_TARGET = 65536


def parse_target(text):
    if ":" in text and not text.startswith("["):
        host, _, port = text.rpartition(":")
        return host, int(port)
    if text.startswith("["):  # "[::1]:1688"
        host, _, rest = text.partition("]")
        return host[1:], int(rest[1:]) if rest.startswith(":") else DEFAULT_PORT
    return text, DEFAULT_PORT


def raise_fd_limit():
    """Best effort: lift RLIMIT_NOFILE so several thousand sockets fit."""
    soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    if hard == resource.RLIM_INFINITY:
        want = FD_TARGET
    else:
        want = min(FD_TARGET, hard)
    if want > soft:
        try:
            resource.setrlimit(resource.RLIMIT_NOFILE, (want, hard))
        except (ValueError, OSError):
            pass
    return resource.getrlimit(resource.RLIMIT_NOFILE)[0]


def open_one(family, address, timeout=3.0):
    """One blocking connect. No data is ever sent: idleness is the point."""
    sock = socket.socket(family, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect(address)
    except OSError:
        sock.close()
        raise
    sock.setblocking(False)
    return sock


class Flood:
    def __init__(self, host, port):
        self.address = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)[0]
        self.family, _, _, _, self.sockaddr = self.address
        self.open = {}  # fd -> socket
        self.poller = select.poll()
        self.peaks = 0
        self.opened = 0
        self.reconnects = 0
        self.failures = 0
        self.fd_limit = raise_fd_limit()
        self.warned = set()

    def warn_once(self, key, message):
        if key not in self.warned:
            self.warned.add(key)
            print(f"  ! {message}", flush=True)

    def connect_more(self, target):
        """Top up to `target` open connections; returns False when capped."""
        room = min(target, self.fd_limit - 16)
        while len(self.open) < room:
            try:
                sock = open_one(self.family, self.sockaddr)
            except OSError as err:
                self.failures += 1
                if err.errno in (errno.EMFILE, errno.ENFILE):
                    self.warn_once("fd", f"out of file descriptors ({self.fd_limit}); see `ulimit -n`")
                    return False
                if err.errno == errno.ECONNREFUSED:
                    self.warn_once("refused", "connection refused — server gone or listen backlog full")
                    time.sleep(0.05)
                    return False
                if err.errno in (errno.EADDRINUSE, errno.EADDRNOTAVAIL):
                    self.warn_once("ports", "out of local ephemeral ports (single source IP limit)")
                    return False
                self.warn_once("econn", f"connect failed: {err}")
                return False
            self.open[sock.fileno()] = sock
            self.poller.register(sock, select.POLLIN)
            self.opened += 1
        return True

    def reap(self, events):
        """Drop closed/broken sockets so they can be replaced."""
        for fd, _ in events:
            sock = self.open.get(fd)
            if sock is None:
                continue
            try:
                # The server sends nothing unless we do, so readable == closed.
                if sock.recv(1) == b"":
                    self.drop(fd)
                    self.reconnects += 1
            except BlockingIOError:
                continue  # spurious wakeup
            except OSError:
                self.drop(fd)
                self.reconnects += 1

    def drop(self, fd):
        sock = self.open.pop(fd, None)
        if sock is not None:
            self.poller.unregister(sock)
            sock.close()

    def close(self):
        for fd in list(self.open):
            self.drop(fd)


def main(argv):
    host, port = DEFAULT_HOST, DEFAULT_PORT
    target = 256
    duration = 30.0
    ramp = False
    maximum = 8192
    step = 64
    step_seconds = 2.0
    quiet = False

    args = list(argv)
    positional = []
    i = 0
    while i < len(args):
        arg = args[i]
        if arg in ("-h", "--help"):
            print(__doc__.strip())
            return 0
        elif arg == "--connections":
            i += 1
            target = int(args[i])
        elif arg == "--duration":
            i += 1
            duration = float(args[i])
        elif arg == "--ramp":
            ramp = True
        elif arg == "--max":
            i += 1
            maximum = int(args[i])
        elif arg == "--step":
            i += 1
            step = int(args[i])
        elif arg == "--step-seconds":
            i += 1
            step_seconds = float(args[i])
        elif arg == "--quiet":
            quiet = True
        elif arg.startswith("-"):
            print(f"unknown option: {arg}", file=sys.stderr)
            return 2
        else:
            positional.append(arg)
        i += 1

    if positional:
        host, port = parse_target(positional[0])

    flood = Flood(host, port)
    print(f"flooding {host}:{port} — target {target} open connections"
          f"{', ramping to %d' % maximum if ramp else ''}"
          f" for {duration:.0f}s (fd limit {flood.fd_limit})", flush=True)

    started = time.monotonic()
    next_step = started + step_seconds
    next_report = started
    flood.connect_more(target)

    try:
        while time.monotonic() - started < duration:
            events = flood.poller.poll(200)
            flood.reap(events)
            if flood.open:
                flood.peaks = max(flood.peaks, len(flood.open))
            flood.connect_more(target)

            now = time.monotonic()
            if ramp and now >= next_step and target < maximum:
                target = min(maximum, target + step)
                next_step = now + step_seconds
            if not quiet and now >= next_report:
                next_report = now + 1.0
                print(f"  t={now - started:5.0f}s  open={len(flood.open):5d}"
                      f"  peak={flood.peaks:5d}  opened={flood.opened:6d}"
                      f"  reconnect={flood.reconnects:6d}  fail={flood.failures:5d}",
                      flush=True)
            # A capped server (--max-clients) accepts into the kernel backlog and
            # dispatches only N at a time, so the extra connects either sit there
            # or come back reset. Say so rather than leaving the numbers a riddle.
            if flood.failures >= max(64, target // 4):
                flood.warn_once(
                    "refused",
                    f"{flood.failures} connect failures — the server is likely at its client "
                    f"cap (--max-clients), or its listen backlog / pids limit is full",
                )
    except KeyboardInterrupt:
        print("  interrupted", flush=True)
    finally:
        open_now = len(flood.open)
        flood.close()

    print(f"done: peak {flood.peaks} simultaneous connections, "
          f"{flood.opened} opened, {flood.reconnects} reconnects, {flood.failures} failures", flush=True)
    print(f"left open at exit: {open_now}  (sockets closed, but the server's thread count stays "
          f"at ~{flood.peaks + 2} until it restarts)", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
