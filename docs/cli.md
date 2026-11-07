# vlmzsd CLI specification

This document is the authoritative CLI reference for `vlmzsd` (a KMS server: an
emulator of Microsoft's Key Management Service) and `vlmzs` (an activation
client for it).

## 1. Goals and principles

- **Two binaries, one job each.** `vlmzsd` is the server; `vlmzs` is the client.
- **No config file.** Configuration comes exclusively from CLI arguments and
  environment variables.
- **Three-tier precedence, fixed:** built-in default < environment variable <
  CLI argument (see [§3](#3-configuration-precedence)).
- **Discoverable.** `--help` is complete and grouped by concern (the same
  groups as §5–§6); this document adds the environment-variable and default
  columns.
- **Human-friendly types.** Durations and GUIDs are written in readable form,
  not magic numbers.

## 2. Command structure

```
vlmzsd [OPTIONS]                 # KMS server (foreground)
vlmzs [HOST[:PORT]] [OPTIONS]    # activation client
```

Each binary supports `--help` / `-h` and `--version` / `-V`. `vlmzsd` accepts no
positional arguments, and `vlmzs` accepts at most one; anything extra is a
configuration error rather than being ignored.

`vlmzsd` runs the KMS server in the foreground. `vlmzs` sends activation
requests (one by default, `--count` for more) to an existing KMS server. When
`HOST` is omitted, `vlmzs` targets `127.0.0.1` (`::1` with `--address-family 6`).

## 3. Configuration precedence

Every `vlmzsd` option that configures server behaviour has both a CLI flag and an
environment variable (see the tables in [§5](#5-server-vlmzsd-options)). The client is interactive and is
configured entirely through CLI arguments; no `VLMZSD_*` variable applies to it.

Precedence, highest to lowest:

1. CLI argument
2. Environment variable (`VLMZSD_*`)
3. Built-in default

### Environment variable conventions

- Single prefix: `VLMZSD_`, followed by the uppercase snake_case option name
  (e.g. `--activation-interval` → `VLMZSD_ACTIVATION_INTERVAL`).
- Boolean variables accept `1`/`true`/`yes`/`on` and `0`/`false`/`no`/`off`
  (case-insensitive).
- Repeatable options (`--listen`, `--epid`) are comma-separated in their
  environment variable (e.g. `VLMZSD_LISTEN="0.0.0.0,::"`). Segments are
  trimmed, and empty segments are skipped: `VLMZSD_LISTEN="0.0.0.0,,::"` binds
  the same two addresses. A value with no non-empty segment counts as unset, so
  the built-in default applies.
- `VLMZSD_LOG_LEVEL` is the one environment variable with no matching CLI flag:
  it selects the log level directly (see [Logging](#logging)).

## 4. Value syntax

### Duration

`<n><unit>` with unit `s`/`m`/`h`/`d`/`w` (seconds, minutes, hours,
days, weeks). Examples: `30s`, `2h`, `7d`, `90m`. The two policy intervals
(`--activation-interval`, `--renewal-interval`) are stored in whole minutes, so
sub-minute values are rounded down; `0` disables where applicable. A duration
that does not fit the field it feeds (seconds for `--timeout`, minutes for the
policy intervals) is a configuration error, not a truncated value.

### GUID

Standard hyphenated hex: `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx`
(case-insensitive). The text is converted to the serialized order the protocol
uses (Data1/Data2/Data3 little-endian, then the 8-byte tail in string order), so
`--cmid` echoes back exactly what you typed and `--app-id`/`--kms-id` compare
equal to the GUIDs stored in the `.kmd` data.

### ePID override

`--epid <name>=<epid>`, where `<name>` is a CSVLC name from the `.kmd` data
(e.g. `Windows`, `Office2013`) and `<epid>` is the 20-byte ePID string.
Repeatable; comma-separated in the environment variable. A repeated `<name>`
keeps its last ePID.

## 5. Server (`vlmzsd`) options

Grouped by concern (help is rendered in these groups).

### General

| Option | Short | Default | Env var | Notes |
|---|---|---|---|---|
| `--help` | `-h` | | — | print the grouped option list and exit |
| `--version` | `-V` | | — | print the version (with the embedded commit when the build was given `-Dgit-sha`), then exit |

### Network

| Option | Short | Default | Env var | Notes |
|---|---|---|---|---|
| `--port <n>` | `-p` | `1688` | `VLMZSD_PORT` | TCP listen port |
| `--listen <addr>` | `-L` | `::` (dual-stack) | `VLMZSD_LISTEN` | repeatable / comma-separated |
| `--timeout <dur>` | | `30s` | `VLMZSD_TIMEOUT` | idle timeout; `0` disables |
| `--max-clients <n>` | `-m` | `1024` | `VLMZSD_MAX_CLIENTS` | concurrent client cap; `0` = unlimited |

`--listen` takes an **IP literal only**, repeatable to bind several addresses;
the port always comes from `--port`, so `--listen 0.0.0.0:1688` is rejected as an
invalid address. The default `::` is a dual-stack socket covering IPv4 and IPv6,
and falls back to `0.0.0.0` on a host without an IPv6 stack.

`--port 0` asks the kernel for an ephemeral port, which is useful for tests and
side-by-side instances. The startup line reports the port that was actually
bound, and each BIND_ACK advertises the port of the socket the client reached
(the reference reads that from the local socket with `getnameinfo`); with
several listen sockets the log names the first one.

`--max-clients` bounds the number of concurrent client connections, and with it the server's worker
threads: the pool never reclaims an idle thread, so the threads a run holds are the main thread, the
log writer, the shutdown reader, one accept task per `--listen` address, and one worker per client
being served. Connections over the cap are not accepted at all: they wait in the kernel backlog (TCP
backpressure) instead of taking a worker, and one warning is logged per saturation period. A freed
slot wakes the listener again at once — the cap is an admission event, not a polling interval. `0`
removes the cap and is reported as a warning at startup.

Threads are visible in the log rather than only through `ps`. At `-v` every pool thread reports
itself, once, when it is first seen (`debug: pool worker <id> started (pool threads: N)`) and once
more when it first serves a client (`debug: pool worker <id> serving clients (client workers: M, pool
threads: N)`) — a thread usually starts out on an `accept` and is then handed the connection it
accepted, so the second line is what ties a connection to a thread. The id is the OS thread id. The
log writer cannot report itself that early, so its role is announced instead (`debug: log writer task
started`). The shutdown summary reports two different numbers at `info`:

- `peak concurrent clients` — the load: the most clients served at one moment.
- `worker threads: N (M served clients)` — the resource: `N` pool threads, `M` of which have served
  a client. The other `N - M` are the log writer, the shutdown reader, and one `accept` per
  `--listen` address.

`N` is counted rather than derived — each thread reports its own first task — so the process thread
count is exactly `N + 1` (the main thread) and matches what `ps` shows. `M` is the part that scales
with load: equal to the peak under a steady load, a couple higher under rapid connect/close churn,
where the pool rotates through an idle worker while an accept task is re-armed. Neither number grows
with the total number of connections served.

`--timeout` bounds how long a read waits for its peer; `0` disables the idle timeout, so a silent
peer is kept until it disconnects. It never delays shutdown: `SIGINT`/`SIGTERM` ends an idle
connection immediately even with `--timeout 0`, so stopping the server never waits out live clients.
The timeout is held in whole seconds, so a duration above `4294967295s` is rejected as a
configuration error.

### Data

| Option | Short | Default | Env var | Notes |
|---|---|---|---|---|
| `--data <file>` | | embedded | `VLMZSD_DATA` | external `.kmd` file; default is the built-in data |

When `--data` is not given, both binaries search the FHS data directories for a
`.kmd` file, highest priority first. `$XDG_DATA_HOME` is **not** consulted; the
user level is `$HOME/.local/share/vlmzsd`:

1. `$HOME/.local/share/vlmzsd/*.kmd` (user level)
2. `/etc/vlmzsd/*.kmd` (admin override)
3. `/var/lib/vlmzsd/*.kmd` (state data)
4. `/usr/local/share/vlmzsd/*.kmd` (locally installed)
5. `/usr/share/vlmzsd/*.kmd` (distribution-packaged)

Within a directory, the alphabetically greatest `*.kmd` name wins, and only
regular files count — a symlinked `.kmd` is skipped. If no `.kmd` file is found
anywhere, the built-in data is used. Builds that ship without it fail to start
instead, and tell you to point `--data` at a `.kmd` file. A `.kmd` file that is
found but unreadable or invalid is a startup error (exit `1`), not a fallback.
`vlmzsd` logs which file won: `loaded KMS data from <file>` at `info`, or
`using embedded KMS data` at `-v`. `vlmzs` is a bare CLI tool (no timestamped
logger) and reports the file only when it fails to load one.

### ePID

| Option | Short | Default | Env var | Notes |
|---|---|---|---|---|
| `--epid <name>=<epid>` | | — | `VLMZSD_EPID` | repeatable / comma-separated |
| `--randomize <0\|1\|2>` | | `1` | `VLMZSD_RANDOMIZE` | ePID randomization level |
| `--lcid <n>` | | random | `VLMZSD_LCID` | fixed LCID for randomized ePIDs, `0..32767` (`0` = random) |
| `--build <n>` | | random | `VLMZSD_BUILD` | fixed build number for randomized ePIDs, `0..65535` (`0` = random) |

`--randomize` decides which ePID a client receives in the RESPONSE:

| Level | ePID |
|---|---|
| `0` | the static ePID stored in the `.kmd` data |
| `1` (default) | one random ePID per CSVLC, generated at startup and reused for the whole run |
| `2` | a fresh random ePID for every request |

`--lcid`/`--build` pin the LCID and host build the randomized levels use;
unset (`0`) means "pick one at random". A random choice is made once per run at
level `1` (every CSVLC's ePID carries the same LCID and host build) and once per
request at level `2`. The upper bounds (`32767` and `65535`) match what an ePID
can carry; a larger value is rejected as a configuration error rather than
truncated. `--epid` overrides beat every level, and any other `--randomize`
value behaves like `0`.

### Activation policy

| Option | Short | Default | Env var | Notes |
|---|---|---|---|---|
| `--activation-interval <dur>` | | `2h` | `VLMZSD_ACTIVATION_INTERVAL` | VL activation interval |
| `--renewal-interval <dur>` | | `7d` | `VLMZSD_RENEWAL_INTERVAL` | VL renewal interval |
| `--whitelist <0..3>` | | `0` | `VLMZSD_WHITELIST` | whitelisting level |
| `--ip-protection <0..3>` | | `0` | `VLMZSD_IP_PROTECTION` | public-IP protection level |
| `--check-client-time` | | off | `VLMZSD_CHECK_CLIENT_TIME` | validate client timestamp |
| `--maintain-clients` | | off | `VLMZSD_MAINTAIN_CLIENTS` | keep client list across requests |
| `--start-empty` | | off | `VLMZSD_START_EMPTY` | start with empty client list |

`--whitelist` and `--ip-protection` are bit masks: add the levels you want
(`3` = both bits).

- `--whitelist`: `1` rejects a request whose AppID does not match the `.kmd`
  data; `2` rejects retail/preview products.
- `--ip-protection`: `1` listens only on the host's private addresses — it
  replaces `--listen` — and `2` rejects clients whose address is public.
- `--check-client-time` rejects a request whose timestamp differs from the
  server's clock by more than four hours (`0xC004F06C`). The clock is read for
  every request, not once per connection, so a keep-alive client that sends
  requests hours apart is judged against the moment each one arrives.

Bits outside those are ignored, so a value above the documented range is accepted
and behaves like the levels it shares bits with.

Both policy intervals are whole minutes, so a duration whose minute count does
not fit in 32 bits is rejected as a configuration error.

### Protocol

| Option | Short | Default | Env var | Notes |
|---|---|---|---|---|
| `--no-ndr64` | | off | `VLMZSD_NDR64` | disable NDR64 transfer syntax (on by default) |
| `--no-btfn` | | off | `VLMZSD_BTFN` | disable bind-time feature negotiation (on by default) |
| `--disconnect-per-request` | | off | `VLMZSD_DISCONNECT_PER_REQUEST` | disconnect after each request |

### Process

| Option | Short | Default | Env var | Notes |
|---|---|---|---|---|
| `--pid-file <file>` | | — | `VLMZSD_PID_FILE` | write PID to file |
| `--verbose` | `-v` | off | — | increase log verbosity, repeatable |
| `--quiet` | `-q` | off | — | decrease log verbosity, repeatable |
| `--quiet-loopback` | | off | `VLMZSD_QUIET_LOOPBACK` | suppress debug logs from loopback (localhost) clients |

`-v`/`-q` select the log level and `VLMZSD_LOG_LEVEL` sets it directly; see
[Logging](#logging).

`--pid-file` is written once, after the listeners are up, and is **not** removed
on exit; a failure to write it is a warning, not a startup error.

Signals: the first `SIGINT`/`SIGTERM` shuts the server down gracefully — it stops accepting, closes
the live connections, and drains the log before exiting with status `0`. A **second** signal (and any
later one) exits immediately with status `128 + signum` (`130` for `SIGINT`, `143` for `SIGTERM`)
without draining. It is there for the case where the log sink itself is blocked: it prints nothing,
because a write to that sink would block the same way, so the status is the only report. `SIGKILL`
cannot be caught.

Exit status: `0` after a graceful shutdown, and `0` for `--help`/`--version`.
Every startup failure — an unreadable or invalid `.kmd`, no usable `--listen`
address, or an option that does not parse — reports one `error:` line and exits
`1` (an argument error prints `vlmzsd: error: <reason>` without the log
timestamp). A forced exit (second signal) uses `128 + signum` instead.

### Logging

One line per event: a UTC ISO-8601 timestamp (`YYYY-MM-DDTHH:MM:SSZ`), a label,
and the message. Levels, most to least verbose: `trace`, `debug`, `info`
(default), `warn`, `err`. The label is spelled out — `trace:`, `debug:`,
`warning:`, `error:` — and `info` lines carry none:

```
2026-10-13T13:02:01Z vlmzsd 0.5.2 listening on port 1688
2026-10-13T13:02:01Z debug: [::ffff:127.0.0.1]:54336: BIND: negotiated NDR64
2026-10-13T13:02:00Z warning: client cap reached (1024), deferring accept
```

`warn`/`err` are the names used by `-q`, `VLMZSD_LOG_LEVEL`, and the option
tables above; the text they print is `warning`/`error`. `trace`/`debug`/`info`
go to **stdout**, `warn`/`err` to **stderr** (Unix convention). Lines below the
chosen level are dropped before formatting; `err` is never suppressed, while
`warn` is dropped when the level is `err` (`-qq`).

The level is chosen by the repeatable `-v`/`-q` flags (`-v` `debug`, `-vv`+
`trace`; `-q` `warn`, `-qq`+ `err`; any `-q` wins over `-v`), then
`VLMZSD_LOG_LEVEL` (`trace`/`debug`/`info`/`warn`/`err`, case-insensitive). An
unrecognized `VLMZSD_LOG_LEVEL` is ignored with a warning, leaving the level at
the default `info`.

> [!WARNING]
> `VLMZSD_VERBOSE`/`VLMZSD_QUIET` are deprecated. They are still honored as the
> lowest-priority fallback when neither `-v`/`-q` nor `VLMZSD_LOG_LEVEL` is set,
> and the server warns on stderr whenever either is present — subject to the log
> level. Use `VLMZSD_LOG_LEVEL` instead.

This is also the whole feature: output goes to the inherited stdout/stderr and
nothing else happens. No log file, no rotation, no format options —
redirecting, persisting, and shipping the output is the supervisor's job
(systemd/journald, Docker).

Delivery is asynchronous (a bounded queue, one writer task), so a slow consumer
never blocks a worker. Lines can be lost:

- the queue is full → the line is dropped instead of blocking the producer;
- the line is too long → truncated to 256 bytes (timestamp and label included;
  the last byte is always a newline, so the line stays greppable);
- the sink write fails → ignored, so a broken stdout cannot take the server down;
- the exit is forced (second signal, see Signals above) → the drain is skipped.

Drops and truncations are reported on stderr as `warning: logging: dropped N
line(s), truncated M line(s) <scope>`, in two shapes: when the writer has caught
up and is about to wait it reports what that period lost (`since the last
report`), and the final drain reports the run's totals (`in total`). Nothing is
printed while nothing has been lost.

## 6. Client (`vlmzs`) options

| Option | Short | Default | Notes |
|---|---|---|---|
| `HOST[:PORT]` | — | `127.0.0.1` | positional; port defaults to `1688` |
| `--product <name>` | | first SKU | product name or 1-based number; looks up GUIDs from `.kmd` |
| `--data <file>` | | embedded | external `.kmd` file |
| `--protocol <4\|5\|6>` | | from product | KMS protocol version (derived from the selected SKU) |
| `--app-id <guid>` | | from product | override AppID |
| `--sku-id <guid>` | | from product | override SKUID |
| `--kms-id <guid>` | | from product | override KMSID |
| `--cmid <guid>` | `-c` | random | client machine ID |
| `--prev-cmid <guid>` | `-o` | zeroed | previous client machine ID |
| `--workstation <name>` | `-w` | random | workstation name (UTF-8, sent as UTF-16) |
| `--vm` | `-m` | off | present as a virtual machine |
| `--count <n>` | `-n` | `1` | number of requests |
| `--virtual-clients <n>` | `-r` | from product | NCountPolicy override (derived from the selected SKU) |
| `--grace <minutes>` | `-g` | `43200` | grace period minutes (BindingExpiration) |
| `--address-family <4\|6>` | | auto | IPv4/IPv6 selection (IP literals and host names) |
| `--list-products` | `-x` | — | print available products and exit |
| `--license-status <0..6>` | `-t` | `1` | LicenseStatus field |
| `--reconnect-per-request` | `-T` | off | force a new connection per request (default reuses one) |
| `--no-multiplexed` | | off | disable multiplexed RPC (on by default) |
| `--no-ndr64` | | off | disable NDR64 transfer syntax (on by default) |
| `--no-btfn` | | off | disable bind-time feature negotiation (on by default) |
| `--timeout <dur>` | | `30s` | idle timeout; `0` disables |
| `--verbose` | `-v` | off | verbosity |

`--protocol` accepts only `4`, `5`, and `6`, and `--license-status` only
`0..6`; any other value is a configuration error, as is a second positional
argument. `--workstation` must be valid UTF-8: the value is decoded to the
UTF-16 the request field carries (surrogate pairs included) and truncated to 63
code units, so a longer name is cut at a character boundary, never mid-pair.

`--timeout` bounds the BIND reply and every RESPONSE read, so the client fails
instead of blocking forever on a peer that accepted the connection and then went
silent. It does **not** bound the connection attempt: an unreachable host is
bounded only by the kernel's own SYN timeout.

`--reconnect-per-request` opens a new connection per request instead of reusing
one. Requests then run concurrently, roughly one per logical CPU — a request
parked in a read holds a worker — so `--count 600` against a silent peer
completes in waves rather than as 600 threads. Without it, all requests share one
keep-alive connection and are sent sequentially; if the server closes that
connection between requests (a server started with `--disconnect-per-request`),
the client reconnects, re-binds, and sends the request again. The failed attempt
never completed, so nothing is printed for it; a request whose response was lost
after the server processed it would be counted twice by the server, which only
affects its client count.

The client exits `0` when all its requests succeeded, and `1` when one fails or
an option is invalid. A request "fails" when it cannot be sent, when the server
rejects it (for example `0xC004F042` from a whitelist), or when the response
fails verification; the per-request diagnostic goes to stderr, and a final
`<n> of <count> request(s) failed` line summarizes it.
