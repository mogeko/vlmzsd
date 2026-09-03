# vlmzsd CLI specification

This document is the authoritative CLI design for the `vlmzsd` (KMS server) and
`vlmzs` (activation client) binaries, replacing the C `vlmcsd` / `vlmcs`
getopt + INI surface. Implementation lives in `src/main.zig` and `src/vlmzs.zig`; 
this file is the spec they must follow.

## 1. Goals and principles

- **Two binaries, one job each.** `vlmzsd` is the KMS server; `vlmzs` is the
  activation client (mirroring the C `vlmcsd` / `vlmcs` split).
- **No config file.** Configuration comes exclusively from CLI arguments and
  environment variables. There is no INI/TOML/YAML config surface.
- **Three-tier precedence, fixed:** built-in default < environment variable <
  CLI argument. This is not a convention — it follows from the two use cases:
  the server's configuration is static and comes from the deployment
  environment (Docker/systemd), the client's configuration is dynamic and
  comes from each invocation.
- **Discoverable.** `--help` is complete and grouped by concern; every default
  value is shown. No single-letter getopt soup.
- **Human-friendly types.** Durations and GUIDs are written in readable form,
  not magic numbers.

## 2. Command structure

```
vlmzsd [OPTIONS]                 # KMS server (foreground)
vlmzs HOST[:PORT] [OPTIONS]      # activation client
```

Each binary supports `--help` / `-h` and `--version` / `-V`.

`vlmzsd` runs the KMS server in the foreground. `vlmzs` sends one activation
request to an existing KMS server.

## 3. Configuration precedence

Every `vlmzsd` option is settable via CLI and via an environment variable. The
client is interactive and is configured almost entirely through CLI arguments
(environment variables are not defined for `vlmzs`).

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
  environment variable (e.g. `VLMZSD_LISTEN="0.0.0.0,::"`).

## 4. Value syntax

### Duration

`<n><unit>` with unit `s`/`m`/`h`/`d`/`w` (seconds, minutes, hours, days,
weeks). Examples: `30s`, `2h`, `7d`, `90m`. Internally converted to minutes for
the KMS protocol (the protocol's native unit); `0` disables where applicable.

### GUID

Standard hyphenated hex: `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx`
(case-insensitive).

### ePID override

`--epid <name>=<epid>`, where `<name>` is a CSVLC name from the `.kmd` data
(e.g. `Windows`, `Office2013`) and `<epid>` is the 20-byte ePID string.
Repeatable; comma-separated in the environment variable.

> Requires `kmsdata.zig` to expose the CSVLC name (the string immediately
> following the ePID string in the `.kmd` string pool) — tracked as a
> prerequisite for Phase 6.

## 5. Server (`vlmzsd`) options

Grouped by concern (help is rendered in these groups).

### Network

| Option | Short | Default | Env var | Notes |
|---|---|---|---|---|
| `--port <n>` | `-p` | `1688` | `VLMZSD_PORT` | TCP listen port |
| `--listen <addr>` | `-L` | `0.0.0.0` | `VLMZSD_LISTEN` | repeatable / comma-separated |
| `--timeout <dur>` | | `30s` | `VLMZSD_TIMEOUT` | idle timeout; `0` disables |
| `--max-clients <n>` | `-m` | unlimited | `VLMZSD_MAX_CLIENTS` | concurrent client cap |

### Data

| Option | Short | Default | Env var | Notes |
|---|---|---|---|---|
| `--data <file>` | | embedded | `VLMZSD_DATA` | external `.kmd` file; default is the `@embedFile`d data |

### ePID

| Option | Short | Default | Env var | Notes |
|---|---|---|---|---|
| `--epid <name>=<epid>` | | — | `VLMZSD_EPID` | repeatable / comma-separated |
| `--randomize <0\|1\|2>` | | `1` | `VLMZSD_RANDOMIZE` | ePID randomization level |
| `--lcid <n>` | | — | `VLMZSD_LCID` | fixed LCID for randomized ePIDs |
| `--build <n>` | | — | `VLMZSD_BUILD` | fixed build number for randomized ePIDs |

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

### Protocol

| Option | Short | Default | Env var | Notes |
|---|---|---|---|---|
| `--no-ndr64` | | on | `VLMZSD_NDR64` | disable NDR64 transfer syntax |
| `--no-btfn` | | on | `VLMZSD_BTFN` | disable bind-time feature negotiation |
| `--disconnect-per-request` | | off | `VLMZSD_DISCONNECT_PER_REQUEST` | disconnect after each request |

### Process

| Option | Short | Default | Env var | Notes |
|---|---|---|---|---|
| `--pid-file <file>` | | — | `VLMZSD_PID_FILE` | write PID to file |
| `--verbose` / `--quiet` | `-v` / `-q` | off | `VLMZSD_VERBOSE` | verbosity of stdout logging |

### Logging

Logging has **no CLI surface**. Output is a **fixed format** written to
**stdout** only; there is no `--log`, `--log-timestamp`, or log-level flag.
Redirecting/persisting logs is the job of the supervisor (systemd/journald,
Docker). This is a deliberate simplification of the C `-l`/`-T`/`-e` options.

## 6. Client (`vlmzs`) options

| Option | Short | Default | Notes |
|---|---|---|---|
| `HOST[:PORT]` | — | `127.0.0.1` | positional; port defaults to `1688` |
| `--product <name>` | | `Windows` | look up GUIDs from `.kmd` |
| `--protocol <4\|5\|6>` | | `6` | KMS protocol version |
| `--app-id <guid>` | | from product | override AppID |
| `--sku-id <guid>` | | from product | override SKUID |
| `--kms-id <guid>` | | from product | override KMSID |
| `--cmid <guid>` | `-c` | random | client machine ID |
| `--prev-cmid <guid>` | `-o` | zeroed | previous client machine ID |
| `--workstation <name>` | `-w` | host name | workstation name |
| `--vm` | `-m` | off | present as a virtual machine |
| `--count <n>` | `-n` | `1` | number of requests |
| `--virtual-clients <n>` | `-r` | `1` | NCountPolicy |
| `--grace <minutes>` | `-g` | `43200` | grace period minutes (BindingExpiration) |
| `--address-family <4\|6>` | | auto | IPv4/IPv6 selection (IP literals and host names) |
| `--list-products` | `-x` | — | print available products and exit |
| `--license-status <0..6>` | `-t` | `1` | LicenseStatus field |
| `--reconnect-per-request` | `-T` | off | reconnect for each request |
| `--no-multiplexed` | | on | disable multiplexed RPC |
| `--no-ndr64` | | on | disable NDR64 transfer syntax |
| `--no-btfn` | | on | disable bind-time feature negotiation |
| `--verbose` | `-v` | off | verbosity |

### Deferred client options

These depend on DNS SRV support (`dns_srv.c`), which is not part of the current
migration surface. They will be added when DNS SRV is implemented:

| Option | C equivalent | Notes |
|---|---|---|
| `--no-dns` | `-d` | do not resolve SRV records |
| `--no-srv-priority` | `-P` | ignore SRV record priority |

## 7. Dropped C options

The following C surface is intentionally **not** carried over, with rationale:

| C option(s) | Rationale |
|---|---|
| `-i <file>` (INI), client `-G`/`-l` (INI) | no config file by design |
| `-u`/`-g` (setuid/setgid) | deployment concern (systemd `User=`/`Group=`) |
| `-s`/`-S`/`-U`/`-W` (NT service) | Windows-only; out of scope for macOS/Linux first |
| `-F0`/`-F1` (freebind) | exotic; revisit if requested |
| `-x <level>` (exit-on-warning) | removed; warnings never terminate the server |
| `-O <vpn>` (TAP adapter) | Windows/OpenVPN-specific; out of scope |
| `-l syslog\|<file>`, `-T0`/`-T1` | logging is fixed-format stdout; supervisor handles files |
| `-e` (log to stdout) | stdout is the only destination, so redundant |
| `-Z` (SIGHUP restart) | internal; re-add only if signal handling is needed |

## 8. Implementation decisions

- **Argument parsing: `zig-clap`** (Hejsil/zig-clap), the closest thing Zig has
  to a community-standard CLI library (à la Rust `clap`): short/long options,
  repeatable options, `--opt=value`, and automatic help generation. It is the
  project's first external dependency (added to `build.zig.zon`). The
  three-tier env-var precedence is implemented as a thin layer on top of
  zig-clap's parsed result — it is independent of the parser choice.
- **Two entry points share one module.** `src/main.zig` (`vlmzsd`) and
  `src/vlmzs.zig` (`vlmzs`) both import the `vlmzsd` module; argument parsing
  and option-to-config mapping live in shared code (e.g. `src/cli_helper.zig`).
- **Logging: no external library.** Zig has no community-standard log library,
  and `std.log` does not match the "fixed format → stdout" requirement. Logging
  is a small hand-written helper (~20 lines) writing a fixed format to stdout.
- **Version pinning risk:** zig-clap's `master` tracks Zig master; when adding
  the dependency, pin the release tag that supports Zig `0.16.0`.
