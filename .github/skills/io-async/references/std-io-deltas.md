# `std.Io` version deltas

History layer for the `io-async` skill. [std-io-0.17.md](./std-io-0.17.md) describes **only** the
release this project builds against; everything historical — what a release changed, and what the
change broke — lives here, so a re-verification does not have to re-diff two toolchains by hand first.

Method behind each entry: diff the corresponding sources of the two releases (`Io.zig`,
`Io/Threaded.zig`, `Io/Semaphore.zig`, `Io/RwLock.zig`, `Io/net.zig`, plus the backend files when a
vtable is involved), then re-run [select_probe.zig](../scripts/select_probe.zig) and
[operate_probe.zig](../scripts/operate_probe.zig) on the newer toolchain. The older release's sources
are fetched from Codeberg, e.g. `https://codeberg.org/ziglang/zig/raw/tag/0.16.0/lib/std/Io.zig` — the
GitHub mirror 404s on `lib/std/Io.zig` for the `0.16.0` tag and has no `v0.16.0` tag.

## 0.17.0 ← 0.16.0

`std-io-0.17.md` was first verified against 0.16.0 and then re-checked claim by claim. These are the
only deltas that touch anything it states:

| Change | Detail |
|---|---|
| Socket writes became operations | `net_send` / `net_read` / `net_write` joined `Operation`; the matching `netSend` / `netRead` / `netWrite` **vtable entries were deleted**, and `Stream.Reader` / `Stream.Writer` were re-pointed at the operations. This is what invalidated the old "no send variant" note. |
| `netWriteFile` stopped panicking | `Threaded`'s `sendFile` backing entry now returns `error.Unimplemented` instead of `@panic("TODO implement")`. |
| Process entries merged | `processReplacePath` / `processSpawnPath` left `Io.VTable` (the path-vs-handle split is now inside `ReplaceOptions.exe` / `SpawnOptions.exe`) and `inheritParentDir` / `inheritParentFile` arrived: **109 → 106 fields**. `Threaded` and `failing` follow that; the three evented backends do not — see below. |
| Two `waitTimeout`s added | `Io.Semaphore.waitTimeout` and `Io.Condition.waitTimeout`, both `Cancelable \|\| error{Timeout}`. |
| `RwLock` internal fixes | `tryLock` and the cancelation path of `lockShared` no longer race; the public API is unchanged. |
| Everything else unchanged | `Select`, `Queue`, `Mutex`, `Event`, `RwLock`, the futex wrappers, `Clock` / `Timeout` / `Timestamp.durationTo`, `Future` / `Group`, `checkCancel` / `recancel` / `CancelProtection`, `Limit`, the vtable's task half, `Threaded.InitOptions` and `setAsyncLimit`. The only additions seen were small helpers (`Limit.toInt64`, `Timestamp.compare`). |

### Evented backends were left behind

Diffing each backend's `io()` vtable literal against both releases shows what the release reshaped and
what it did not:

| Backend | vtable entries, 0.16 → 0.17 | names the 0.17 `Io.VTable` no longer has | 0.17 fields it never wires |
|---|---|---|---|
| `Io.Dispatch` | 109 → 106 | `processReplacePath`, `processSpawnPath` | `inheritParentDir`, `inheritParentFile` |
| `Io.Uring` | 109 → 106 | same two | same two |
| `Io.Kqueue` | 43 → 41 | `fileWriteStreaming`, `fileReadStreaming`, `netRead`, `netSend`, `netReceive` | 70 of 106 |

All three were edited for the streaming half of the change — each dropped the entries that became
operations — and none for the process half, which is why they no longer compile at all. Current status,
including the stubbed socket surface that makes the missing vtable entries the smaller problem:
[`Io.Evented` in 0.17.0](./std-io-0.17.md#ioevented-in-0170).

`Kqueue` was already stale against the **0.16** `Io.VTable` (`fileWriteStreaming`, `fileReadStreaming`
and `netReceive` are not 0.16 fields either), so none of the evented backends has compiled for two
releases: do not read "0.17 left them behind" as "0.16 could have served sockets".

### Probes

The 0.16 probe cases needed no changes at all: re-running both scripts on 0.17.0 reproduced every 0.16
measurement (timings within a millisecond or two). `operate_probe.zig` gained cases P5/P6 for the send
path this release newly made expressible.

## Adding the next release

1. Fetch the new tag's `lib/std/Io.zig` (Codeberg, see above) and diff it against the version
   `std-io-0.17.md` was verified against — the `Io.VTable` field list is the fastest summary.
2. Re-run both probes on the new toolchain, on macOS *and* Linux, before touching any claim.
3. Write the new release's own reference file, carrying over only what still holds, and add a section
   here for the deltas (including anything the release broke elsewhere — check the backend vtables
   again, they are the usual casualty).
