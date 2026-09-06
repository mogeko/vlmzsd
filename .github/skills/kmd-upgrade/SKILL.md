---
name: kmd-upgrade
description: 'Validate and propagate a change to the embedded KMS data file (src/vlmcsd.kmd) in vlmzsd. Use whenever src/vlmcsd.kmd is modified — upgraded, regenerated, or hand-edited — to check the new data is a legal .kmd file, then update the tests and docs that pin the default data. Works with the kmd-format agent for layout analysis. Keywords: .kmd, vlmcsd.kmd, KMS data, upgrade, kmsdata, CSVLC, HostBuild, default data, record count.'
argument-hint: '<what changed in src/vlmcsd.kmd>'
---

# KMS Data (.kmd) Upgrade

Validate a changed `src/vlmcsd.kmd` and propagate the new default data into the
byte-level tests and documentation. The embedded `.kmd` is a wire-visible
artifact: every change must be checked for legality, then pinned.

## When to Use

- `src/vlmcsd.kmd` was replaced, regenerated, or hand-edited.
- You changed a CSVLC, app/KMS/SKU item, or HostBuild record in the data.
- `zig build test` fails in `src/kmsdata.zig` after a data change.

## Procedure

1. **Establish what changed.** `git diff --stat src/vlmcsd.kmd` and note whether
   it is a regeneration (record counts changed) or a targeted edit (values changed).

2. **Analyze the new layout.** Invoke the `kmd-format` subagent to map the new
   header/record layout against `docs/migration.md` §3.4, and report the
   header fields (magic, major/minor version, counts, offsets) and record
   values that moved.

3. **Validate legality.** Confirm all of these against `docs/migration.md` §3.4
   and `src/kmsdata.zig`:
   - `Magic[0..4] == "KMD\0"` and the last byte of the file is `0`.
   - `MajorVer == 2` (minor may vary).
   - Offsets (`AppItemOffset@32`, `HostBuildOffset@56`) and counts are
     self-consistent with the file size: `72 + csvlk*32`, `app_offset +
     items*32`, `hostbuild_offset + hostbuilds*32` all fit within the file.
   - Every string offset (ePID, name, display name) points to a NUL-terminated
     region.
   - Run `zig build test --summary all`. The `parse embedded .kmd data` and
     `kmd header fields` tests are the authoritative legality check; any
     failure means the data is illegal (or the test is stale — fix the data first).

4. **Update the pinning tests** (only after the data itself is legal):
   - `src/kmsdata.zig` — update `parse embedded .kmd data` field values and
     `kmd header fields` size (`raw.len`) and record counts.
   - `src/kms.zig` / `src/root.zig` / `src/rpc.zig` — any golden value derived
     from the default data (e.g. `@embedFile("vlmcsd.kmd")` round-trips).

5. **Update the docs**:
   - `docs/migration.md` §3.4 — default-data byte size and record counts
     (CSVLC / app / kms / sku / hostbuild), and any format change.
   - `README.md` / `docs/cli.md` — only if the change alters the user-visible
     surface (e.g. the product list).

6. **Verify.** `zig fmt` and `zig build test --summary all` must pass; every
   updated assert carries a `// from docs/migration.md §3.4` provenance comment.

## Checklist

- [ ] New `.kmd` is legal: magic, `MajorVer == 2`, trailing NUL, consistent offsets/counts.
- [ ] `kmd-format` agent report reviewed; layout matches `docs/migration.md` §3.4.
- [ ] All field/count/size asserts in `src/kmsdata.zig` updated with provenance comments.
- [ ] `docs/migration.md` §3.4 default-data numbers updated.
- [ ] `zig fmt` + `zig build test --summary all` pass.
