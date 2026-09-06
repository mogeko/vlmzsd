# `.kmd` Data File Format

This document is the authoritative specification of the `.kmd` (KMS data) binary
format consumed by `vlmzsd` / `vlmzs`. The parser is `src/kmsdata.zig`; the
byte-level layout is pinned by the tests in that file and summarized in
`docs/migration.md` §3.4. This file describes the format in full.

## 1. Overview

A `.kmd` file is a packed little-endian binary that bundles the KMS activation
data:

- A 72-byte header.
- An array of **CSVLC** records (license channels — the products that can be
  activated, e.g. `Windows`, `Office2019`).
- An array of **Item** records, stored contiguously in three groups: App, KMS,
  then SKU.
- An array of **HostBuild** records (Windows build fingerprint metadata).
- A **string pool**: NUL-terminated C strings referenced by offset from the
  records above.

All multi-byte integers are little-endian. The parser reads fields one at a time
with `std.mem.readInt(..., .little)` — never casting bytes to a padded struct.

The default data is embedded at compile time: `src/vlmcsd.kmd`
(`@embedFile("vlmcsd.kmd")`).

## 2. File layout

```
+----------------+   offset 0
| Header         |  72 bytes
+----------------+   offset 72
| CSVLC records  |  CsvlkCount × 32 bytes
+----------------+   offset AppItemOffset
| Item records   |  (AppItemCount + KmsItemCount + SkuItemCount) × 32 bytes
+----------------+   offset HostBuildOffset
| HostBuild rec. |  HostBuildCount × 32 bytes
+----------------+
| String pool    |  NUL-terminated strings; last file byte is a NUL
+----------------+
```

The header's offsets are relative to the start of the file and must agree with
the record counts:

- `AppItemOffset == 72 + CsvlkCount * 32`
- `HostBuildOffset == AppItemOffset + (AppItemCount + KmsItemCount + SkuItemCount) * 32`

## 3. Header (72 bytes)

| Offset | Size | Type | Field | Notes |
|-------:|-----:|------|-------|-------|
| 0 | 4 | bytes | Magic | `"KMD\0"` (K, M, D, NUL) |
| 4 | 2 | u16 LE | MinorVer | |
| 6 | 2 | u16 LE | MajorVer | **must equal 2** |
| 8 | 1 | u8 | CsvlkCount | number of CSVLC records |
| 9 | 1 | u8 | Flags | default data uses `1` |
| 10 | 2 | — | Reserved | |
| 12 | 4 | u32 LE | AppItemCount | |
| 16 | 4 | u32 LE | KmsItemCount | |
| 20 | 4 | u32 LE | SkuItemCount | |
| 24 | 4 | u32 LE | HostBuildCount | |
| 28 | 4 | — | (unused) | |
| 32 | 8 | u64 LE | AppItemOffset | relative to file start |
| 40 | 16 | — | (unused) | |
| 56 | 8 | u64 LE | HostBuildOffset | relative to file start |
| 64 | 8 | — | (unused) | |

## 4. CSVLC record (32 bytes)

One record per license channel. Stored consecutively starting at offset 72.

| Offset | Size | Type | Field | Notes |
|-------:|-----:|------|-------|-------|
| 0 | 8 | u64 LE | EPidOffset | string-pool offset of the ePID template |
| 8 | 8 | i64 LE | ReleaseDate | Unix timestamp |
| 16 | 4 | u32 LE | GroupId | license group id |
| 20 | 4 | u32 LE | MinKeyId | lower bound (inclusive) of generated key ids |
| 24 | 4 | u32 LE | MaxKeyId | upper bound (exclusive) of generated key ids |
| 28 | 1 | u8 | MinActiveClients | |
| 29 | 3 | — | (unused) | |

The channel's human-readable name is **not** a header field: it is the string
that immediately follows the ePID in the string pool, i.e.
`name_offset = EPidOffset + len(epid) + 1`. This is what `--epid <name>=<epid>`
looks up.

## 5. Item record (32 bytes)

Stored contiguously starting at `AppItemOffset`, in the order App, KMS, SKU
(`apps()[0..app_count]`, `kms()[app_count..][0..kms_count]`, `skus()[..]`).

| Offset | Size | Type | Field | Notes |
|-------:|-----:|------|-------|-------|
| 0 | 16 | bytes | Guid | product/KMS GUID |
| 16 | 8 | u64 LE | NameOffset | string-pool offset of the product name |
| 24 | 1 | u8 | AppIndex | |
| 25 | 1 | u8 | KmsIndex | |
| 26 | 1 | u8 | ProtocolVersion | |
| 27 | 1 | u8 | NCountPolicy | |
| 28 | 1 | u8 | IsRetail | |
| 29 | 1 | u8 | IsPreview | |
| 30 | 1 | u8 | EPidIndex | index into the CSVLC array |
| 31 | 1 | — | (unused) | |

## 6. HostBuild record (32 bytes)

Stored consecutively starting at `HostBuildOffset`.

| Offset | Size | Type | Field | Notes |
|-------:|-----:|------|-------|-------|
| 0 | 8 | u64 LE | DisplayNameOffset | string-pool offset of the build name |
| 8 | 8 | i64 LE | ReleaseDate | Unix timestamp |
| 16 | 4 | i32 LE | BuildNumber | Windows build number |
| 20 | 4 | i32 LE | PlatformId | |
| 24 | 4 | u32 LE | Flags | bit 0 (`1<<0`) = `UseNdr64` |
| 28 | 4 | — | (unused) | |

## 7. String pool

All `*Offset` fields point into the string pool, which follows the HostBuild
array and runs to the end of the file. Strings are NUL-terminated C strings
(ASCII). The **last byte of the file must be `0`** — this is checked by the
parser unless unsafe data loading is enabled.

## 8. Legality constraints

The parser (`kmsdata.parse`) rejects a file with `error.InvalidFormat` when any
of these hold:

- Fewer than 72 bytes.
- `Magic[0..4] != "KMD\0"`.
- `MajorVer != 2`.
- The last byte is not `0`.
- A record array extends past the end of the file.
- Any string offset points outside the file or to a region with no NUL
  terminator.

Use `zig build test` as the authoritative check — the `parse embedded .kmd data`
and `kmd header fields` tests pin the current data exactly. When upgrading the
default data, follow the `kmd-upgrade` skill.

## 9. Default data

`src/vlmcsd.kmd` (embedded) — 19,371 bytes:

| Count | Value |
|---|---|
| CSVLC | 8 |
| App items | 3 |
| KMS items | 36 |
| SKU items | 261 |
| HostBuild | 8 |

## 10. Parser mapping

| Concept | `src/kmsdata.zig` |
|---|---|
| Sizes | `header_size` (72), `csvlk_size` (32), `item_size` (32), `hostbuild_size` (32) |
| Header parse | `parse` — `readLe` of each header field |
| CSVLC record | `CsvlkData` + loop at `header_size + i * csvlk_size` |
| Item record | `VlmcsdData` + loop at `app_offset + i * item_size` |
| HostBuild record | `HostBuild` + loop at `hostbuild_offset + i * hostbuild_size` |
| String pool | `cString(raw, offset)` — reads to the next NUL |
