# `kmdconv` — `.kmd` ⇄ JSON converter

`kmdconv` is a developer tool that converts between the vlmzsd `.kmd` binary
data format and a human-editable JSON representation. It is **not part of the
user-facing surface**: it is not installed by `zig build` and exists to make
`.kmd` files inspectable and editable.

The binary format itself is specified in `docs/kmd-format.md`; the parser is
`src/kmsdata.zig`.

## Building

`kmdconv` is not installed by the default `zig build`. Build it explicitly:

```sh
zig build kmdconv
# binary at zig-out/bin/kmdconv
```

Its tests run with the normal test suite:

```sh
zig build test
```

## Usage

```
kmdconv [OPTIONS] <file>
```

- **Default direction** (`JSON → KMD`): read a JSON file, write a `.kmd` file.
- **Reverse** (`-r`, `KMD → JSON`): read a `.kmd` file, write JSON.
- Input `<file>` may be `-` to read from stdin (output then goes to stdout,
  since no filename is available to derive from).
- Without `-o`, the output is written to the **current directory** with the
  input's stem and the matching suffix: `data.json` → `data.kmd`, and with `-r`
  `data.kmd` → `data.json`.

### Examples

```sh
# Inspect the embedded data file as JSON (printed to stdout)
kmdconv -r - < src/vlmcsd.kmd

# Convert JSON to .kmd (writes ./data.kmd)
kmdconv data.json

# Convert .kmd to JSON (writes ./data.json)
kmdconv -r data.kmd

# Convert with an explicit output path
kmdconv data.json -o /path/to/custom.kmd

# Round-trip: kmd -> JSON -> kmd
kmdconv -r src/vlmcsd.kmd -o data.json
kmdconv data.json -o rebuilt.kmd
```

## CLI

| Option | Description |
|---|---|
| `<file>` | input file; `-` reads stdin (positional, required) |
| `-h`, `--help` | print help and exit |
| `-V`, `--version` | print version and exit |
| `-` | read input from stdin instead of `<file>` |
| `-r`, `--reverse` | reverse direction: read `.kmd`, write JSON |
| `-o`, `--output <file>` | write output to `<file>` (default: derived sibling in the current directory) |

Errors print a one-line diagnostic to stderr and exit non-zero. If the input
fails to parse in the chosen direction, the error hints at the opposite
direction (e.g. "is this a `.kmd` file? use -r").

## JSON format

The top level is an object mirroring `kmsdata.KmsData`:

| Field | Type | Meaning |
|---|---|---|
| `minor_ver` | int (u16) | header minor version |
| `major_ver` | int (u16) | header major version (must be `2`) |
| `flags` | int (u8) | header flags |
| `csvlk` | array | license channels (CSVLC records) |
| `apps` | array | App item records |
| `kms` | array | KMS item records |
| `skus` | array | SKU item records |
| `hostbuilds` | array | HostBuild records |

All numbers are JSON integers (no floats). `guid` is a 32-character lowercase
hex string encoding the 16 GUID bytes in file byte order (not the hyphenated
RFC 4122 form).

### CSVLC record

| Field | Type | Meaning |
|---|---|---|
| `epid` | string | ePID template |
| `name` | string | human-readable channel name (follows `epid` in the string pool) |
| `release_date` | int (i64) | Unix timestamp |
| `group_id` | int (u32) | license group id |
| `min_key_id` | int (u32) | generated key id lower bound (inclusive) |
| `max_key_id` | int (u32) | generated key id upper bound (exclusive) |
| `min_active_clients` | int (u8) | |

### Item record (`apps` / `kms` / `skus`)

| Field | Type | Meaning |
|---|---|---|
| `guid` | string | 32-char lowercase hex of the 16 GUID bytes |
| `name` | string | product / KMS name |
| `app_index` | int (u8) | |
| `kms_index` | int (u8) | |
| `protocol_version` | int (u8) | |
| `n_count_policy` | int (u8) | |
| `is_retail` | int (u8) | |
| `is_preview` | int (u8) | |
| `epid_index` | int (u8) | index into the `csvlk` array |

### HostBuild record

| Field | Type | Meaning |
|---|---|---|
| `display_name` | string | build name |
| `release_date` | int (i64) | Unix timestamp |
| `build_number` | int (i32) | Windows build number |
| `platform_id` | int (i32) | |
| `flags` | int (u32) | bit 0 (`1<<0`) = `UseNdr64` |

### Example

```json
{
  "minor_ver": 0,
  "major_ver": 2,
  "flags": 1,
  "csvlk": [
    {
      "epid": "03612-04919-019-192355-03-1033-17763.0000-2622024",
      "name": "Windows",
      "release_date": 1714089600,
      "group_id": 4919,
      "min_key_id": 20000,
      "max_key_id": 20019999,
      "min_active_clients": 0
    }
  ],
  "apps": [
    {
      "guid": "3427c95582d6714d983ed6ec3f16059f",
      "name": "Windows",
      "app_index": 0,
      "kms_index": 0,
      "protocol_version": 0,
      "n_count_policy": 50,
      "is_retail": 0,
      "is_preview": 0,
      "epid_index": 0
    }
  ],
  "kms": [],
  "skus": [],
  "hostbuilds": [
    {
      "display_name": "Windows 11 24H2 / Server 2025",
      "release_date": 1714089600,
      "build_number": 26100,
      "platform_id": 3612,
      "flags": 7
    }
  ]
}
```

## Notes

- The `.kmd` produced from JSON is semantically identical to its source but
  not byte-identical: the string pool is rebuilt without deduplication. Use
  `scripts/dump_kmd.py` to inspect a generated file, and see the `kmd-upgrade`
  skill for the workflow around editing the embedded `src/vlmcsd.kmd`.
