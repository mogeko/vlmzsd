#!/usr/bin/env python3
"""Dump and validate a vlmcsd `.kmd` data file.

Prints the header, CSVLC / Item / HostBuild records, and string-pool-derived
fields, then runs the legality checks from `docs/kmd-format.md` §8. Exits
non-zero if any check fails.

Usage:
    dump_kmd.py [FILE]          # default: src/vlmcsd.kmd
"""

import struct
import sys

HEADER_SIZE = 72
CSVLC_SIZE = 32
ITEM_SIZE = 32
HOSTBUILD_SIZE = 32


def u16(d, o):
    return struct.unpack_from("<H", d, o)[0]


def u32(d, o):
    return struct.unpack_from("<I", d, o)[0]


def u64(d, o):
    return struct.unpack_from("<Q", d, o)[0]


def i32(d, o):
    return struct.unpack_from("<i", d, o)[0]


def i64(d, o):
    return struct.unpack_from("<q", d, o)[0]


def cstr(d, off):
    """Read a NUL-terminated string at `off`; raises on out-of-range/unterminated."""
    if off >= len(d):
        raise ValueError(f"string offset {off} is past end of file ({len(d)})")
    end = d.find(b"\x00", off)
    if end < 0:
        raise ValueError(f"string at offset {off} is not NUL-terminated")
    return d[off:end].decode("latin-1")


def main(argv):
    path = argv[1] if len(argv) > 1 else "src/vlmcsd.kmd"
    try:
        with open(path, "rb") as f:
            d = f.read()
    except OSError as e:
        print(f"ERROR: cannot read {path}: {e}")
        return 1

    errors = []

    if len(d) < HEADER_SIZE:
        print(f"ERROR: file too short ({len(d)} < {HEADER_SIZE})")
        return 1

    magic = d[0:4]
    minor = u16(d, 4)
    major = u16(d, 6)
    csvlk_count = d[8]
    flags = d[9]
    app_count = u32(d, 12)
    kms_count = u32(d, 16)
    sku_count = u32(d, 20)
    hb_count = u32(d, 24)
    app_offset = u64(d, 32)
    hb_offset = u64(d, 56)

    print("== Header ==")
    print(f"file size:     {len(d)}")
    print(f"magic:         {magic!r}")
    print(f"minor/major:   {minor}/{major}")
    print(f"csvlk_count:   {csvlk_count}")
    print(f"flags:         {flags}")
    print(f"app/kms/sku:   {app_count}/{kms_count}/{sku_count}")
    print(f"hostbuilds:    {hb_count}")
    print(f"app_offset:    {app_offset}")
    print(f"hb_offset:     {hb_offset}")

    if magic != b"KMD\x00":
        errors.append('magic != "KMD\\0"')
    if major != 2:
        errors.append(f"MajorVer {major} != 2")
    if d[-1] != 0:
        errors.append("last byte is not 0")

    items_total = app_count + kms_count + sku_count
    expected_app = HEADER_SIZE + csvlk_count * CSVLC_SIZE
    expected_hb = app_offset + items_total * ITEM_SIZE
    if app_offset != expected_app:
        errors.append(
            f"AppItemOffset {app_offset} != 72 + {csvlk_count}*32 = {expected_app}"
        )
    if hb_offset != expected_hb:
        errors.append(
            f"HostBuildOffset {hb_offset} != app_offset + {items_total}*32 = {expected_hb}"
        )
    if app_offset + items_total * ITEM_SIZE > len(d):
        errors.append("item array extends past end of file")
    if hb_offset + hb_count * HOSTBUILD_SIZE > len(d):
        errors.append("hostbuild array extends past end of file")

    print("\n== CSVLC records ==")
    for i in range(csvlk_count):
        base = HEADER_SIZE + i * CSVLC_SIZE
        if base + CSVLC_SIZE > len(d):
            errors.append(f"csvlc[{i}] extends past end of file")
            break
        try:
            epid_off = u64(d, base)
            epid = cstr(d, epid_off)
            name = cstr(d, epid_off + len(epid) + 1)
            rel = i64(d, base + 8)
            gid = u32(d, base + 16)
            mink = u32(d, base + 20)
            maxk = u32(d, base + 24)
            mac = d[base + 28]
        except ValueError as e:
            errors.append(f"csvlc[{i}]: {e}")
            continue
        print(
            f"  [{i}] {name!r} group={gid} mink={mink} maxk={maxk} "
            f"min_active={mac} release={rel}"
        )
        print(f"      epid={epid!r}")

    print("\n== Item records ==")
    idx = 0
    for kind, cnt in (("app", app_count), ("kms", kms_count), ("sku", sku_count)):
        for _ in range(cnt):
            base = app_offset + idx * ITEM_SIZE
            if base + ITEM_SIZE > len(d):
                errors.append(f"item[{idx}] extends past end of file")
                idx += 1
                continue
            try:
                guid = d[base : base + 16].hex()
                name = cstr(d, u64(d, base + 16))
                app = d[base + 24]
                kms = d[base + 25]
                proto = d[base + 26]
                n_count = d[base + 27]
                retail = d[base + 28]
                preview = d[base + 29]
                epid = d[base + 30]
            except ValueError as e:
                errors.append(f"item[{idx}]: {e}")
                idx += 1
                continue
            print(
                f"  [{idx:3d}] {kind:4s} guid={guid} {name!r} "
                f"app={app} kms={kms} proto={proto} n_count={n_count} "
                f"retail={retail} preview={preview} epid={epid}"
            )
            idx += 1

    print("\n== HostBuild records ==")
    for i in range(hb_count):
        base = hb_offset + i * HOSTBUILD_SIZE
        if base + HOSTBUILD_SIZE > len(d):
            errors.append(f"hostbuild[{i}] extends past end of file")
            break
        try:
            name = cstr(d, u64(d, base))
            rel = i64(d, base + 8)
            build = i32(d, base + 16)
            platform = i32(d, base + 20)
            flags = u32(d, base + 24)
        except ValueError as e:
            errors.append(f"hostbuild[{i}]: {e}")
            continue
        print(
            f"  [{i}] {name!r} build={build} platform={platform} "
            f"flags={flags} release={rel}"
        )

    if errors:
        print("\n== ERRORS ==")
        for e in errors:
            print(f"  - {e}")
        return 1

    print("\nOK: all legality checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
