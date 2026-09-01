#!/usr/bin/env bash
# Run `zig build test` when the agent session ends (Stop hook).
# No-op when `zig` is unavailable or the workspace has no `build.zig`.
# A failing suite is reported as a non-blocking warning (exit 1) so the
# session still ends normally while the failure stays visible.

set -u

command -v zig >/dev/null 2>&1 || exit 0
[ -f build.zig ] || exit 0

if zig build test --summary all; then
  echo "zig-build-test: OK — all tests passed"
else
  echo "zig-build-test: tests FAILED — run 'zig build test' to inspect" >&2
  exit 1
fi
