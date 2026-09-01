#!/usr/bin/env bash
# Auto-format edited Zig files with `zig fmt` (PostToolUse hook).
# Reads the VS Code hook input JSON from stdin; only acts on file-editing tools
# that touched a `.zig` file. A missing `zig` binary is a no-op; a failed format
# is a non-blocking warning (exit 1), never a hard block.

set -u

input="$(cat 2>/dev/null || true)"
[ -n "$input" ] || exit 0

# Only react to file-editing tools.
tool_name="$(printf '%s' "$input" | grep -oE '"tool_name"[[:space:]]*:[[:space:]]*"[^"]*"' | head -1 | sed -E 's/^.*"([^"]*)"$/\1/')"
case "$tool_name" in
  create_file | replace_string_in_file | insert_edit_into_file | edit_notebook_file) ;;
  *) exit 0 ;;
esac

# Extract the edited file path (VS Code uses camelCase `filePath`; accept snake_case fallback).
file="$(printf '%s' "$input" | grep -oE '"filePath"[[:space:]]*:[[:space:]]*"[^"]*"' | head -1 | sed -E 's/^.*"([^"]*)"$/\1/')"
if [ -z "$file" ]; then
  file="$(printf '%s' "$input" | grep -oE '"file_path"[[:space:]]*:[[:space:]]*"[^"]*"' | head -1 | sed -E 's/^.*"([^"]*)"$/\1/')"
fi

# Only format .zig files; skip URIs (e.g. untitled:) and non-Zig paths.
case "$file" in
  *.zig) ;;
  *) exit 0 ;;
esac

# Require `zig`; skip silently rather than blocking edits when unavailable.
if ! command -v zig >/dev/null 2>&1; then
  exit 0
fi

# Format the single changed file in place.
if ! zig fmt "$file"; then
  echo "zig-fmt hook: failed to format $file" >&2
  exit 1
fi

exit 0
