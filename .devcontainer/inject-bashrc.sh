#!/bin/bash
# Usage: ./inject-bashrc.sh [source-file]
# Default source: .devcontainer/bashrc-extras

SOURCE="${1:-/tmp/bashrc-extras}"
TARGET="$HOME/.bashrc"
START_MARKER="# >>> devcontainer-extras >>>"
END_MARKER="# <<< devcontainer-extras <<<"

if [ ! -f "$SOURCE" ]; then
    echo "Source file not found: $SOURCE"
    exit 1
fi

# Remove existing block (if any) and the trailing newline it leaves
sed -i "/^${START_MARKER}$/,/^${END_MARKER}$/d" "$TARGET"

# Append new block
{
    echo "$START_MARKER"
    cat "$SOURCE"
    echo "$END_MARKER"
} >> "$TARGET"

echo "Injected $SOURCE into $TARGET"