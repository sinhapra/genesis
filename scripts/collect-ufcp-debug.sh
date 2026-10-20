#!/usr/bin/env bash
# Run from any directory after building matching ufcp binaries on both hosts.
set -u
set -o pipefail
if (( $# < 2 )); then
    echo "Usage: $0 SOURCE [user@]HOST:NEW_DEST [REMOTE_UFCP]" >&2
    exit 2
fi
project=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
binary="$project/ufcp"
source_file=$1
target=$2
remote_program=${3:-ufcp}
log=$(mktemp "./ufcp-debug-$(date +%Y%m%d-%H%M%S)-XXXXXX.log") || exit 1
printf 'Collecting diagnostics in %s\n' "$log"
{
    printf 'UTC: '; date -u '+%Y-%m-%dT%H:%M:%SZ'
    uname -a
    printf 'Local revision: '
    git -C "$project" rev-parse HEAD || true
    printf 'Local binary: %s\n' "$binary"
    sha256sum -- "$binary" || true
    printf 'Source size: '
    stat -c '%s bytes' -- "$source_file" || true
    printf 'Remote helper: %s\n' "$remote_program"
    printf 'Command: '
    printf '%q ' "$binary" copy "$source_file" "$target" --transport=udp --debug "--remote-program=$remote_program"
    printf '\n'
    "$binary" copy "$source_file" "$target" --transport=udp --debug "--remote-program=$remote_program"
    result=$?
    printf 'ufcp exit code: %s\n' "$result"
    printf 'Send this log to the maintainer. It contains host/user/IP and path metadata, not session keys or file payload.\n'
    exit "$result"
} 2>&1 | tee "$log"
exit "${PIPESTATUS[0]}"
