#!/usr/bin/env bash
set -euo pipefail

script_directory="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
binary_path="$script_directory/target/release/mtr"
destination_path="${DEST_PATH:-/usr/local/bin/mtr}"
platform_name="$(uname -s)"

require_command() {
    command -v "$1" >/dev/null 2>&1 || {
        printf 'error: missing command: %s\n' "$1" >&2
        exit 1
    }
}

run_privileged() {
    if [[ "$EUID" -eq 0 ]]; then
        "$@"
    else
        sudo "$@"
    fi
}

if [[ "$EUID" -eq 0 ]]; then
    printf 'error: do not run install.sh as root; it builds the project as the current user\n' >&2
    printf 'run it as a normal user so Cargo artifacts remain writable\n' >&2
    exit 1
fi

require_command cargo
require_command install
require_command sudo
require_command mktemp

if [[ "$destination_path" != /* ]]; then
    printf 'error: DEST_PATH must be absolute: %s\n' "$destination_path" >&2
    exit 1
fi
if [[ -d "$destination_path" ]]; then
    printf 'error: DEST_PATH must name a file, not a directory: %s\n' "$destination_path" >&2
    exit 1
fi
destination_directory="$(dirname -- "$destination_path")"
if [[ ! -d "$destination_directory" ]]; then
    printf 'error: destination directory does not exist: %s\n' "$destination_directory" >&2
    exit 1
fi

if [[ "$platform_name" == Linux* ]] && ! command -v setcap >/dev/null 2>&1; then
    printf 'error: Linux installation requires setcap from libcap; no SUID fallback is used\n' >&2
    exit 1
fi

if [[ -n "${CARGO_TARGET_DIR:-}" || -n "${CARGO_BUILD_TARGET:-}" ]]; then
    printf 'error: unset CARGO_TARGET_DIR and CARGO_BUILD_TARGET so the release artifact path is unambiguous\n' >&2
    exit 1
fi

printf 'building Rust MTR release binary...\n'
(cd "$script_directory" && cargo build --release --locked)

if [[ ! -f "$binary_path" ]]; then
    printf 'error: build artifact not found: %s\n' "$binary_path" >&2
    exit 1
fi

temporary_path="$(run_privileged mktemp "$destination_directory/.mtr-install.XXXXXX")"
cleanup() {
    run_privileged rm -f -- "$temporary_path"
}
trap cleanup EXIT

printf 'installing to %s...\n' "$destination_path"
run_privileged install -m 0755 "$binary_path" "$temporary_path"
run_privileged mv -f -- "$temporary_path" "$destination_path"
trap - EXIT

capability_granted=0
if [[ "$platform_name" == Linux* ]]; then
    if ! run_privileged setcap cap_net_raw+ep "$destination_path"; then
        printf 'error: setcap failed; the new binary has no cap_net_raw\n' >&2
        printf 'the destination filesystem may not support security.capability xattrs\n' >&2
        exit 1
    fi

    if command -v getcap >/dev/null 2>&1; then
        capability_state="$(getcap "$destination_path" || true)"
        if [[ "$capability_state" != *"cap_net_raw=ep"* ]]; then
            printf 'error: cap_net_raw verification failed\n' >&2
            exit 1
        fi
    else
        printf 'warning: getcap is unavailable; cap_net_raw was applied but not verified\n' >&2
    fi
    capability_granted=1
fi

printf 'installed: %s\n' "$destination_path"
printf 'uninstall: sudo rm -f -- %q\n' "$destination_path"
if [[ "$capability_granted" -eq 1 ]]; then
    printf 'remove capability: sudo setcap -r -- %q\n' "$destination_path"
fi
