#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Danang Galuh Tegar Prasetyo
#
# Entry script of https://github.com/danang-id/server-hardening
#
# It shows what machine it is on (operating system, kernel, processor) and
# whether the tool supports it. On a machine that is not supported it says why
# and stops, without downloading anything. On a supported machine it downloads
# the matching binary from the latest release, checks it against the checksum
# list of that release, explains why administrator access is needed, waits for
# Enter, and starts the tool. Extra arguments go to the tool, for example:
#   sh hardening.sh --dry-run
# When piped:  curl -fsSL <url> | sh -s -- --dry-run
#
# What is supported is not written here. The release carries a file, SUPPORTED,
# with one line per system, and this script reads it. So the script does not
# change when support grows.
#
# HARDENING_RELEASE_URL replaces the download location. HARDENING_OS_RELEASE
# replaces /etc/os-release. Both are for mirrors and tests. The default is the
# latest release on GitHub. TMPDIR is where the download goes first; if running
# programs from it is not allowed (noexec), other places are tried.
#
# The checksum comes from the same release as the binary. It catches a broken
# or cut-off download. It does not protect you from a release that was
# tampered with, so read the script and the source if that matters to you.

set -eu

REPO="danang-id/server-hardening"
BASE="${HARDENING_RELEASE_URL:-https://github.com/$REPO/releases/latest/download}"
OS_RELEASE="${HARDENING_OS_RELEASE:-/etc/os-release}"

NL='
'

say() { printf '%s\n' "$*"; }
die() { printf 'error: %s\n' "$*" >&2; exit 1; }

# ---- cleaning up ----
# Leaving by Ctrl+C must leave, not carry on after the trap, so each signal
# exits with its usual status and the EXIT trap does the cleaning.

work=""
# shellcheck disable=SC2317,SC2329 # it runs from the trap
cleanup() {
    if [ -n "$work" ]; then rm -rf "$work"; fi
}
trap cleanup EXIT
trap 'printf "\n"; exit 130' INT
trap 'exit 143' TERM
trap 'exit 129' HUP

# ---- looks ----

if [ -t 1 ] && [ -z "${NO_COLOR:-}" ] && [ "${TERM:-dumb}" != dumb ]; then
    BOLD=$(printf '\033[1m'); DIM=$(printf '\033[2m'); GREEN=$(printf '\033[1;32m')
    RED=$(printf '\033[1;31m'); OFF=$(printf '\033[0m')
else
    BOLD=""; DIM=""; GREEN=""; RED=""; OFF=""
fi

case "${LC_ALL:-${LC_CTYPE:-${LANG:-}}}" in
    *[Uu][Tt][Ff]-8*|*[Uu][Tt][Ff]8*) DOT=$(printf '\342\200\242') ;;
    *) DOT="-" ;;
esac

# ---- the machine ----

kernel=$(uname -sr)
machine=$(uname -m)
os_id=""; os_version=""; hint=""

osr_get() {
    [ -r "$OS_RELEASE" ] || return 0
    sed -n "s/^$1=//p" "$OS_RELEASE" | head -n 1 | sed "s/^\"\(.*\)\"\$/\1/; s/^'\(.*\)'\$/\1/"
}

case "$(uname -s)" in
    Linux)
        os_id=$(osr_get ID)
        os_version=$(osr_get VERSION_ID)
        os_name=$(osr_get NAME)
        os_name=${os_name% GNU/Linux}
        [ -n "$os_name" ] || os_name="Linux"
        os_label=$(osr_get PRETTY_NAME)
        if [ -z "$os_label" ]; then
            if [ -n "$(osr_get NAME)" ]; then os_label="$os_name${os_version:+ $os_version}"; else os_label="Linux"; fi
        fi
        ;;
    Darwin)
        os_name="macOS"
        os_version=$(sw_vers -productVersion 2>/dev/null || true)
        os_label="macOS${os_version:+ $os_version}"
        ;;
    MINGW*|MSYS*|CYGWIN*)
        os_name="Windows"; os_label="Windows"
        hint="On Windows Server use hardening.ps1."
        ;;
    *)
        os_name=$(uname -s); os_label=$os_name
        ;;
esac

# The architecture the way Go names it, which is how the release names its
# files, and the way people say it.
case "$machine" in
    x86_64|amd64)   arch=amd64;   arch_name="x86-64" ;;
    aarch64|arm64)  arch=arm64;   arch_name="ARM64" ;;
    i?86)           arch=386;     arch_name="x86 (32-bit)" ;;
    arm|armv*)      arch=arm;     arch_name="ARM (32-bit)" ;;
    riscv64)        arch=riscv64; arch_name="RISC-V" ;;
    ppc64le)        arch=ppc64le; arch_name="PowerPC 64-bit (little-endian)" ;;
    ppc64)          arch=ppc64;   arch_name="PowerPC 64-bit" ;;
    s390x)          arch=s390x;   arch_name="IBM Z" ;;
    loongarch64)    arch=loong64; arch_name="LoongArch" ;;
    *)              arch=$machine; arch_name=$machine ;;
esac

# ---- the screen ----

row() { printf '  %s%-16s%s%s\n' "$DIM" "$1" "$OFF" "$2"; }

# show prints what is known about the machine and the verdict. reasons holds
# one phrase per line, or nothing when the machine is supported.
reasons=""
show() {
    say ""
    say "  ${BOLD}Interactive Server Hardening${OFF}"
    say "  ${DIM}github.com/danang-id/server-hardening${OFF}"
    say ""
    row "OS" "$os_label"
    row "Kernel" "$kernel"
    row "Architecture" "$arch"
    if [ -z "$reasons" ]; then
        row "Support status" "${GREEN}SUPPORTED${OFF}"
    else
        row "Support status" "${RED}NOT SUPPORTED${OFF}"
        label="Reason"
        count=$(printf '%s\n' "$reasons" | wc -l | tr -d ' ')
        printf '%s\n' "$reasons" | while IFS= read -r r; do
            if [ "$count" -gt 1 ]; then r="$DOT $r"; fi
            row "$label" "$r"
            label=""
        done
        if [ -n "$hint" ]; then say ""; say "  $hint"; fi
    fi
    say ""
}

stop_unsupported() {
    show
    exit 1
}

# Only Linux has a release. Nothing needs downloading to know the rest.
if [ "$(uname -s)" != "Linux" ]; then
    reasons="$os_name is not supported operating system"
    stop_unsupported
fi

# The tool asks questions, so it needs a terminal. When this script is piped
# into sh, the standard input is the pipe, so the terminal is opened by name.
if ! ( : </dev/tty ) 2>/dev/null; then
    die "no terminal found. The tool is interactive: run it from a terminal session."
fi

# ---- tools ----

if command -v curl >/dev/null 2>&1; then
    fetch() { curl -fsSL --proto '=https,file' --retry 3 --connect-timeout 15 -o "$2" "$1"; }
    fetch_bar() { curl -fL --proto '=https,file' --retry 3 --connect-timeout 15 --progress-bar -o "$2" "$1"; }
elif command -v wget >/dev/null 2>&1; then
    fetch() { wget -q -O "$2" "$1"; }
    fetch_bar() { wget -q --show-progress -O "$2" "$1"; }
else
    die "neither curl nor wget is installed. Install one of them (for example: apt-get install curl) and run this again."
fi

if command -v sha256sum >/dev/null 2>&1; then
    hash_of() { sha256sum "$1" | cut -d ' ' -f 1; }
elif command -v shasum >/dev/null 2>&1; then
    hash_of() { shasum -a 256 "$1" | cut -d ' ' -f 1; }
else
    die "neither sha256sum nor shasum is installed, so the download cannot be checked."
fi

# The binary runs from a temporary directory, so the directory must allow
# running programs. On a hardened server /tmp often does not: it is mounted
# noexec (this tool's own tmp-hardening control does that), and sudo then
# fails with "Permission denied". So each candidate is tried by running a small
# script from it, and the first one that works is used.
make_work() {
    for base in "${TMPDIR:-}" /tmp /var/tmp /dev/shm "${XDG_RUNTIME_DIR:-}" "${HOME:-}"; do
        if [ -z "$base" ] || [ ! -d "$base" ] || [ ! -w "$base" ]; then continue; fi
        d=$(mktemp -d "$base/hardening.XXXXXX" 2>/dev/null) || continue
        chmod 700 "$d"
        printf '#!/bin/sh\nexit 0\n' > "$d/probe"
        chmod 700 "$d/probe"
        if "$d/probe" >/dev/null 2>&1; then
            rm -f "$d/probe"
            work=$d
            return 0
        fi
        rm -rf "$d"
    done
    return 1
}
make_work || die "no directory on this machine allows running programs (/tmp and the others are mounted noexec or cannot be written). Set TMPDIR to one that does, for example: TMPDIR=\$HOME sh hardening.sh"

# verify checks a downloaded file against the checksum list of the release.
verify() {
    want=$(awk -v f="$2" '$2 == f || $2 == "*" f { print $1; exit }' "$work/SHA256SUMS")
    [ -n "$want" ] || die "the checksum list has no entry for $2"
    got=$(hash_of "$1")
    [ "$got" = "$want" ] || die "checksum mismatch for $2 (expected $want, got $got). Nothing was run."
}

# ---- is this machine supported? ----

fetch "$BASE/SHA256SUMS" "$work/SHA256SUMS" || die "cannot download the checksum list $BASE/SHA256SUMS"
fetch "$BASE/SUPPORTED" "$work/SUPPORTED" || die "cannot download the list of supported systems $BASE/SUPPORTED"
verify "$work/SUPPORTED" SUPPORTED

# Each line of SUPPORTED is: system ID, version, architectures. The checks go
# in order: the operating system, then its version, then the processor. An
# operating system that is not supported ends them.
os_known=0; ver_known=0; arch_ok=0; arch_any=0
while read -r s_id s_ver s_archs; do
    case "$s_id" in ""|"#"*) continue ;; esac
    for a in $s_archs; do
        if [ "$a" = "$arch" ]; then arch_any=1; fi
    done
    if [ "$s_id" = "$os_id" ]; then
        os_known=1
        if [ "$s_ver" = "$os_version" ]; then
            ver_known=1
            for a in $s_archs; do
                if [ "$a" = "$arch" ]; then arch_ok=1; fi
            done
        fi
    fi
done < "$work/SUPPORTED"

add_reason() { reasons="${reasons:+$reasons$NL}$1"; }
if [ "$os_known" -eq 0 ]; then
    add_reason "$os_name is not supported operating system"
else
    if [ "$ver_known" -eq 0 ]; then
        add_reason "$os_name${os_version:+ $os_version} is not supported operating system version"
        if [ "$arch_any" -eq 0 ]; then add_reason "$arch_name is not supported processor architecture"; fi
    elif [ "$arch_ok" -eq 0 ]; then
        add_reason "$arch_name is not supported processor architecture"
    fi
fi

show
[ -z "$reasons" ] || exit 1

# ---- downloading ----

asset="hardening-linux-$arch"
say "Downloading $asset"
fetch_bar "$BASE/$asset" "$work/$asset" || die "cannot download $BASE/$asset"
verify "$work/$asset" "$asset"
say "Checksum verified."
chmod 700 "$work/$asset"

# ---- administrator access ----

if [ "$(id -u)" -eq 0 ]; then
    run() { "$@" </dev/tty; }
else
    command -v sudo >/dev/null 2>&1 || die "this tool changes system settings and must run as root, and sudo is not installed. Log in as root and run this again."
    say ""
    say "The tool changes system settings (packages, services, firewall, SSH), so it needs administrator access."
    say "sudo will ask for your password after you press Enter."
    # shellcheck disable=SC2024 # the redirect belongs to the tool, not to sudo
    run() { sudo "$@" </dev/tty; }
fi

say ""
printf 'Press Enter to start, or Ctrl+C to cancel. '
IFS= read -r _ </dev/tty || die "no answer from the terminal"

# Not exec: the temporary directory is removed when the tool ends. The tool
# keeps its own copy of itself for the automatic undo. The screen it would show
# first is the one above, so it is skipped.
set +e
run "$work/$asset" --skip-welcome "$@"
status=$?
set -e
exit "$status"
