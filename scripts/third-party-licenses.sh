#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Danang Galuh Tegar Prasetyo
#
# Prints the license notices of everything that is built into the release
# binaries: the Go libraries from go.mod, for every target the release builds,
# and the Go standard library. The release workflow saves the output as
# THIRD_PARTY_LICENSES, because those licenses ask for their notices to travel
# with the binaries.
#
# Run it from the repository root with a Go toolchain and the modules
# downloaded (go mod download):
#
#   sh scripts/third-party-licenses.sh > THIRD_PARTY_LICENSES
#
# A library whose published module has no license file can have its notice
# supplied by this repository, in scripts/licenses/<module path>/LICENSE. Add one
# only after checking the license that the library's author states.
#
# The script reports every library that still has no notice and then stops
# with an error, so that a missing notice is found before a release and not
# after.
set -eu

pkg=${1:-./cmd/hardening}
tab=$(printf '\t')
supplied=$(dirname "$0")/licenses

line() { printf '================================================================\n'; }

printf 'Third-party licenses\n\n'
printf 'server-hardening is licensed under the GNU General Public License,\n'
printf 'version 3 or (at your option) any later version. See LICENSE.\n\n'
printf 'The release binaries also contain the software below, which has its own\n'
printf 'license. Each notice is reproduced as the author published it.\n\n'

mods=$(
    for target in linux/amd64 linux/arm64 windows/amd64; do
        GOOS=${target%/*} GOARCH=${target#*/} CGO_ENABLED=0 go list -deps \
            -f '{{with .Module}}{{if not .Main}}{{.Path}}{{"\t"}}{{.Version}}{{"\t"}}{{.Dir}}{{end}}{{end}}' "$pkg"
    done | grep . | sort -u
)

list=$(mktemp)
trap 'rm -f "$list"' EXIT
printf '%s\n' "$mods" > "$list"

missing=0
while IFS=$tab read -r path version dir; do
    found=0
    for f in "$dir"/LICENSE* "$dir"/LICENCE* "$dir"/COPYING*; do
        [ -f "$f" ] || continue
        line
        printf '%s %s (%s)\n' "$path" "$version" "${f##*/}"
        line
        cat "$f"
        printf '\n'
        found=1
    done
    if [ "$found" -eq 0 ] && [ -f "$supplied/$path/LICENSE" ]; then
        line
        printf '%s %s (LICENSE, supplied by this repository)\n' "$path" "$version"
        line
        cat "$supplied/$path/LICENSE"
        printf '\n'
        found=1
    fi
    if [ "$found" -eq 0 ]; then
        printf 'error: no license file found for %s %s in %s\n' "$path" "$version" "$dir" >&2
        missing=1
    fi
done < "$list"
[ "$missing" -eq 0 ] || exit 1

goroot=$(go env GOROOT)
line
printf 'The Go standard library (%s)\n' "$(go env GOVERSION)"
line
cat "$goroot/LICENSE"
