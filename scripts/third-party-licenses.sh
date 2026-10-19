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
# It stops with an error if a library has no license file, so that a missing
# notice is found before a release and not after.
set -eu

pkg=${1:-./cmd/hardening}
tab=$(printf '\t')

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

printf '%s\n' "$mods" | while IFS=$tab read -r path version dir; do
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
    if [ "$found" -eq 0 ]; then
        printf 'error: no license file found for %s %s in %s\n' "$path" "$version" "$dir" >&2
        exit 1
    fi
done

goroot=$(go env GOROOT)
line
printf 'The Go standard library (%s)\n' "$(go env GOVERSION)"
line
cat "$goroot/LICENSE"
