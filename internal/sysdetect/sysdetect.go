// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Danang Galuh Tegar Prasetyo

// Package sysdetect reads which operating system the tool is running on.
package sysdetect

import (
	"bufio"
	"io"
	"os"
	"strings"
)

// ParseOSRelease parses the content of /etc/os-release into key/value pairs.
func ParseOSRelease(r io.Reader) map[string]string {
	out := map[string]string{}
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		out[k] = strings.Trim(v, `"'`)
	}
	return out
}

// ReadOSRelease reads /etc/os-release.
func ReadOSRelease() (map[string]string, error) {
	f, err := os.Open("/etc/os-release")
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return ParseOSRelease(f), nil
}
