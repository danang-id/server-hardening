// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Danang Galuh Tegar Prasetyo

package sysdetect

import "testing"

func TestDescribe(t *testing.T) {
	deb := map[string]string{"PRETTY_NAME": "Debian GNU/Linux 13 (trixie)", "NAME": "Debian GNU/Linux", "VERSION_ID": "13"}
	for _, c := range []struct {
		goos, arch string
		osr        map[string]string
		kernel     string
		version    string
		want       Machine
	}{
		{"linux", "amd64", deb, "6.12.48+deb13-amd64", "",
			Machine{"Debian", "13", "Debian GNU/Linux 13 (trixie)", "Linux 6.12.48+deb13-amd64", "amd64"}},
		{"linux", "arm64", map[string]string{"NAME": "Alpine Linux", "VERSION_ID": "3.20"}, "6.6.1", "",
			Machine{"Alpine Linux", "3.20", "Alpine Linux 3.20", "Linux 6.6.1", "arm64"}},
		{"linux", "amd64", nil, "", "", Machine{"Linux", "", "Linux", "Linux", "amd64"}},
		{"darwin", "arm64", nil, "25.0.0", "26.0", Machine{"macOS", "26.0", "macOS 26.0", "Darwin 25.0.0", "arm64"}},
		{"darwin", "arm64", nil, "25.0.0", "", Machine{"macOS", "", "macOS", "Darwin 25.0.0", "arm64"}},
		{"windows", "amd64", nil, "", "", Machine{"Windows", "", "Windows", "Windows NT", "amd64"}},
		{"freebsd", "amd64", nil, "14.1", "", Machine{"FreeBSD", "", "freebsd", "FreeBSD 14.1", "amd64"}},
	} {
		if got := Describe(c.goos, c.arch, c.osr, c.kernel, c.version); got != c.want {
			t.Errorf("%s: got %+v want %+v", c.goos, got, c.want)
		}
	}
}

func TestArchName(t *testing.T) {
	for in, want := range map[string]string{"riscv64": "RISC-V", "arm64": "ARM64", "amd64": "x86-64", "weird": "weird"} {
		if got := ArchName(in); got != want {
			t.Errorf("%s: %q", in, got)
		}
	}
}
