// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Danang Galuh Tegar Prasetyo

package main

import (
	"errors"
	"strings"
	"testing"

	_ "github.com/danang-id/server-hardening/Debian/13/Controls"
	"github.com/danang-id/server-hardening/internal/sysdetect"
)

func machine(goos, arch string, osr map[string]string) sysdetect.Machine {
	return sysdetect.Describe(goos, arch, osr, "1.0", "27.0")
}

func TestAssess(t *testing.T) {
	deb := func(v string) map[string]string {
		return map[string]string{"ID": "debian", "NAME": "Debian GNU/Linux", "VERSION_ID": v}
	}
	for name, c := range map[string]struct {
		goos, arch string
		osr        map[string]string
		oerr       error
		want       []string // nil: supported
	}{
		"debian 13 amd64": {"linux", "amd64", deb("13"), nil, nil},
		"debian 13 arm64": {"linux", "arm64", deb("13"), nil, nil},
		"debian 9":        {"linux", "amd64", deb("9"), nil, []string{"Debian 9 is not supported operating system version"}},
		"debian 13 riscv": {"linux", "riscv64", deb("13"), nil, []string{"RISC-V is not supported processor architecture"}},
		"debian 9 riscv": {"linux", "riscv64", deb("9"), nil, []string{
			"Debian 9 is not supported operating system version", "RISC-V is not supported processor architecture"}},
		"ubuntu":    {"linux", "amd64", map[string]string{"ID": "ubuntu", "NAME": "Ubuntu", "VERSION_ID": "24.04"}, nil, []string{"Ubuntu is not supported operating system"}},
		"mac arm64": {"darwin", "arm64", nil, nil, []string{"macOS is not supported operating system"}},
		"mac riscv": {"darwin", "riscv64", nil, nil, []string{"macOS is not supported operating system"}},
		"windows":   {"windows", "amd64", nil, nil, []string{"Windows is not supported operating system"}},
		"no file":   {"linux", "amd64", nil, errors.New("no such file"), []string{"The operating system cannot be identified: no such file"}},
	} {
		sys, got := assess(c.goos, machine(c.goos, c.arch, c.osr), c.osr, c.oerr)
		if c.want == nil {
			if sys == nil || len(got) != 0 {
				t.Errorf("%s: want supported, got %v", name, got)
			}
			continue
		}
		if sys != nil || strings.Join(got, "|") != strings.Join(c.want, "|") {
			t.Errorf("%s: got %v want %v (sys %v)", name, got, c.want, sys)
		}
	}
}

func TestReasonsError(t *testing.T) {
	err := reasonsError([]string{"Debian 9 is not supported operating system version", "RISC-V is not supported processor architecture"})
	want := "Debian 9 is not supported operating system version; RISC-V is not supported processor architecture. This tool hardens Debian 13 servers only, for now"
	if err.Error() != want {
		t.Fatal(err)
	}
}
