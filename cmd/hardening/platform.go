// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Danang Galuh Tegar Prasetyo

package main

import (
	"errors"
	"slices"
	"strings"

	"github.com/danang-id/server-hardening/internal/registry"
	"github.com/danang-id/server-hardening/internal/sysdetect"
)

// assess says whether the tool can harden this computer. It returns the system
// to use, or the reasons it cannot, one phrase for each. osr is the parsed
// /etc/os-release and osrErr says why it could not be read. The tool changes
// the system it runs on, so running it on a laptop would either fail or, worse,
// change the laptop.
//
// The checks go in order: the operating system, then its version, then the
// processor architecture. An operating system that is not supported ends it,
// because its version and its processor say nothing more.
func assess(goos string, m sysdetect.Machine, osr map[string]string, osrErr error) (*registry.System, []string) {
	if goos != "linux" {
		return nil, []string{m.Name + " is not supported operating system"}
	}
	if osrErr != nil {
		return nil, []string{"The operating system cannot be identified: " + osrErr.Error()}
	}
	if !registry.KnowsOS(osr["ID"]) {
		return nil, []string{m.Name + " is not supported operating system"}
	}

	var reasons []string
	sys, err := registry.Detect(osr)
	if err != nil {
		reasons = append(reasons, strings.TrimSpace(m.Name+" "+m.Version)+" is not supported operating system version")
	}
	// The architecture counts for the matched system. When the version did not
	// match, for every version of the system the tool knows.
	ok := true
	if sys != nil {
		ok = sys.SupportsArch(m.Arch)
	} else if all := registry.Archs(); len(all) > 0 {
		ok = slices.Contains(all, m.Arch)
	}
	if !ok {
		reasons = append(reasons, sysdetect.ArchName(m.Arch)+" is not supported processor architecture")
	}
	if len(reasons) > 0 {
		sys = nil
	}
	return sys, reasons
}

// reasonsError is the reasons as an error, for a run without the full-screen
// interface.
func reasonsError(reasons []string) error {
	return errors.New(strings.Join(reasons, "; ") + ". This tool hardens Debian 13 servers only, for now")
}
