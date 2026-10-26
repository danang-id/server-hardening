// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Danang Galuh Tegar Prasetyo

package controls

import "testing"

// The support list is what hardening.sh reads from the release, so Match has
// to accept every minor release of AlmaLinux 10 and nothing else.
func TestMatchAcceptsEveryMinorRelease(t *testing.T) {
	for _, v := range []string{"10", "10.0", "10.1", "10.2", "10.11"} {
		if !System.Match(map[string]string{"ID": "almalinux", "VERSION_ID": v}) {
			t.Errorf("Match does not accept AlmaLinux %s", v)
		}
	}
	for name, r := range map[string]map[string]string{
		"AlmaLinux 9":       {"ID": "almalinux", "VERSION_ID": "9.6"},
		"AlmaLinux 100":     {"ID": "almalinux", "VERSION_ID": "100.1"},
		"Rocky Linux 10":    {"ID": "rocky", "VERSION_ID": "10.1"},
		"Debian 13":         {"ID": "debian", "VERSION_ID": "13"},
		"no version at all": {"ID": "almalinux"},
	} {
		if System.Match(r) {
			t.Errorf("Match accepts %s", name)
		}
	}
	if System.OSID != "almalinux" || System.Version != "10" {
		t.Fatalf("the support list says %s %s", System.OSID, System.Version)
	}
}
