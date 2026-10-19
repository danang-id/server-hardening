// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Danang Galuh Tegar Prasetyo

package controls

import (
	"testing"

	"github.com/danang-id/server-hardening/internal/registry"
)

// The support list is what hardening.sh reads from the release, so it has to
// say what the system really matches.
func TestSupportListMatchesTheSystem(t *testing.T) {
	if !System.Match(map[string]string{"ID": System.OSID, "VERSION_ID": System.Version}) {
		t.Fatalf("Match does not accept %s %s, the OSID and Version of the system", System.OSID, System.Version)
	}
	if System.Match(map[string]string{"ID": System.OSID, "VERSION_ID": "9"}) {
		t.Fatal("Match accepts Debian 9")
	}
	if got, want := registry.SupportList(), "debian 13 amd64 arm64\n"; got != want {
		t.Fatalf("support list %q, want %q", got, want)
	}
}
