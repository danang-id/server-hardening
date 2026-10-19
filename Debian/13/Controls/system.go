// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Danang Galuh Tegar Prasetyo

// Package controls holds the hardening controls for Debian 13 (Trixie).
//
// Each control is one file named <CC><NN>_<category>.<control-name>.go, where
// CC is the category number and NN the control number. A test checks that the
// filename matches the control's own metadata.
package controls

import (
	debian13 "github.com/danang-id/server-hardening/Debian/13"
	"github.com/danang-id/server-hardening/internal/control"
	"github.com/danang-id/server-hardening/internal/registry"
)

// System is Debian 13. Each control file adds itself with System.Add from
// its init function. The registry sorts them lazily, so init order between
// files does not matter.
var System = &registry.System{
	OSID:      "debian",
	Version:   "13",
	ID:        "debian-13",
	Name:      "Debian 13 (Trixie)",
	Dir:       "Debian/13/Controls",
	Reference: debian13.Reference,
	// The architectures Debian 13 is released for that this tool is meant to
	// be used on.
	Archs: []string{"amd64", "arm64"},
	Match: func(r map[string]string) bool {
		return r["ID"] == "debian" && r["VERSION_ID"] == "13"
	},
	NotApplicable: map[control.Category]string{},
}

func init() { registry.Register(System) }
