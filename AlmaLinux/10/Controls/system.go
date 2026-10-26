// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Danang Galuh Tegar Prasetyo

// Package controls holds the hardening controls for AlmaLinux 10.
//
// Each control is one file named <CC><NN>_<category>.<control-name>.go, where
// CC is the category number and NN the control number. A test checks that the
// filename matches the control's own metadata.
package controls

import (
	"strings"

	almalinux10 "github.com/danang-id/server-hardening/AlmaLinux/10"
	"github.com/danang-id/server-hardening/internal/control"
	"github.com/danang-id/server-hardening/internal/registry"
)

// System is AlmaLinux 10, every minor release of it. The controls are tested
// on the latest minor release, which is 10.2. Each control file adds itself
// with System.Add from its init function. The registry sorts them lazily, so
// init order between files does not matter.
var System = &registry.System{
	OSID:      "almalinux",
	Version:   "10",
	ID:        "almalinux-10",
	Name:      "AlmaLinux 10 (Heliotrope Lion)",
	Dir:       "AlmaLinux/10/Controls",
	Reference: almalinux10.Reference,
	// The architectures AlmaLinux 10 is released for that this tool is meant
	// to be used on.
	Archs: []string{"amd64", "arm64"},
	// os-release writes VERSION_ID as "10.2": the major version is what counts.
	Match: func(r map[string]string) bool {
		major, _, _ := strings.Cut(r["VERSION_ID"], ".")
		return r["ID"] == "almalinux" && major == "10"
	},
	NotApplicable: map[control.Category]string{},
}

func init() { registry.Register(System) }
