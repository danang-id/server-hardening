// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Danang Galuh Tegar Prasetyo

// Package registry holds the systems and their controls, and puts the
// controls in the one fixed run order.
package registry

import (
	"fmt"
	"slices"
	"sort"
	"strings"

	"github.com/danang-id/server-hardening/internal/control"
)

// System is one operating system version, for example Debian 13.
type System struct {
	// OSID is the operating system this version belongs to, as /etc/os-release
	// writes it in ID ("debian"). It tells a version that is not supported
	// apart from an operating system that is not supported at all.
	OSID string
	// Version is the version of that system, as os-release writes VERSION_ID ("13").
	Version string
	ID      string // "debian-13"
	Name    string // "Debian 13 (Trixie)"
	Dir     string // controls folder relative to the repository root
	// NotApplicable lists categories that do not exist on this system, each
	// with the written reason. The same reason is in REFERENCES.md.
	NotApplicable map[control.Category]string
	// Archs lists the processor architectures the system is meant for, in the
	// names Go uses ("amd64", "arm64"). Empty means any.
	Archs []string
	// Match decides from the parsed /etc/os-release whether this is the system.
	Match func(osRelease map[string]string) bool
	// Reference is the text of the system's REFERENCES.md. The screen shows
	// the short description of each control from it.
	Reference string

	controls []control.Control
}

// Add registers a control. It panics on a duplicate ID, which is a bug in the
// code and is also caught by the tests.
func (s *System) Add(c control.Control) {
	id := c.Meta().ID
	for _, x := range s.controls {
		if x.Meta().ID == id {
			panic(fmt.Sprintf("registry: duplicate control %q in %s", id, s.ID))
		}
	}
	s.controls = append(s.controls, c)
}

// Controls returns all controls in the fixed run order: control weight, then
// category number, then control number.
func (s *System) Controls() []control.Control {
	out := append([]control.Control(nil), s.controls...)
	sort.SliceStable(out, func(i, j int) bool { return Less(out[i].Meta(), out[j].Meta()) })
	return out
}

// Less reports whether a sorts before b in the run order.
func Less(a, b control.Meta) bool {
	if wa, wb := a.EffectiveWeight(), b.EffectiveWeight(); wa != wb {
		return wa < wb
	}
	if a.Category != b.Category {
		return a.Category < b.Category
	}
	return a.Number < b.Number
}

// Get finds a control by ID.
func (s *System) Get(id string) (control.Control, bool) {
	for _, c := range s.controls {
		if c.Meta().ID == id {
			return c, true
		}
	}
	return nil, false
}

var systems []*System

// Register adds a system. Each system's package calls it from init.
func Register(s *System) { systems = append(systems, s) }

// Systems returns all registered systems.
func Systems() []*System { return append([]*System(nil), systems...) }

// SupportList says which systems the tool supports, one per line: the
// operating system ID, the version and the architectures, separated by spaces,
// for example "debian 13 amd64 arm64". The entry script reads it from the
// release to decide, before it downloads the tool, whether the tool can run.
func SupportList() string {
	var b strings.Builder
	for _, s := range systems {
		if s.OSID == "" || s.Version == "" {
			continue
		}
		b.WriteString(s.OSID)
		b.WriteString(" ")
		b.WriteString(s.Version)
		for _, a := range s.Archs {
			b.WriteString(" ")
			b.WriteString(a)
		}
		b.WriteByte('\n')
	}
	return b.String()
}

// KnowsOS reports whether some registered system is a version of the
// operating system with this os-release ID.
func KnowsOS(id string) bool {
	for _, s := range systems {
		if s.OSID != "" && s.OSID == id {
			return true
		}
	}
	return false
}

// SupportsArch reports whether the system is meant for the architecture.
func (s *System) SupportsArch(arch string) bool {
	return len(s.Archs) == 0 || slices.Contains(s.Archs, arch)
}

// Archs returns every architecture some registered system is meant for. It is
// empty when no system limits its architectures.
func Archs() []string {
	var out []string
	for _, s := range systems {
		for _, a := range s.Archs {
			if !slices.Contains(out, a) {
				out = append(out, a)
			}
		}
	}
	return out
}

// Detect returns the system that matches the parsed /etc/os-release.
func Detect(osRelease map[string]string) (*System, error) {
	for _, s := range systems {
		if s.Match != nil && s.Match(osRelease) {
			return s, nil
		}
	}
	return nil, fmt.Errorf("unsupported system: %s %s", osRelease["NAME"], osRelease["VERSION_ID"])
}
