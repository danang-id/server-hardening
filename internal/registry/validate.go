// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Danang Galuh Tegar Prasetyo

package registry

import (
	"fmt"
	"strings"

	"github.com/danang-id/server-hardening/internal/control"
)

// Validate checks the rules that every system must follow and returns all
// problems found. The repository tests call it for every system.
func Validate(s *System) []error {
	var errs []error
	bad := func(format string, a ...any) { errs = append(errs, fmt.Errorf(format, a...)) }

	byID := map[string]control.Meta{}
	pos := map[string][2]int{}
	for _, c := range s.controls {
		m := c.Meta()
		if _, dup := byID[m.ID]; dup {
			bad("%s: duplicate ID", m.ID)
		}
		byID[m.ID] = m
	}

	for _, c := range s.controls {
		m := c.Meta()
		slug, name, ok := strings.Cut(m.ID, ".")
		if !ok || name == "" {
			bad("%s: ID must be <category-slug>.<name>", m.ID)
			continue
		}
		if m.Category.Slug() != slug {
			bad("%s: ID prefix %q does not match category %d (%s)", m.ID, slug, m.Category, m.Category.Slug())
		}
		if _, na := s.NotApplicable[m.Category]; na {
			bad("%s: category %s is declared N/A but has a control", m.ID, slug)
		}
		if m.Number < 1 || m.Number > 99 {
			bad("%s: control number %d out of range 1..99", m.ID, m.Number)
		}
		key := [2]int{int(m.Category), m.Number}
		for id, p := range pos {
			if p == key {
				bad("%s and %s share category %d control number %d", m.ID, id, m.Category, m.Number)
			}
		}
		pos[m.ID] = key
		if w := m.EffectiveWeight(); w < 1 || w > 999 {
			bad("%s: weight %d out of range 1..999", m.ID, w)
		}
		if m.Title == "" {
			bad("%s: missing title", m.ID)
		}
		if m.Has(control.TagIrreversible) && m.NoRevertReason == "" {
			bad("%s: tagged irreversible but has no reason", m.ID)
		}
		if m.Has(control.TagIrreversible) && m.Has(control.TagReadonly) {
			bad("%s: irreversible and readonly together", m.ID)
		}
		for _, r := range m.Requires {
			req, ok := byID[r]
			switch {
			case r == m.ID:
				bad("%s: requires itself", m.ID)
			case !ok:
				bad("%s: requires unknown control %s", m.ID, r)
			case !Less(req, m):
				bad("%s: required control %s does not sort earlier in the run order", m.ID, r)
			}
		}
	}
	for cat, reason := range s.NotApplicable {
		if strings.TrimSpace(reason) == "" {
			bad("category %d is N/A without a reason", cat)
		}
	}
	return errs
}

// ValidateCoverage reports every category that has neither a control nor a
// declaration that it does not apply to the system.
func ValidateCoverage(s *System) []error {
	have := map[control.Category]bool{}
	for _, c := range s.controls {
		have[c.Meta().Category] = true
	}
	var errs []error
	for _, cat := range control.Categories() {
		if _, na := s.NotApplicable[cat]; !have[cat] && !na {
			errs = append(errs, fmt.Errorf("category %02d %s has no control and no N/A declaration", cat, cat.Slug()))
		}
	}
	return errs
}
