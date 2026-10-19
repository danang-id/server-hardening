// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Danang Galuh Tegar Prasetyo

// Package engine builds and runs apply and revert plans.
package engine

import (
	"sort"

	"github.com/danang-id/server-hardening/internal/control"
	"github.com/danang-id/server-hardening/internal/registry"
)

// Dep is one extra control that a plan needs, and which controls need it.
type Dep struct {
	Control    control.Control
	RequiredBy []string // IDs
}

// Skipped explains why a selected control is not in the plan.
type Skipped struct {
	ID     string
	Reason string
}

// Plan is the ordered list of controls to run. The order is the system's
// fixed run order for an apply, and its reverse for a revert. The user's
// selection only filters that order.
type Plan struct {
	Items   []control.Control
	Added   []string // IDs added as dependencies (apply) or dependents (revert)
	Skipped []Skipped
}

// Consent asks the user once about all extra controls. It returns true to add
// them. On false, only the controls that needed them are skipped.
type Consent func(extra []Dep) (bool, error)

// BuildApply builds the plan for applying the selected controls.
// applied says whether a control's check reports it as applied already.
func BuildApply(sys *registry.System, selected []string, applied func(id string) bool, consent Consent) (*Plan, error) {
	want := map[string]bool{}
	plan := &Plan{}
	for _, id := range selected {
		if applied(id) {
			plan.Skipped = append(plan.Skipped, Skipped{id, "already applied"})
			continue
		}
		want[id] = true
	}

	// Find the extra controls: those that are required, not applied and not
	// selected, directly or through other controls.
	extra := map[string][]string{}
	var walk func(id, by string)
	seen := map[string]bool{}
	walk = func(id, by string) {
		c, ok := sys.Get(id)
		if !ok {
			return
		}
		for _, r := range c.Meta().Requires {
			if applied(r) {
				continue
			}
			if !want[r] {
				extra[r] = append(extra[r], by)
			}
			if !seen[r] {
				seen[r] = true
				walk(r, by)
			}
		}
	}
	for id := range want {
		walk(id, id)
	}

	if len(extra) > 0 {
		deps := make([]Dep, 0, len(extra))
		for id, by := range extra {
			c, _ := sys.Get(id)
			deps = append(deps, Dep{Control: c, RequiredBy: dedupe(by)})
		}
		sortDeps(deps)
		yes, err := consent(deps)
		if err != nil {
			return nil, err
		}
		if yes {
			for id := range extra {
				want[id] = true
				plan.Added = append(plan.Added, id)
			}
			sort.Strings(plan.Added)
		} else {
			// Drop every selected control whose requirements are not met,
			// repeating until nothing more falls out.
			for changed := true; changed; {
				changed = false
				for id := range want {
					c, _ := sys.Get(id)
					for _, r := range c.Meta().Requires {
						if !applied(r) && !want[r] {
							delete(want, id)
							plan.Skipped = append(plan.Skipped, Skipped{id, "needs " + r + ", which was declined"})
							changed = true
							break
						}
					}
				}
			}
		}
	}

	for _, c := range sys.Controls() {
		if want[c.Meta().ID] {
			plan.Items = append(plan.Items, c)
		}
	}
	return plan, nil
}

// BuildRevert builds the plan for reverting the selected controls. Applied
// controls that require a selected control are offered too. Items come in the
// reverse of the run order.
func BuildRevert(sys *registry.System, selected []string, applied func(id string) bool, consent Consent) (*Plan, error) {
	want := map[string]bool{}
	for _, id := range selected {
		want[id] = true
	}
	plan := &Plan{}

	// Applied controls that depend, directly or not, on a selected control.
	extra := map[string][]string{}
	for changed := true; changed; {
		changed = false
		for _, c := range sys.Controls() {
			m := c.Meta()
			if !applied(m.ID) || !m.Revertible() {
				continue
			}
			for _, r := range m.Requires {
				if (want[r] || extra[r] != nil) && !want[m.ID] && !contains(extra[m.ID], r) {
					extra[m.ID] = append(extra[m.ID], r)
					changed = true
				}
			}
		}
	}
	if len(extra) > 0 {
		deps := make([]Dep, 0, len(extra))
		for id, by := range extra {
			c, _ := sys.Get(id)
			deps = append(deps, Dep{Control: c, RequiredBy: dedupe(by)}) // here: the controls it depends on
		}
		sortDeps(deps)
		yes, err := consent(deps)
		if err != nil {
			return nil, err
		}
		if yes {
			for id := range extra {
				want[id] = true
				plan.Added = append(plan.Added, id)
			}
			sort.Strings(plan.Added)
		} else {
			// A control with applied dependents is skipped, because reverting it would
			// leave them half working.
			blocked := map[string]bool{}
			for _, by := range extra {
				for _, r := range by {
					blocked[r] = true
				}
			}
			for id := range blocked {
				if want[id] {
					delete(want, id)
					plan.Skipped = append(plan.Skipped, Skipped{id, "other applied controls depend on it"})
				}
			}
		}
	}

	all := sys.Controls()
	for i := len(all) - 1; i >= 0; i-- {
		if want[all[i].Meta().ID] {
			plan.Items = append(plan.Items, all[i])
		}
	}
	return plan, nil
}

func dedupe(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return out
}

func contains(l []string, s string) bool {
	for _, x := range l {
		if x == s {
			return true
		}
	}
	return false
}

func sortDeps(d []Dep) {
	sort.Slice(d, func(i, j int) bool { return registry.Less(d[i].Control.Meta(), d[j].Control.Meta()) })
}
