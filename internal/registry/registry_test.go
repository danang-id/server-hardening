// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Danang Galuh Tegar Prasetyo

package registry

import (
	"context"
	"strings"
	"testing"

	"github.com/danang-id/server-hardening/internal/control"
)

type fake struct {
	control.Base
}

func (fake) Check(context.Context, *control.Env) (control.State, error) { return 0, nil }
func (fake) Apply(context.Context, *control.Env, control.Values) error  { return nil }
func (fake) Revert(context.Context, *control.Env) error                 { return nil }

func mk(id string, cat control.Category, n, w int, req ...string) control.Control {
	return fake{control.Base{M: control.Meta{ID: id, Category: cat, Number: n, Weight: w, Title: id, Requires: req}}}
}

func ids(cs []control.Control) string {
	var s []string
	for _, c := range cs {
		s = append(s, c.Meta().ID)
	}
	return strings.Join(s, " ")
}

func TestRunOrder(t *testing.T) {
	s := &System{ID: "t"}
	s.Add(mk("misc.late", control.Misc, 1, 990))
	s.Add(mk("network.b", control.Network, 2, 0))
	s.Add(mk("baseline.a", control.Baseline, 1, 0))
	s.Add(mk("network.a", control.Network, 1, 0))
	s.Add(mk("aaa.early", control.AAA, 1, 100))
	want := "aaa.early baseline.a network.a network.b misc.late"
	if got := ids(s.Controls()); got != want {
		t.Fatalf("got %q want %q", got, want)
	}
}

func TestValidate(t *testing.T) {
	s := &System{ID: "t"}
	s.Add(mk("baseline.a", control.Baseline, 1, 0))
	s.Add(mk("baseline.b", control.Baseline, 2, 0, "baseline.a"))
	if errs := Validate(s); len(errs) != 0 {
		t.Fatalf("unexpected: %v", errs)
	}

	cases := map[string]*System{
		"does not sort earlier":   {controls: []control.Control{mk("baseline.a", control.Baseline, 2, 0, "baseline.b"), mk("baseline.b", control.Baseline, 3, 0)}},
		"requires itself":         {controls: []control.Control{mk("baseline.a", control.Baseline, 1, 0, "baseline.a")}},
		"requires unknown":        {controls: []control.Control{mk("baseline.a", control.Baseline, 1, 0, "aaa.x")}},
		"does not match category": {controls: []control.Control{mk("aaa.a", control.Baseline, 1, 0)}},
		"share category":          {controls: []control.Control{mk("baseline.a", control.Baseline, 1, 0), mk("baseline.b", control.Baseline, 1, 0)}},
	}
	for want, sys := range cases {
		found := false
		for _, e := range Validate(sys) {
			if strings.Contains(e.Error(), want) {
				found = true
			}
		}
		if !found {
			t.Errorf("expected an error containing %q, got %v", want, Validate(sys))
		}
	}
}

func TestDependencyOnLowerWeightIsAccepted(t *testing.T) {
	// A required control with a lower weight sorts earlier even in a later category.
	s := &System{controls: []control.Control{mk("misc.a", control.Misc, 1, 100), mk("baseline.b", control.Baseline, 1, 0, "misc.a")}}
	if errs := Validate(s); len(errs) != 0 {
		t.Fatalf("unexpected: %v", errs)
	}
}

func TestCoverageNeedsEveryCategory(t *testing.T) {
	s := &System{controls: []control.Control{mk("baseline.a", control.Baseline, 1, 0)}}
	if len(ValidateCoverage(s)) != 9 {
		t.Fatalf("want 9 missing categories, got %v", ValidateCoverage(s))
	}
	s.NotApplicable = map[control.Category]string{control.AAA: "no accounts here"}
	if len(ValidateCoverage(s)) != 8 {
		t.Fatalf("N/A with a reason should count: %v", ValidateCoverage(s))
	}
}
