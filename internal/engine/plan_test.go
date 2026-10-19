// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Danang Galuh Tegar Prasetyo

package engine

import (
	"context"
	"strings"
	"testing"

	"github.com/danang-id/server-hardening/internal/control"
	"github.com/danang-id/server-hardening/internal/registry"
)

type fake struct{ control.Base }

func (fake) Check(context.Context, *control.Env) (control.State, error) { return 0, nil }
func (fake) Apply(context.Context, *control.Env, control.Values) error  { return nil }
func (fake) Revert(context.Context, *control.Env) error                 { return nil }

func mk(id string, cat control.Category, n int, req ...string) control.Control {
	return fake{control.Base{M: control.Meta{ID: id, Category: cat, Number: n, Title: id, Requires: req}}}
}

// aaa.user <- remote-access.key <- remote-access.keyonly, plus network.fw
func system() *registry.System {
	s := &registry.System{ID: "t"}
	s.Add(mk("aaa.user", control.AAA, 1))
	s.Add(mk("remote-access.key", control.RemoteAccess, 1, "aaa.user"))
	s.Add(mk("remote-access.keyonly", control.RemoteAccess, 2, "aaa.user", "remote-access.key"))
	s.Add(mk("network.fw", control.Network, 1))
	return s
}

func ids(p *Plan) string {
	var s []string
	for _, c := range p.Items {
		s = append(s, c.Meta().ID)
	}
	return strings.Join(s, " ")
}

func none(string) bool { return false }

func TestApplyAddsDependenciesAtTheirOwnPlace(t *testing.T) {
	var asked []Dep
	p, err := BuildApply(system(), []string{"remote-access.keyonly", "network.fw"}, none, func(d []Dep) (bool, error) {
		asked = d
		return true, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if got, want := ids(p), "aaa.user remote-access.key remote-access.keyonly network.fw"; got != want {
		t.Fatalf("got %q want %q", got, want)
	}
	if len(asked) != 2 { // asked once, both extras listed
		t.Fatalf("consent listed %d extras", len(asked))
	}
}

func TestApplyDeclineSkipsOnlyTheControlThatNeededThem(t *testing.T) {
	p, _ := BuildApply(system(), []string{"remote-access.keyonly", "network.fw"}, none, func([]Dep) (bool, error) { return false, nil })
	if got := ids(p); got != "network.fw" {
		t.Fatalf("got %q", got)
	}
	if len(p.Skipped) != 1 || p.Skipped[0].ID != "remote-access.keyonly" {
		t.Fatalf("skipped: %+v", p.Skipped)
	}
}

func TestApplySkipsAppliedDependenciesWithoutAsking(t *testing.T) {
	applied := func(id string) bool { return id == "aaa.user" || id == "remote-access.key" }
	p, _ := BuildApply(system(), []string{"remote-access.keyonly"}, applied, func([]Dep) (bool, error) {
		t.Fatal("consent should not be asked")
		return false, nil
	})
	if got := ids(p); got != "remote-access.keyonly" {
		t.Fatalf("got %q", got)
	}
}

func TestApplyCascadesWhenASelectedDependencyIsDropped(t *testing.T) {
	s := &registry.System{ID: "t"}
	s.Add(mk("aaa.a", control.AAA, 1))
	s.Add(mk("baseline.b", control.Baseline, 1, "aaa.a")) // never sorts after aaa.a? weight equal, baseline first
	_ = s
	// b is selected and needs a (extra). Declining drops b; c needs b and must go too.
	s2 := &registry.System{ID: "t"}
	s2.Add(mk("baseline.a", control.Baseline, 1))
	s2.Add(mk("aaa.b", control.AAA, 1, "baseline.a"))
	s2.Add(mk("network.c", control.Network, 1, "aaa.b"))
	p, _ := BuildApply(s2, []string{"aaa.b", "network.c"}, none, func([]Dep) (bool, error) { return false, nil })
	if len(p.Items) != 0 || len(p.Skipped) != 2 {
		t.Fatalf("plan %q skipped %+v", ids(p), p.Skipped)
	}
}

func TestRevertRunsInReverseAndOffersDependents(t *testing.T) {
	applied := func(string) bool { return true }
	var asked []Dep
	p, _ := BuildRevert(system(), []string{"aaa.user"}, applied, func(d []Dep) (bool, error) {
		asked = d
		return true, nil
	})
	if got, want := ids(p), "remote-access.keyonly remote-access.key aaa.user"; got != want {
		t.Fatalf("got %q want %q", got, want)
	}
	if len(asked) != 2 {
		t.Fatalf("asked %d", len(asked))
	}
}

func TestRevertDeclineSkipsTheTickedControl(t *testing.T) {
	applied := func(string) bool { return true }
	p, _ := BuildRevert(system(), []string{"aaa.user", "network.fw"}, applied, func([]Dep) (bool, error) { return false, nil })
	if got := ids(p); got != "network.fw" {
		t.Fatalf("got %q", got)
	}
}
