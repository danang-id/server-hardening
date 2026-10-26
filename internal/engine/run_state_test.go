// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Danang Galuh Tegar Prasetyo

package engine

import (
	"context"
	"strings"
	"testing"

	"github.com/danang-id/server-hardening/internal/control"
)

func TestCountsAsApplied(t *testing.T) {
	for _, tc := range []struct {
		st            control.State
		apply, revert bool
	}{
		{control.NotApplied, false, false},
		{control.Applied, true, true},
		{control.Pending, true, true},
		// Applied in part: an apply has work left, a revert has work to undo.
		{control.Partial, false, true},
	} {
		if got := counts(tc.st, false); got != tc.apply {
			t.Errorf("apply, state %d: got %v", tc.st, got)
		}
		if got := counts(tc.st, true); got != tc.revert {
			t.Errorf("revert, state %d: got %v", tc.st, got)
		}
	}
}

// setState puts a control into the state that its check will report.
func setState(t *testing.T, sys interface {
	Get(string) (control.Control, bool)
}, id string, st control.State) {
	t.Helper()
	c, ok := sys.Get(id)
	if !ok {
		t.Fatalf("no control %s", id)
	}
	c.(*rec).state = st
}

func TestSelectedPartialControlRunsAgain(t *testing.T) {
	var log []string
	sys := build(&log, meta("misc.a", control.Misc, 1, false))
	setState(t, sys, "misc.a", control.Partial)
	ui := &script{preset: Customize, pick: map[control.Category][]string{control.Misc: {"misc.a"}}}
	if err := Run(context.Background(), env(false), ui, sys, false); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(log, "|"); got != "apply misc.a " {
		t.Fatalf("a control applied in part must run again: %q", got)
	}
}

func TestPartialPrerequisiteIsOfferedAgain(t *testing.T) {
	var log []string
	a := meta("misc.a", control.Misc, 1, false)
	b := meta("misc.b", control.Misc, 2, false)
	b.Requires = []string{"misc.a"}
	sys := build(&log, a, b)
	setState(t, sys, "misc.a", control.Partial)
	ui := &script{preset: Customize, deps: true, pick: map[control.Category][]string{control.Misc: {"misc.b"}}}
	if err := Run(context.Background(), env(false), ui, sys, false); err != nil {
		t.Fatal(err)
	}
	if ui.askedDeps != 1 {
		t.Fatalf("the unfinished prerequisite must be offered: asked %d times", ui.askedDeps)
	}
	if got := strings.Join(log, "|"); got != "apply misc.a |apply misc.b " {
		t.Fatalf("got %q", got)
	}
}

func TestPendingPrerequisiteIsNotRunAgain(t *testing.T) {
	var log []string
	a := meta("misc.a", control.Misc, 1, false)
	b := meta("misc.b", control.Misc, 2, false)
	b.Requires = []string{"misc.a"}
	sys := build(&log, a, b)
	setState(t, sys, "misc.a", control.Pending)
	ui := &script{preset: Customize, pick: map[control.Category][]string{control.Misc: {"misc.b"}}}
	if err := Run(context.Background(), env(false), ui, sys, false); err != nil {
		t.Fatal(err)
	}
	if ui.askedDeps != 0 {
		t.Fatal("a control that only waits for a reboot is done: nothing to ask")
	}
	if got := strings.Join(log, "|"); got != "apply misc.b " {
		t.Fatalf("got %q", got)
	}
}

// seenEntries keeps the entries of the selection, to see how each is offered.
type seenEntries struct {
	script
	entries []Entry
}

func (s *seenEntries) PickControls(ctx context.Context, c control.Category, e []Entry, pre map[string]bool, na string) ([]string, error) {
	s.entries = append(s.entries, e...)
	return s.script.PickControls(ctx, c, e, pre, na)
}

func TestSelectionShowsPendingAsWaitingAndPartialAsOpen(t *testing.T) {
	var log []string
	sys := build(&log,
		meta("misc.a", control.Misc, 1, false),
		meta("misc.b", control.Misc, 2, false),
		meta("misc.c", control.Misc, 3, false),
	)
	setState(t, sys, "misc.a", control.Pending)
	setState(t, sys, "misc.b", control.Partial)
	setState(t, sys, "misc.c", control.Applied)
	ui := &seenEntries{script: script{preset: Customize}}
	if err := Run(context.Background(), env(false), ui, sys, false); err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, e := range ui.entries {
		got[e.Control.Meta().ID] = e.Disabled
	}
	want := map[string]string{"misc.a": "applied, waiting to take effect", "misc.b": "", "misc.c": "already applied"}
	for id, w := range want {
		if got[id] != w {
			t.Errorf("%s: disabled %q, want %q", id, got[id], w)
		}
	}
}

func TestRevertOffersPartialAndPendingControls(t *testing.T) {
	var log []string
	sys := build(&log,
		meta("misc.a", control.Misc, 1, false),
		meta("misc.b", control.Misc, 2, false),
	)
	setState(t, sys, "misc.a", control.Pending)
	setState(t, sys, "misc.b", control.Partial)
	ui := &script{pick: map[control.Category][]string{control.Misc: {"misc.a", "misc.b"}}}
	if err := Run(context.Background(), env(false), ui, sys, true); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(log, "|"); got != "revert misc.b|revert misc.a" {
		t.Fatalf("got %q", got)
	}
}
