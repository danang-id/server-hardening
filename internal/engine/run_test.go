// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Danang Galuh Tegar Prasetyo

package engine

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/danang-id/server-hardening/internal/control"
	"github.com/danang-id/server-hardening/internal/registry"
)

// rec is a control that records what the engine did to it.
type rec struct {
	control.Base
	log      *[]string
	state    control.State
	applyErr error
}

func (r *rec) Check(context.Context, *control.Env) (control.State, error) { return r.state, nil }
func (r *rec) Apply(_ context.Context, _ *control.Env, in control.Values) error {
	*r.log = append(*r.log, "apply "+r.M.ID+" "+in.String("v"))
	if r.applyErr == nil {
		r.state = control.Applied
	}
	return r.applyErr
}
func (r *rec) Revert(context.Context, *control.Env) error {
	*r.log = append(*r.log, "revert "+r.M.ID)
	r.state = control.NotApplied
	return nil
}
func (r *rec) Inputs(context.Context, *control.Env) ([]control.Input, error) {
	if r.M.Has(control.TagInput) {
		return []control.Input{{Key: "v", Label: "v", Default: "d"}}, nil
	}
	return nil, nil
}

type nopLog struct{}

func (nopLog) Infof(string, ...any) {}
func (nopLog) Warnf(string, ...any) {}

// script is a UI that answers from fixed values.
type script struct {
	preset       Preset
	pick         map[control.Category][]string
	deps         bool
	lockoutOK    bool
	lockoutErr   error
	onLockout    func()
	summary      Summary
	askedDeps    int
	lockoutAsked int
	warned       int
	warnErr      error // what WarnIrreversibleLockout returns
}

func (s *script) PickPreset(context.Context) (Preset, error) { return s.preset, nil }
func (s *script) PickControls(_ context.Context, c control.Category, _ []Entry, _ map[string]bool, _ string) ([]string, error) {
	return s.pick[c], nil
}
func (s *script) ConfirmSelection(context.Context, []string, bool) (bool, error) { return true, nil }
func (s *script) ConfirmDependencies(context.Context, []Dep, bool) (bool, error) {
	s.askedDeps++
	return s.deps, nil
}
func (s *script) AskInputs(_ context.Context, c control.Control, in []control.Input) (control.Values, error) {
	return control.Values{in[0].Key: {"answer-" + c.Meta().ID}}, nil
}
func (s *script) ConfirmLockout(context.Context, control.Control, time.Duration) (bool, error) {
	s.lockoutAsked++
	if s.onLockout != nil {
		s.onLockout()
	}
	return s.lockoutOK, s.lockoutErr
}
func (s *script) WarnIrreversibleLockout(context.Context, control.Control) error {
	s.warned++
	return s.warnErr
}
func (s *script) ShowSummary(x Summary) { s.summary = x }

func build(log *[]string, specs ...control.Meta) *registry.System {
	sys := &registry.System{ID: "t"}
	for _, m := range specs {
		sys.Add(&rec{Base: control.Base{M: m}, log: log})
	}
	return sys
}

func env(dry bool) *control.Env { return &control.Env{Log: nopLog{}, DryRun: dry} }

func meta(id string, cat control.Category, n int, def bool, tags ...control.Tag) control.Meta {
	return control.Meta{ID: id, Category: cat, Number: n, Title: id, Default: def, Tags: tags}
}

func TestRecommendedPresetAppliesDefaultsInFixedOrder(t *testing.T) {
	var log []string
	sys := build(&log,
		meta("network.fw", control.Network, 1, true),
		meta("baseline.host", control.Baseline, 1, true, control.TagInput),
		meta("misc.extra", control.Misc, 1, false),
	)
	ui := &script{preset: Recommended}
	if err := Run(context.Background(), env(false), ui, sys, false); err != nil {
		t.Fatal(err)
	}
	got := strings.Join(log, "|")
	want := "apply baseline.host answer-baseline.host|apply network.fw "
	if got != want {
		t.Fatalf("got %q want %q", got, want)
	}
	if len(ui.summary.Done) != 2 {
		t.Fatalf("summary: %+v", ui.summary)
	}
}

func TestDryRunChangesNothingAndAsksNoInputs(t *testing.T) {
	var log []string
	sys := build(&log, meta("baseline.host", control.Baseline, 1, true, control.TagInput))
	ui := &script{preset: Recommended}
	if err := Run(context.Background(), env(true), ui, sys, false); err != nil {
		t.Fatal(err)
	}
	if len(log) != 0 || !ui.summary.Dry || len(ui.summary.Done) != 1 {
		t.Fatalf("log %v summary %+v", log, ui.summary)
	}
}

func TestLockoutNotConfirmedRevertsTheChange(t *testing.T) {
	var log []string
	sys := build(&log, meta("remote-access.keyonly", control.RemoteAccess, 1, true, control.TagLockout))
	ui := &script{preset: Recommended, lockoutOK: false}
	if err := Run(context.Background(), env(false), ui, sys, false); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(log, "|"); got != "apply remote-access.keyonly |revert remote-access.keyonly" {
		t.Fatalf("got %q", got)
	}
	if ui.lockoutAsked != 1 {
		t.Fatal("lockout was not asked")
	}
}

func TestLockoutConfirmedKeepsTheChange(t *testing.T) {
	var log []string
	sys := build(&log, meta("remote-access.keyonly", control.RemoteAccess, 1, true, control.TagLockout))
	ui := &script{preset: Recommended, lockoutOK: true}
	_ = Run(context.Background(), env(false), ui, sys, false)
	if got := strings.Join(log, "|"); got != "apply remote-access.keyonly " {
		t.Fatalf("got %q", got)
	}
}

func TestIrreversibleLockoutWarnsFirstAndNeverReverts(t *testing.T) {
	var log []string
	m := meta("network.networkd", control.Network, 1, true, control.TagLockout, control.TagIrreversible)
	m.NoRevertReason = "cannot be repaired from the server"
	sys := build(&log, m)
	ui := &script{preset: Recommended, lockoutOK: false}
	_ = Run(context.Background(), env(false), ui, sys, false)
	if ui.warned != 1 || ui.lockoutAsked != 0 {
		t.Fatalf("warned %d, lockout asked %d", ui.warned, ui.lockoutAsked)
	}
	if got := strings.Join(log, "|"); got != "apply network.networkd " {
		t.Fatalf("got %q", got)
	}
}

func TestFailedControlDoesNotStopTheRun(t *testing.T) {
	var log []string
	sys := build(&log, meta("baseline.a", control.Baseline, 1, true), meta("baseline.b", control.Baseline, 2, true))
	c, _ := sys.Get("baseline.a")
	c.(*rec).applyErr = context.DeadlineExceeded
	ui := &script{preset: Recommended}
	if err := Run(context.Background(), env(false), ui, sys, false); err != nil {
		t.Fatal(err)
	}
	if len(ui.summary.Failed) != 1 || len(ui.summary.Done) != 1 {
		t.Fatalf("summary: %+v", ui.summary)
	}
}

func TestRevertListsOnlyAppliedAndRunsInReverse(t *testing.T) {
	var log []string
	sys := build(&log,
		meta("baseline.a", control.Baseline, 1, true),
		meta("baseline.b", control.Baseline, 2, true),
		meta("baseline.c", control.Baseline, 3, true),
	)
	for id, st := range map[string]control.State{"baseline.a": control.Applied, "baseline.b": control.NotApplied, "baseline.c": control.Applied} {
		c, _ := sys.Get(id)
		c.(*rec).state = st
	}
	ui := &script{pick: map[control.Category][]string{control.Baseline: {"baseline.a", "baseline.c"}}}
	if err := Run(context.Background(), env(false), ui, sys, true); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(log, "|"); got != "revert baseline.c|revert baseline.a" {
		t.Fatalf("got %q", got)
	}
}

// fakeGuard records when the automatic undo is armed and disarmed.
type fakeGuard struct {
	log       *[]string
	armErr    error
	disarmErr error
}

func (g *fakeGuard) Arm(_ context.Context, id string, w time.Duration) (func(context.Context) error, error) {
	if g.armErr != nil {
		return nil, g.armErr
	}
	if w != LockoutWindow {
		panic("unexpected window")
	}
	*g.log = append(*g.log, "arm "+id)
	return func(context.Context) error {
		*g.log = append(*g.log, "disarm "+id)
		return g.disarmErr
	}, nil
}

func guarded(log *[]string, g *fakeGuard) (*registry.System, *control.Env) {
	sys := build(log, meta("remote-access.keyonly", control.RemoteAccess, 1, true, control.TagLockout))
	e := env(false)
	e.Guard = g
	return sys, e
}

func TestGuardIsArmedBeforeTheChangeAndDisarmedWhenConfirmed(t *testing.T) {
	var log []string
	sys, e := guarded(&log, &fakeGuard{log: &log})
	ui := &script{preset: Recommended, lockoutOK: true}
	if err := Run(context.Background(), e, ui, sys, false); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(log, "|"); got != "arm remote-access.keyonly|apply remote-access.keyonly |disarm remote-access.keyonly" {
		t.Fatalf("got %q", got)
	}
	if len(ui.summary.Done) != 1 || len(ui.summary.Failed) != 0 {
		t.Fatalf("summary: %+v", ui.summary)
	}
}

func TestGuardIsDisarmedBeforeANoRevert(t *testing.T) {
	var log []string
	sys, e := guarded(&log, &fakeGuard{log: &log})
	ui := &script{preset: Recommended, lockoutOK: false}
	if err := Run(context.Background(), e, ui, sys, false); err != nil {
		t.Fatal(err)
	}
	want := "arm remote-access.keyonly|apply remote-access.keyonly |disarm remote-access.keyonly|revert remote-access.keyonly"
	if got := strings.Join(log, "|"); got != want {
		t.Fatalf("got %q", got)
	}
	if len(ui.summary.Done) != 0 || len(ui.summary.Failed) != 1 || !strings.Contains(ui.summary.Failed[0].Reason, "undone") {
		t.Fatalf("an undone control must not be listed as done: %+v", ui.summary)
	}
}

func TestGuardStaysArmedWhenThePromptEndsWithoutAnAnswer(t *testing.T) {
	var log []string
	sys, e := guarded(&log, &fakeGuard{log: &log})
	aborted := errors.New("aborted")
	ui := &script{preset: Recommended, lockoutErr: aborted}
	err := Run(context.Background(), e, ui, sys, false)
	if !errors.Is(err, aborted) {
		t.Fatalf("err = %v", err)
	}
	if got := strings.Join(log, "|"); got != "arm remote-access.keyonly|apply remote-access.keyonly " {
		t.Fatalf("the timer must stay armed and nothing be reverted by the tool: %q", got)
	}
}

func TestGuardIsDisarmedWhenTheChangeFails(t *testing.T) {
	var log []string
	sys, e := guarded(&log, &fakeGuard{log: &log})
	c, _ := sys.Get("remote-access.keyonly")
	c.(*rec).applyErr = errors.New("boom")
	ui := &script{preset: Recommended}
	if err := Run(context.Background(), e, ui, sys, false); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(log, "|"); got != "arm remote-access.keyonly|apply remote-access.keyonly |disarm remote-access.keyonly" {
		t.Fatalf("got %q", got)
	}
	if ui.lockoutAsked != 0 {
		t.Fatal("a failed change needs no lockout check")
	}
}

func TestTimerThatFiredFirstIsReportedAndNotRevertedTwice(t *testing.T) {
	var log []string
	sys, e := guarded(&log, &fakeGuard{log: &log, disarmErr: errors.New("unit not loaded")})
	c, _ := sys.Get("remote-access.keyonly")
	// While the user thinks, the timer reverts the control.
	ui := &script{preset: Recommended, lockoutOK: true, onLockout: func() { c.(*rec).state = control.NotApplied }}
	if err := Run(context.Background(), e, ui, sys, false); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(strings.Join(log, "|"), "revert") {
		t.Fatalf("the tool must not revert again: %v", log)
	}
	if len(ui.summary.Failed) != 1 || !strings.Contains(ui.summary.Failed[0].Reason, "automatic undo") || len(ui.summary.Done) != 0 {
		t.Fatalf("summary: %+v", ui.summary)
	}
}

func TestStillAppliedMeansADisarmErrorIsOnlyAWarning(t *testing.T) {
	var log []string
	sys, e := guarded(&log, &fakeGuard{log: &log, disarmErr: errors.New("odd")})
	ui := &script{preset: Recommended, lockoutOK: true}
	if err := Run(context.Background(), e, ui, sys, false); err != nil {
		t.Fatal(err)
	}
	if len(ui.summary.Done) != 1 {
		t.Fatalf("summary: %+v", ui.summary)
	}
}

func TestRunWithoutAGuardStillRevertsWhenNotConfirmed(t *testing.T) {
	var log []string
	sys, e := guarded(&log, &fakeGuard{log: &log, armErr: errors.New("no systemd")})
	ui := &script{preset: Recommended, lockoutOK: false}
	if err := Run(context.Background(), e, ui, sys, false); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(log, "|"); got != "apply remote-access.keyonly |revert remote-access.keyonly" {
		t.Fatalf("got %q", got)
	}
	e.Guard = nil
	log = nil
	ui = &script{preset: Recommended, lockoutOK: false}
	_ = Run(context.Background(), e, ui, sys, false)
	if got := strings.Join(log, "|"); got != "apply remote-access.keyonly |revert remote-access.keyonly" {
		t.Fatalf("no guard at all: %q", got)
	}
}

func TestIrreversibleLockoutIsNeverGuarded(t *testing.T) {
	var log []string
	m := meta("network.networkd", control.Network, 1, true, control.TagLockout, control.TagIrreversible)
	m.NoRevertReason = "cannot be repaired from the server"
	sys := build(&log, m)
	e := env(false)
	e.Guard = &fakeGuard{log: &log}
	_ = Run(context.Background(), e, &script{preset: Recommended}, sys, false)
	if got := strings.Join(log, "|"); got != "apply network.networkd " {
		t.Fatalf("got %q", got)
	}
}

func TestRevertRunsAreNotGuarded(t *testing.T) {
	var log []string
	sys, e := guarded(&log, &fakeGuard{log: &log})
	c, _ := sys.Get("remote-access.keyonly")
	c.(*rec).state = control.Applied
	ui := &script{pick: map[control.Category][]string{control.RemoteAccess: {"remote-access.keyonly"}}}
	if err := Run(context.Background(), e, ui, sys, true); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(log, "|"); got != "revert remote-access.keyonly" {
		t.Fatalf("got %q", got)
	}
}

// finRec is a control with a last step.
type finRec struct{ *rec }

func (f finRec) Finalize(context.Context, *control.Env) error {
	*f.log = append(*f.log, "finalize "+f.M.ID)
	return nil
}

func TestFinalizeRunsOnlyAfterTheChangeIsConfirmed(t *testing.T) {
	for _, ok := range []bool{true, false} {
		var log []string
		sys := &registry.System{ID: "t"}
		sys.Add(finRec{&rec{Base: control.Base{M: meta("remote-access.port", control.RemoteAccess, 1, true, control.TagLockout)}, log: &log}})
		ui := &script{preset: Recommended, lockoutOK: ok}
		if err := Run(context.Background(), env(false), ui, sys, false); err != nil {
			t.Fatal(err)
		}
		got := strings.Join(log, "|")
		if ok && got != "apply remote-access.port |finalize remote-access.port" {
			t.Fatalf("confirmed: %q", got)
		}
		if !ok && got != "apply remote-access.port |revert remote-access.port" {
			t.Fatalf("not confirmed: %q", got)
		}
	}
}

func TestFinalizeFailureIsAWarningNotAFailure(t *testing.T) {
	var log []string
	sys := &registry.System{ID: "t"}
	sys.Add(failFin{finRec{&rec{Base: control.Base{M: meta("remote-access.port", control.RemoteAccess, 1, true)}, log: &log}}})
	ui := &script{preset: Recommended}
	if err := Run(context.Background(), env(false), ui, sys, false); err != nil {
		t.Fatal(err)
	}
	if len(ui.summary.Done) != 1 {
		t.Fatalf("summary: %+v", ui.summary)
	}
}

type failFin struct{ finRec }

func (failFin) Finalize(context.Context, *control.Env) error { return errors.New("no") }

// actionRec is a control that counts its checks.
type actionRec struct {
	rec
	checks *int
}

func (a *actionRec) Check(ctx context.Context, e *control.Env) (control.State, error) {
	*a.checks++
	return a.rec.Check(ctx, e)
}

// seen is a UI that remembers the entries it was shown.
type seen struct {
	*script
	entries []Entry
}

func (s *seen) PickControls(ctx context.Context, c control.Category, e []Entry, pre map[string]bool, na string) ([]string, error) {
	s.entries = append(s.entries, e...)
	return s.script.PickControls(ctx, c, e, pre, na)
}

func TestActionControlIsNeverCheckedOrCalledApplied(t *testing.T) {
	var log []string
	var checks int
	m := meta("baseline.upgrade", control.Baseline, 1, true)
	m.Action = true
	// The control would say "applied", if it were asked.
	sys := &registry.System{ID: "t"}
	sys.Add(&actionRec{rec: rec{Base: control.Base{M: m}, log: &log, state: control.Applied}, checks: &checks})
	ui := &seen{script: &script{preset: Customize, pick: map[control.Category][]string{control.Baseline: {"baseline.upgrade"}}}}
	if err := Run(context.Background(), env(false), ui, sys, false); err != nil {
		t.Fatal(err)
	}
	if checks != 0 {
		t.Fatalf("an action is never checked, got %d checks", checks)
	}
	if len(ui.entries) != 1 || ui.entries[0].Disabled != "" || ui.entries[0].State != control.NotApplied {
		t.Fatalf("an action must always be offered: %+v", ui.entries)
	}
	if got := strings.Join(log, "|"); got != "apply baseline.upgrade " {
		t.Fatalf("it must run when chosen: %q", got)
	}
}

// idleAction is an action that says it has nothing to do.
type idleAction struct {
	actionRec
	why string
}

func (a *idleAction) Idle(context.Context, *control.Env) string { return a.why }

func TestIdleActionIsShownAsUnavailableNotApplied(t *testing.T) {
	var log []string
	var checks int
	m := meta("asr.remove", control.ASR, 1, true)
	m.Action = true
	sys := &registry.System{ID: "t"}
	sys.Add(&idleAction{actionRec: actionRec{rec: rec{Base: control.Base{M: m}, log: &log}, checks: &checks}, why: "nothing to remove"})
	ui := &seen{script: &script{preset: Customize, pick: map[control.Category][]string{}}}
	if err := Run(context.Background(), env(false), ui, sys, false); err != nil {
		t.Fatal(err)
	}
	if len(ui.entries) != 1 {
		t.Fatalf("entries: %+v", ui.entries)
	}
	if e := ui.entries[0]; e.Disabled != "nothing to remove" || e.State != control.NotApplied {
		t.Fatalf("an idle action says why it is idle, never \"already applied\": %+v", e)
	}
	if checks != 0 {
		t.Fatalf("an action is never checked, got %d", checks)
	}
}

// Declining the warning of one irreversible control skips that control and
// what needs it. Everything else still runs, and the run ends normally.
func TestDecliningTheWarningSkipsOnlyThatControlAndItsDependents(t *testing.T) {
	var log []string
	a := meta("baseline.a", control.Baseline, 1, true)
	nw := meta("network.networkd", control.Network, 1, true, control.TagLockout, control.TagIrreversible)
	nw.NoRevertReason = "cannot be repaired from the server"
	dns := meta("network.dns", control.Network, 2, true)
	dns.Requires = []string{"network.networkd"}
	z := meta("system-kernel.z", control.SystemKernel, 1, true)
	sys := build(&log, a, nw, dns, z)
	ui := &script{preset: Recommended, warnErr: ErrSkip}
	if err := Run(context.Background(), env(false), ui, sys, false); err != nil {
		t.Fatalf("declining one control must not end the run: %v", err)
	}
	if got := strings.Join(log, "|"); got != "apply baseline.a |apply system-kernel.z " {
		t.Fatalf("only the unrelated controls run: %q", got)
	}
	var skipped []string
	for _, s := range ui.summary.Skipped {
		skipped = append(skipped, s.ID+": "+s.Reason)
	}
	want := "network.networkd: you chose not to continue|network.dns: needs network.networkd, which did not run"
	if got := strings.Join(skipped, "|"); got != want {
		t.Fatalf("skipped:\n got %q\nwant %q", got, want)
	}
	if len(ui.summary.Failed) != 0 || len(ui.summary.Done) != 2 {
		t.Fatalf("summary: %+v", ui.summary)
	}
}

// Any other error from the warning, such as the user quitting, still ends the run.
func TestOtherWarningErrorsStillEndTheRun(t *testing.T) {
	var log []string
	nw := meta("network.networkd", control.Network, 1, true, control.TagLockout, control.TagIrreversible)
	nw.NoRevertReason = "x"
	z := meta("system-kernel.z", control.SystemKernel, 1, true)
	sys := build(&log, nw, z)
	quit := errors.New("quit")
	ui := &script{preset: Recommended, warnErr: quit}
	if err := Run(context.Background(), env(false), ui, sys, false); !errors.Is(err, quit) {
		t.Fatalf("err = %v", err)
	}
	if len(log) != 0 {
		t.Fatalf("nothing should have run: %v", log)
	}
}

// A control whose prerequisite failed does not run on top of nothing.
func TestControlAfterFailedPrerequisiteIsSkipped(t *testing.T) {
	var log []string
	a := meta("baseline.a", control.Baseline, 1, true)
	b := meta("baseline.b", control.Baseline, 2, true)
	b.Requires = []string{"baseline.a"}
	sys := build(&log, a, b)
	if c, ok := sys.Get("baseline.a"); ok {
		c.(*rec).applyErr = errors.New("boom")
	}
	ui := &script{preset: Recommended}
	if err := Run(context.Background(), env(false), ui, sys, false); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(log, "|"); got != "apply baseline.a " {
		t.Fatalf("b must not run after a failed: %q", got)
	}
}
