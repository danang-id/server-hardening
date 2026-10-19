// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Danang Galuh Tegar Prasetyo

package app

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"sync"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/danang-id/server-hardening/internal/control"
	"github.com/danang-id/server-hardening/internal/engine"
	"github.com/danang-id/server-hardening/internal/registry"
	"github.com/danang-id/server-hardening/internal/screen"
)

// fake is a control that records what was done to it.
type fake struct {
	control.Base
	mu    *sync.Mutex
	log   *[]string
	state control.State
	in    []control.Input
	fail  bool
}

func (f *fake) Check(context.Context, *control.Env) (control.State, error) { return f.state, nil }
func (f *fake) Inputs(context.Context, *control.Env) ([]control.Input, error) {
	return f.in, nil
}
func (f *fake) Apply(_ context.Context, _ *control.Env, v control.Values) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	*f.log = append(*f.log, "apply "+f.M.ID+" "+v.String("name"))
	if f.fail {
		return errors.New("boom")
	}
	return nil
}
func (f *fake) Revert(context.Context, *control.Env) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	*f.log = append(*f.log, "revert "+f.M.ID)
	return nil
}

type nopGuard struct{}

func (nopGuard) Arm(context.Context, string, time.Duration) (func(context.Context) error, error) {
	return func(context.Context) error { return nil }, nil
}

type rig struct {
	t      *testing.T
	u      *UI
	ctx    context.Context
	cancel context.CancelFunc
	sys    *registry.System
	env    *control.Env
	log    *[]string
	mu     *sync.Mutex
	logs   *bytes.Buffer
	done   chan error
}

func newRig(t *testing.T, controls ...*fake) *rig {
	t.Helper()
	r := &rig{t: t, log: &[]string{}, mu: &sync.Mutex{}, logs: &bytes.Buffer{}, done: make(chan error, 1)}
	r.ctx, r.cancel = context.WithCancel(context.Background())
	t.Cleanup(r.cancel)
	r.sys = &registry.System{ID: "t", Name: "Test OS", Reference: "### baseline.host\n\n**What it does.** Sets the name.\n\n**Why.** A reason.\n"}
	for _, c := range controls {
		c.mu, c.log = r.mu, r.log
		r.sys.Add(c)
	}
	r.u = New(Options{System: "Test OS", Cancel: r.cancel, Log: r.logs, LogPath: "/tmp/x.log", Output: io.Discard})
	r.u.p.Send(tea.WindowSizeMsg{Width: 100, Height: 30})
	r.env = &control.Env{Root: t.TempDir(), Log: r.u.Logger(), Guard: nopGuard{}}
	return r
}

func (r *rig) start(revert bool) {
	go func() { r.done <- engine.Run(r.ctx, r.env, r.u, r.sys, revert) }()
}

// current asks the program which screen is up. Only the type is safe to use
// outside the program's goroutine.
func (r *rig) current() screen.Screen {
	var s screen.Screen
	r.on(func(m *model) { s = m.cur })
	return s
}

// on runs f on the program's own goroutine, where the screens may be touched.
func (r *rig) on(f func(m *model)) {
	r.t.Helper()
	done := make(chan struct{})
	r.u.p.Send(funcMsg(func(m *model) { f(m); close(done) }))
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		r.t.Fatal("the program does not answer")
	}
}

// text is the current screen as plain text.
func (r *rig) text() string {
	var out string
	r.on(func(m *model) { out = plain(m.screen().View(100, 30)) })
	return out
}

// ticked is the number of ticked controls on the selection screen.
func (r *rig) ticked() int {
	n := -1
	r.on(func(m *model) {
		if s, ok := m.cur.(*screen.Select); ok {
			n = s.Count()
		}
	})
	return n
}

// asking reports whether the run screen has a question up.
func (r *rig) asking() bool {
	var a bool
	r.on(func(m *model) { a = m.cur == screen.Screen(m.run) && m.run != nil && m.run.Asking() })
	return a
}

// waitFor waits until the screen is of type T and returns it.
func waitFor[T screen.Screen](r *rig) {
	r.t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if _, ok := r.current().(T); ok {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	var zero T
	r.t.Fatalf("no %T on the screen; there is %T", zero, r.current())
}

func (r *rig) waitAsking() {
	r.t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if r.asking() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	r.t.Fatal("the lockout question did not appear")
}

func (r *rig) key(k ...string) {
	for _, s := range k {
		var m tea.KeyMsg
		switch s {
		case "enter":
			m = tea.KeyMsg{Type: tea.KeyEnter}
		case "esc":
			m = tea.KeyMsg{Type: tea.KeyEsc}
		case "tab":
			m = tea.KeyMsg{Type: tea.KeyTab}
		default:
			m = tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(s)}
		}
		r.u.p.Send(m)
	}
}

func (r *rig) finish() error {
	r.t.Helper()
	select {
	case err := <-r.done:
		return err
	case <-time.After(5 * time.Second):
		r.t.Fatal("the engine did not finish")
		return nil
	}
}

func meta(id string, cat control.Category, n int, def bool, tags ...control.Tag) control.Meta {
	return control.Meta{ID: id, Category: cat, Number: n, Title: "Title of " + id, Default: def, Tags: tags}
}

func TestApplyFlowFromSelectionToSummary(t *testing.T) {
	r := newRig(t,
		&fake{Base: control.Base{M: meta("baseline.host", control.Baseline, 1, true, control.TagInput)},
			in: []control.Input{{Key: "name", Label: "Name", Default: "web-01"}}},
		&fake{Base: control.Base{M: meta("network.fw", control.Network, 1, true)}},
		&fake{Base: control.Base{M: meta("misc.extra", control.Misc, 1, false)}},
	)
	r.start(false)

	waitFor[*screen.Select](r)
	if n := r.ticked(); n != 2 {
		t.Fatalf("recommended ticks: %d", n)
	}
	r.key("enter")

	waitFor[*screen.Form](r)
	if got := r.text(); !strings.Contains(got, "web-01") {
		t.Fatalf("the form lacks its default:\n%s", got)
	}
	r.key("enter")

	waitFor[*screen.Review](r)
	if got := r.text(); !strings.Contains(got, "Name: web-01") || !strings.Contains(got, "Ready to apply 2 controls") {
		t.Fatalf("review:\n%s", got)
	}
	r.key("enter")

	waitFor[*screen.Summary](r)
	r.key("enter")
	if err := r.finish(); err != nil {
		t.Fatal(err)
	}
	r.u.Close()

	if got := strings.Join(*r.log, "|"); got != "apply baseline.host web-01|apply network.fw " {
		t.Fatalf("applied: %q", got)
	}
	var out bytes.Buffer
	r.u.PrintSummary(&out)
	for _, want := range []string{"Applied: 2", "+ Title of baseline.host", "+ Title of network.fw", "Log: /tmp/x.log"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("summary lacks %q:\n%s", want, out.String())
		}
	}
	if !strings.Contains(r.logs.String(), "Step 1 / 2: Title of baseline.host") {
		t.Errorf("log file:\n%s", r.logs.String())
	}
}

func TestEditFromReviewGoesBackToTheSelection(t *testing.T) {
	r := newRig(t,
		&fake{Base: control.Base{M: meta("baseline.host", control.Baseline, 1, true)}},
		&fake{Base: control.Base{M: meta("network.fw", control.Network, 1, true)}},
	)
	r.start(false)
	waitFor[*screen.Select](r)
	r.key("enter")
	waitFor[*screen.Review](r)
	r.key("e")
	waitFor[*screen.Select](r)
	if n := r.ticked(); n != 2 {
		t.Fatalf("the choice should be kept, got %d ticks", n)
	}
	r.key(" ", "enter") // untick the first one, review again
	waitFor[*screen.Review](r)
	if got := r.text(); !strings.Contains(got, "Ready to apply 1 control") {
		t.Fatalf("review:\n%s", got)
	}
	r.key("enter")
	waitFor[*screen.Summary](r)
	r.key("enter")
	if err := r.finish(); err != nil {
		t.Fatal(err)
	}
	r.u.Close()
	if got := strings.Join(*r.log, "|"); got != "apply network.fw " {
		t.Fatalf("applied: %q", got)
	}
}

func TestBackFromTheFormReturnsToTheSelection(t *testing.T) {
	r := newRig(t, &fake{Base: control.Base{M: meta("baseline.host", control.Baseline, 1, true, control.TagInput)},
		in: []control.Input{{Key: "name", Label: "Name", Default: "x"}}})
	r.start(false)
	waitFor[*screen.Select](r)
	r.key("enter")
	waitFor[*screen.Form](r)
	r.key("esc")
	waitFor[*screen.Select](r)
	r.key("q")
	if err := r.finish(); !errors.Is(err, ErrExit) {
		t.Fatalf("q should be a normal exit, got %v", err)
	}
	r.u.Close()
	if len(*r.log) != 0 {
		t.Fatalf("nothing may run: %v", *r.log)
	}
}

func TestLockoutQuestionIsAnsweredOnTheRunScreen(t *testing.T) {
	r := newRig(t, &fake{Base: control.Base{M: meta("remote-access.keyonly", control.RemoteAccess, 1, true, control.TagLockout)}})
	r.start(false)
	waitFor[*screen.Select](r)
	r.key("enter")
	waitFor[*screen.Review](r)
	r.key("enter")

	r.waitAsking()
	r.key("y")
	waitFor[*screen.Summary](r)
	r.key("enter")
	if err := r.finish(); err != nil {
		t.Fatal(err)
	}
	r.u.Close()
	if got := strings.Join(*r.log, "|"); got != "apply remote-access.keyonly " {
		t.Fatalf("it must stay applied: %q", got)
	}
}

func TestLockoutNoRevertsTheChange(t *testing.T) {
	r := newRig(t, &fake{Base: control.Base{M: meta("remote-access.keyonly", control.RemoteAccess, 1, true, control.TagLockout)}})
	r.start(false)
	waitFor[*screen.Select](r)
	r.key("enter")
	waitFor[*screen.Review](r)
	r.key("enter")
	r.waitAsking()
	r.key("n")
	waitFor[*screen.Summary](r)
	r.key("enter")
	if err := r.finish(); err != nil {
		t.Fatal(err)
	}
	r.u.Close()
	if got := strings.Join(*r.log, "|"); got != "apply remote-access.keyonly |revert remote-access.keyonly" {
		t.Fatalf("got %q", got)
	}
	var out bytes.Buffer
	r.u.PrintSummary(&out)
	if !strings.Contains(out.String(), "failed Title of remote-access.keyonly: not confirmed, so it was undone") {
		t.Fatalf("summary:\n%s", out.String())
	}
}

func TestCtrlCStopsTheEngine(t *testing.T) {
	r := newRig(t, &fake{Base: control.Base{M: meta("baseline.host", control.Baseline, 1, true)}})
	r.start(false)
	waitFor[*screen.Select](r)
	r.key("ctrl+c")
	r.u.p.Send(tea.KeyMsg{Type: tea.KeyCtrlC})
	err := r.finish()
	if !errors.Is(err, ErrAborted) {
		t.Fatalf("ctrl+c is a forced stop, got %v", err)
	}
	if err := r.u.Ended(err); !errors.Is(err, ErrAborted) {
		t.Fatalf("Ended keeps it: %v", err)
	}
	r.u.Close()
}

func TestRevertFlowHasNoQuestions(t *testing.T) {
	r := newRig(t, &fake{Base: control.Base{M: meta("baseline.host", control.Baseline, 1, true, control.TagInput)},
		state: control.Applied, in: []control.Input{{Key: "name", Label: "Name"}}})
	r.start(true)
	waitFor[*screen.Select](r)
	if n := r.ticked(); n != 0 {
		t.Fatal("nothing is ticked in a revert")
	}
	r.key(" ", "enter")
	waitFor[*screen.Review](r)
	r.key("enter")
	waitFor[*screen.Summary](r)
	r.key("enter")
	if err := r.finish(); err != nil {
		t.Fatal(err)
	}
	r.u.Close()
	if got := strings.Join(*r.log, "|"); got != "revert baseline.host" {
		t.Fatalf("got %q", got)
	}
}

func plain(ls []screen.Line) string {
	var b strings.Builder
	for _, l := range ls {
		b.WriteString(l.Plain())
		b.WriteByte('\n')
	}
	return b.String()
}
