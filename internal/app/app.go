// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Danang Galuh Tegar Prasetyo

// Package app connects the full-screen interface to the engine. One Bubble Tea
// program runs for the whole session. Each question the engine asks becomes a
// screen, and the engine waits for the answer.
package app

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/danang-id/server-hardening/internal/control"
	"github.com/danang-id/server-hardening/internal/engine"
	"github.com/danang-id/server-hardening/internal/screen"
	"github.com/danang-id/server-hardening/internal/sysdetect"
	"github.com/danang-id/server-hardening/internal/tui"
)

// ErrAborted is returned when the user stops the program with ctrl+c. That is
// a forced stop, not a choice made in the program, so it ends with a failure
// status.
var ErrAborted = tui.ErrAborted

// ErrExit is returned when the user leaves on purpose, with q or the Exit
// button. It is a normal end, not a failure.
var ErrExit = errors.New("the user chose to exit")

// UI implements engine.UI, engine.Guided and engine.Progress.
type UI struct {
	system  string
	revert  bool
	cancel  context.CancelFunc
	p       *tea.Program
	done    chan struct{} // closed when the program has ended
	aborted chan struct{} // closed when the user left on purpose
	abortMu sync.Once
	ctrlC   atomic.Bool // the user left with ctrl+c, not with q or a button
	logFile io.Writer
	logPath string
	host    func() string // the machine name for the header; may be nil

	mu      sync.Mutex
	titles  map[string]string // control ID to title, for the summary and the questions
	summary *screen.SummaryData
}

var (
	_ engine.UI       = (*UI)(nil)
	_ engine.Guided   = (*UI)(nil)
	_ engine.Progress = (*UI)(nil)
)

// Options are what New needs.
type Options struct {
	System  string
	Theme   screen.Theme
	Cancel  context.CancelFunc // stops the engine when the user leaves
	Log     io.Writer          // receives every log line; may be nil
	LogPath string             // shown in the summary
	Host    func() string      // the machine name shown in the header; read often, so keep it cheap

	// Input and Output replace the terminal. Tests use them to run without
	// one. When Output is nil, the real terminal is used.
	Input  io.Reader
	Output io.Writer
}

// New starts the program on the terminal.
func New(o Options) *UI {
	u := &UI{
		system: o.System, cancel: o.Cancel, logFile: o.Log, logPath: o.LogPath, host: o.Host,
		done: make(chan struct{}), aborted: make(chan struct{}),
		titles: map[string]string{},
	}
	m := &model{ui: u, th: o.Theme, now: time.Now(), busy: &screen.Busy{System: o.System, Msg: "Checking this system…"}}
	opts := []tea.ProgramOption{tea.WithAltScreen()}
	if o.Output != nil {
		opts = append(opts, tea.WithInput(o.Input), tea.WithOutput(o.Output))
	}
	u.p = tea.NewProgram(m, opts...)
	go func() {
		if _, err := u.p.Run(); errors.Is(err, tea.ErrInterrupted) {
			u.ctrlC.Store(true) // a SIGINT that reached the program
		}
		u.abort() // a program that ends by itself (a signal) counts as the user leaving
		close(u.done)
	}()
	return u
}

// quitErr is the error for a user who has left: ErrAborted after ctrl+c and
// ErrExit after q.
func (u *UI) quitErr() error {
	if u.ctrlC.Load() {
		return ErrAborted
	}
	return ErrExit
}

// Ended says what a finished run means. After the user left, whatever error
// the engine gave on the way out (it was told to stop, so it often says
// "canceled") is replaced by ErrExit or ErrAborted. Any other error is
// returned as it is.
func (u *UI) Ended(err error) error {
	if err == nil {
		return nil
	}
	select {
	case <-u.aborted:
	default:
		return err
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, ErrAborted) || errors.Is(err, ErrExit) {
		return u.quitErr()
	}
	return err
}

// abort records that the user left and stops the engine.
func (u *UI) abort() {
	u.abortMu.Do(func() {
		close(u.aborted)
		if u.cancel != nil {
			u.cancel()
		}
	})
}

// Close ends the program and restores the terminal.
func (u *UI) Close() {
	u.p.Quit()
	<-u.done
}

// PrintSummary writes the last summary as plain text. It is for after Close,
// because the alt screen is gone by then and so is the summary on it.
func (u *UI) PrintSummary(w io.Writer) {
	u.mu.Lock()
	d := u.summary
	u.mu.Unlock()
	if d == nil {
		return
	}
	verb := "Applied"
	switch {
	case d.Dry:
		verb = "Would run (dry run, nothing changed)"
	case d.Revert:
		verb = "Reverted"
	}
	fmt.Fprintf(w, "%s: %d\n", verb, len(d.Done))
	for _, x := range d.Done {
		fmt.Fprintf(w, "  + %s\n", x)
	}
	if len(d.Added) > 0 {
		fmt.Fprintf(w, "Added because others need them: %s\n", strings.Join(d.Added, ", "))
	}
	for _, x := range d.Skipped {
		fmt.Fprintf(w, "  - skipped %s: %s\n", x.Title, x.Reason)
	}
	for _, x := range d.Failed {
		fmt.Fprintf(w, "  ! failed %s: %s\n", x.Title, x.Reason)
	}
	for _, x := range d.Partial {
		fmt.Fprintf(w, "  ~ %s was reverted only in part\n", x)
	}
	if d.Reboot && !d.Dry {
		fmt.Fprintln(w, "A reboot is needed to finish some changes.")
	}
	if d.LogFile != "" {
		fmt.Fprintf(w, "Log: %s\n", d.LogFile)
	}
}

// ask shows a screen and waits until it is done.
func (u *UI) ask(ctx context.Context, s screen.Screen) (screen.Event, error) {
	ch := make(chan screen.Event, 1)
	u.p.Send(showMsg{s: s, reply: ch})
	return u.wait(ctx, ch)
}

func (u *UI) wait(ctx context.Context, ch <-chan screen.Event) (screen.Event, error) {
	select {
	case ev := <-ch:
		if ev == screen.Quit {
			return ev, u.quitErr()
		}
		return ev, nil
	case <-u.aborted:
		return screen.Quit, u.quitErr()
	case <-ctx.Done():
		select {
		case <-u.aborted:
			return screen.Quit, u.quitErr()
		default:
		}
		return screen.Quit, ctx.Err()
	}
}

func (u *UI) title(id string) string {
	u.mu.Lock()
	defer u.mu.Unlock()
	if t, ok := u.titles[id]; ok {
		return t
	}
	return id
}

func (u *UI) titlesOf(ids []string) []string {
	out := make([]string, len(ids))
	for i, id := range ids {
		out[i] = u.title(id)
	}
	return out
}

// Welcome shows the first screen: the machine, whether it is supported, and
// Start or Exit. reasons is why the machine is not supported, empty when it is.
// It returns nil when the user chose Start, and ErrExit when the user chose to
// leave, which is a normal way to end.
func (u *UI) Welcome(ctx context.Context, m sysdetect.Machine, reasons []string) error {
	s := screen.NewWelcome(m, reasons)
	if _, err := u.ask(ctx, s); err != nil {
		return err
	}
	if !s.Start {
		return ErrExit
	}
	return nil
}

// Select shows the whole selection on one screen.
func (u *UI) Select(ctx context.Context, m engine.Menu, ticked map[string]bool) ([]string, error) {
	u.revert = m.Revert
	u.mu.Lock()
	for _, g := range m.Groups {
		for _, e := range g.Entries {
			u.titles[e.Control.Meta().ID] = e.Control.Meta().Title
		}
	}
	u.mu.Unlock()

	var groups []*screen.Group
	for _, g := range m.Groups {
		sg := &screen.Group{Num: g.Category.Number(), Name: g.Category.Name(), NA: g.NA}
		for _, e := range g.Entries {
			md := e.Control.Meta()
			tags := md.Tags
			if m.Revert { // a revert asks nothing
				tags = nil
				for _, t := range md.Tags {
					if t != control.TagInput {
						tags = append(tags, t)
					}
				}
			}
			sg.Items = append(sg.Items, &screen.Item{
				ID: md.ID, Title: md.Title, Tags: tags, Needs: u.titlesOf(md.Requires),
				What: e.Doc.What, Why: e.Doc.Why, Disabled: e.Disabled,
				Done:        e.Disabled == "already applied",
				Partial:     e.State == control.Partial,
				Recommended: md.Default && e.Disabled == "" && !m.Revert,
				Ticked:      ticked[md.ID] && e.Disabled == "",
			})
		}
		groups = append(groups, sg)
	}
	s := screen.NewSelect(u.system, m.Revert, groups)
	ev, err := u.ask(ctx, s)
	if err != nil {
		return nil, err
	}
	if ev != screen.Done {
		return nil, u.quitErr()
	}
	return s.Selected(), nil
}

// Review shows the plan, with the answers, before anything changes.
func (u *UI) Review(ctx context.Context, r engine.Review) (engine.ReviewAction, error) {
	var items []screen.ReviewItem
	for _, it := range r.Items {
		md := it.Control.Meta()
		items = append(items, screen.ReviewItem{Title: md.Title, Tags: md.Tags, Added: it.Added, Values: it.Values})
	}
	s := screen.NewReview(u.system, r.Revert, items, int(engine.LockoutWindow.Minutes()))
	if _, err := u.ask(ctx, s); err != nil {
		return engine.ReviewEdit, err
	}
	switch {
	case s.Result:
		return engine.ReviewApply, nil
	case s.ChangeAnswers:
		return engine.ReviewAnswers, nil
	}
	return engine.ReviewEdit, nil
}

func (u *UI) ConfirmDependencies(ctx context.Context, extra []engine.Dep, revert bool) (bool, error) {
	title, body, yes, no, by := "Add the controls they need?",
		"Some of the controls you ticked need these first. They are in the plan before the controls that need them.",
		"Add them", "Skip those controls", "needed by"
	if revert {
		title, body, yes, no, by = "Revert these too?",
			"These applied controls depend on what you ticked. Reverting only the ticked ones would leave them half working.",
			"Revert them too", "Keep them", "depends on"
	}
	var list []string
	for _, d := range extra {
		list = append(list, d.Control.Meta().Title+"  ("+by+": "+strings.Join(u.titlesOf(d.RequiredBy), ", ")+")")
	}
	s := screen.NewConfirm(u.system, title, []string{body}, list, yes, no, true)
	if _, err := u.ask(ctx, s); err != nil {
		return false, err
	}
	return s.Result, nil
}

func (u *UI) AskInputs(ctx context.Context, c control.Control, inputs []control.Input) (control.Values, error) {
	f := screen.NewForm(u.system, c.Meta().Title, inputs)
	ev, err := u.ask(ctx, f)
	if err != nil {
		return nil, err
	}
	if ev == screen.Back {
		return nil, engine.ErrBack
	}
	return f.Values, nil
}

// askOnRun puts a question on the run screen and waits for the answer.
func (u *UI) askOnRun(ctx context.Context, set func(r *screen.Run), result func() bool) (bool, error) {
	ch := make(chan screen.Event, 1)
	u.p.Send(funcMsg(func(m *model) {
		if m.run == nil {
			m.run = screen.NewRun(u.system, u.revert, nil, m.now)
		}
		set(m.run)
		m.cur, m.reply = m.run, ch
	}))
	if _, err := u.wait(ctx, ch); err != nil {
		return false, err
	}
	ans := make(chan bool, 1)
	u.p.Send(funcMsg(func(m *model) { ans <- result() }))
	select {
	case v := <-ans:
		return v, nil
	case <-u.done:
		return false, u.quitErr()
	}
}

func (u *UI) ConfirmLockout(ctx context.Context, c control.Control, window time.Duration) (bool, error) {
	var run *screen.Run
	return u.askOnRun(ctx,
		func(r *screen.Run) { run = r; r.AskLockout(c.Meta().Title, window) },
		func() bool { return run.Result })
}

func (u *UI) WarnIrreversibleLockout(ctx context.Context, c control.Control) error {
	var run *screen.Run
	ok, err := u.askOnRun(ctx,
		func(r *screen.Run) { run = r; r.AskWarn(c.Meta().Title) },
		func() bool { return run.Result })
	if err != nil {
		return err
	}
	if !ok {
		return engine.ErrSkip
	}
	return nil
}

func (u *UI) ShowSummary(s engine.Summary) {
	d := screen.SummaryData{
		System: u.system, Revert: s.Revert, Dry: s.Dry, Reboot: s.Reboot, Elapsed: s.Elapsed,
		Done: u.titlesOf(s.Done), Added: u.titlesOf(s.Added), Partial: u.titlesOf(s.Partial),
	}
	for _, x := range s.Skipped {
		d.Skipped = append(d.Skipped, screen.Row{Title: u.title(x.ID), Reason: x.Reason})
	}
	for _, x := range s.Failed {
		d.Failed = append(d.Failed, screen.Row{Title: u.title(x.ID), Reason: x.Reason})
	}
	d.LogFile = u.logPath
	u.log(false, fmt.Sprintf("Summary: %d done, %d failed, %d skipped", len(d.Done), len(d.Failed), len(d.Skipped)))
	u.mu.Lock()
	u.summary = &d
	u.mu.Unlock()
	_, _ = u.ask(context.Background(), screen.NewSummary(d))
}

// PickPreset, PickControls and ConfirmSelection belong to the one-question
// prompts of the plain interface. The full-screen interface uses Select and
// Review instead, so these only satisfy engine.UI.
func (u *UI) PickPreset(context.Context) (engine.Preset, error) { return engine.Recommended, nil }
func (u *UI) PickControls(context.Context, control.Category, []engine.Entry, map[string]bool, string) ([]string, error) {
	return nil, errors.New("not used")
}
func (u *UI) ConfirmSelection(context.Context, []string, bool) (bool, error) { return true, nil }

// Begin, Step and End draw the run screen.
func (u *UI) Begin(items []control.Control, revert bool) {
	var titles []string
	for _, c := range items {
		titles = append(titles, c.Meta().Title)
	}
	u.p.Send(funcMsg(func(m *model) {
		m.run = screen.NewRun(u.system, revert, titles, m.now)
		m.cur, m.reply = m.run, nil
	}))
}

func (u *UI) Step(i int) {
	u.p.Send(funcMsg(func(m *model) {
		if m.run != nil {
			m.run.Start(i)
		}
	}))
}

func (u *UI) End(i int, o engine.Outcome, note string) {
	u.p.Send(funcMsg(func(m *model) {
		if m.run != nil {
			if o == engine.StepSkipped {
				m.run.Skip(i, note)
				return
			}
			m.run.Finish(i, o == engine.StepDone, note)
		}
	}))
}

// Logger sends the live log lines to the run screen and to the log file.
type Logger struct{ U *UI }

func (l Logger) Infof(f string, a ...any) { l.U.log(false, fmt.Sprintf(f, a...)) }
func (l Logger) Warnf(f string, a ...any) { l.U.log(true, fmt.Sprintf(f, a...)) }

// Logger returns the logger that goes with this UI.
func (u *UI) Logger() Logger { return Logger{u} }

func (u *UI) log(warn bool, text string) {
	if u.logFile != nil {
		level := "INFO "
		if warn {
			level = "WARN "
		}
		fmt.Fprintf(u.logFile, "%s %s%s\n", time.Now().Format("2006-01-02 15:04:05"), level, text)
	}
	u.p.Send(funcMsg(func(m *model) {
		if m.run != nil {
			m.run.Log(warn, text)
		} else {
			m.busy.Last = text
		}
	}))
}
