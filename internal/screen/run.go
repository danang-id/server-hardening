// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Danang Galuh Tegar Prasetyo

package screen

import (
	"fmt"
	"strings"
	"time"
)

// StepState is where a step of the run is.
type StepState int

// The states of a step.
const (
	Pending StepState = iota
	Running
	Succeeded
	Failed
	Skipped // not run: declined, or something it needs did not run
)

type step struct {
	title string
	st    StepState
	note  string
}

type logLine struct {
	warn bool
	text string
}

type promptKind int

const (
	askLockout promptKind = iota // log in from a new session
	askWarn                      // an irreversible lockout is next
	askStop                      // the user pressed ctrl+c
)

type prompt struct {
	kind     promptKind
	title    string
	body     []string
	yes, no  string
	deadline time.Time // askLockout: when the automatic undo runs
	yesFocus bool
}

// Run shows the steps of a run and the live log. Lockout questions appear on
// top of it.
type Run struct {
	hostLabel
	System string
	Revert bool

	// Result is the answer to the last lockout or warning question.
	Result bool

	steps []*step
	logs  []logLine
	start time.Time
	now   time.Time
	p     *prompt
}

// NewRun makes the screen for a run of the given steps.
func NewRun(system string, revert bool, titles []string, now time.Time) *Run {
	r := &Run{System: system, Revert: revert, start: now, now: now}
	for _, t := range titles {
		r.steps = append(r.steps, &step{title: t})
	}
	return r
}

// Start marks step i as running.
func (r *Run) Start(i int) {
	if i >= 0 && i < len(r.steps) {
		r.steps[i].st = Running
	}
}

// Finish marks step i as done, or failed with a note.
func (r *Run) Finish(i int, ok bool, note string) {
	if i < 0 || i >= len(r.steps) {
		return
	}
	r.steps[i].st, r.steps[i].note = Succeeded, ""
	if !ok {
		r.steps[i].st, r.steps[i].note = Failed, note
	}
}

// Skip marks step i as not run.
func (r *Run) Skip(i int, note string) {
	if i < 0 || i >= len(r.steps) {
		return
	}
	r.steps[i].st, r.steps[i].note = Skipped, note
}

// Log adds a line to the live log.
func (r *Run) Log(warn bool, text string) {
	for ln := range strings.SplitSeq(strings.TrimRight(text, "\n"), "\n") {
		r.logs = append(r.logs, logLine{warn, ln})
	}
	if len(r.logs) > 500 {
		r.logs = r.logs[len(r.logs)-500:]
	}
}

// AskLockout asks the user to log in from a new session. The automatic undo
// runs at now+window.
func (r *Run) AskLockout(change string, window time.Duration) {
	r.p = &prompt{
		kind:  askLockout,
		title: "Check your access",
		body: []string{
			"Keep this session open. Open a NEW terminal and log in to this server now.",
			"Change: " + change,
			"If you answer No, or do not answer in time, the change is undone, even if this connection is lost.",
		},
		yes: "Yes, it works", no: "No, undo it",
		deadline: r.now.Add(window),
	}
}

// AskWarn warns about an irreversible lockout control.
func (r *Run) AskWarn(change string) {
	r.p = &prompt{
		kind:  askWarn,
		title: "This cannot be undone",
		body: []string{
			change,
			"This change can cut your connection and cannot be reverted by this tool. Keep your provider's web console open before you continue.",
			"If you skip it, the rest of the run goes on.",
		},
		yes: "Continue", no: "Skip this one",
	}
}

// Asking reports whether a question is on the screen.
func (r *Run) Asking() bool { return r.p != nil && r.p.kind != askStop }

func (r *Run) Tick(now time.Time) { r.now = now }

func (r *Run) Key(k string) Event {
	if r.p == nil {
		if k == "ctrl+c" {
			r.p = &prompt{
				kind:  askStop,
				title: "Stop now?",
				body:  []string{"The step in progress is interrupted and may be left half done. Steps not started are not run."},
				yes:   "Stop", no: "Keep going",
			}
		}
		return None
	}
	p := r.p
	switch k {
	case "ctrl+c":
		if p.kind != askStop {
			return Quit // the question stays unanswered; the undo timer stays armed
		}
		return Quit
	case "left", "right", "tab", "shift+tab", "h", "l":
		p.yesFocus = !p.yesFocus
	case "y":
		return r.answer(true)
	case "n":
		return r.answer(false)
	case "esc":
		if p.kind == askStop {
			return r.answer(false)
		}
	case "enter":
		return r.answer(p.yesFocus)
	}
	return None
}

func (r *Run) answer(yes bool) Event {
	kind := r.p.kind
	r.p = nil
	if kind == askStop {
		if yes {
			return Quit
		}
		return None
	}
	r.Result = yes
	return Done
}

var spinner = []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}

func (r *Run) spin() string { return spinner[(r.now.UnixMilli()/100)%int64(len(spinner))] }

func clock(d time.Duration) string {
	d = max(d, 0).Round(time.Second)
	return fmt.Sprintf("%02d:%02d", int(d.Minutes()), int(d.Seconds())%60)
}

func (r *Run) counts() (done, cur int) {
	cur = -1
	for i, s := range r.steps {
		switch s.st {
		case Succeeded, Failed, Skipped:
			done++
		case Running:
			cur = i
		}
	}
	return
}

func (r *Run) View(w, h int) []Line {
	done, _ := r.counts()
	verb := "Applying"
	if r.Revert {
		verb = "Reverting"
	}
	right := Cat(L(fmt.Sprintf("%d / %d", done, len(r.steps)), Accent, Bold), L("  "+clock(r.now.Sub(r.start)), Dim))
	head := header(w, r.System, r.Host, right)

	room := bodyH(h, head)
	stepsH := min(len(r.steps)+2, room/2+1)
	stepsH = max(stepsH, 5)
	logH := room - stepsH
	body := append(r.stepsPane(w, stepsH, verb), r.logPane(w, logH)...)
	if r.p != nil {
		body = r.overlay(body, w, room)
	}
	foot := footer(w, nil, []Hint{{"ctrl+c", "stop"}})
	if r.Asking() {
		foot = footer(w, []Hint{{"←→", "choose"}, {"enter", "confirm"}, {"y", r.p.yes}, {"n", r.p.no}}, []Hint{{"ctrl+c", "leave"}})
	}
	return page(w, h, head, body, foot)
}

func (r *Run) stepsPane(w, h int, verb string) []Line {
	inner := h - 2
	cw := w - 4
	_, cur := r.counts()
	if cur < 0 {
		cur = 0
		for i, s := range r.steps {
			if s.st == Pending {
				cur = i
				break
			}
			cur = i
		}
	}
	first := max(min(cur-inner/2, len(r.steps)-inner), 0)
	var rows []Line
	for i := first; i < len(r.steps) && len(rows) < inner; i++ {
		s := r.steps[i]
		var g Span
		tst := Plain
		switch s.st {
		case Pending:
			g, tst = Span{"·", Dim}, Dim
		case Running:
			g = Span{r.spin(), Accent}
		case Succeeded:
			g = Span{"✔", OK}
		case Failed:
			g = Span{"✖", Err}
		case Skipped:
			g, tst = Span{"–", Warn}, Dim
		}
		l := Cat(Line{g}, L(" "), L(s.title, tst))
		if (s.st == Failed || s.st == Skipped) && s.note != "" {
			l = Cat(l, L("  "+s.note, Dim))
		}
		rows = append(rows, l.Cut(cw))
	}
	return box(verb, pad(rows, inner), w, false)
}

func (r *Run) logPane(w, h int) []Line {
	inner := h - 2
	cw := w - 4
	var rows []Line
	start := max(len(r.logs)-inner, 0)
	for _, ln := range r.logs[start:] {
		if ln.warn {
			rows = append(rows, L("! "+ln.text, Warn).Cut(cw))
		} else {
			rows = append(rows, L(ln.text, Dim).Cut(cw))
		}
	}
	return box("Log", pad(rows, inner), w, false)
}

func (r *Run) overlay(body []Line, w, room int) []Line {
	p := r.p
	bw := modalWidth(w)
	cw := bw - 4
	var rows []Line
	for _, para := range p.body {
		for _, ln := range Wrap(para, cw) {
			rows = append(rows, L(ln))
		}
		rows = append(rows, L(""))
	}
	if !p.deadline.IsZero() {
		left := p.deadline.Sub(r.now)
		st := Accent
		if left < time.Minute {
			st = Warn
		}
		msg := "Automatic undo in " + clock(left)
		if left <= 0 {
			msg, st = "The automatic undo is running", Warn
		}
		rows = append(rows, L(msg, st, Bold), L(""))
	}
	b := func(label string, on bool) Line {
		if on {
			return L(" "+label+" ", Accent, Bold, Cursor)
		}
		return L(" "+label+" ", Dim)
	}
	btn := Cat(b(p.yes, p.yesFocus), L("   "), b(p.no, !p.yesFocus))
	rows = append(rows, Cat(L(strings.Repeat(" ", max((cw-btn.Width())/2, 0))), btn))
	dlg := box(p.title, rows, bw, true)
	if p.kind != askStop {
		dlg[0] = recolor(dlg[0], Warn)
	}
	return centered(dlg, w, room)
}
