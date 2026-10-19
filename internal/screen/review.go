// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Danang Galuh Tegar Prasetyo

package screen

import (
	"fmt"
	"slices"
	"strconv"
	"time"

	"github.com/danang-id/server-hardening/internal/control"
)

// ReviewItem is one control in the review.
type ReviewItem struct {
	Title  string
	Tags   []control.Tag
	Added  bool     // added because another control needs it
	Values []string // the answers, one line each
}

// Review is the last screen before anything changes.
type Review struct {
	hostLabel
	System         string
	Revert         bool
	Items          []ReviewItem
	LockoutMinutes int

	// Result is true to go ahead, false to go back. When it is false,
	// ChangeAnswers says whether the user wants the questions again (true) or
	// the selection (false).
	Result        bool
	ChangeAnswers bool
	sel           int // the button under the cursor: 0 go ahead, 1 selection, 2 answers
	top           int
}

// NewReview makes the review screen.
func NewReview(system string, revert bool, items []ReviewItem, lockoutMinutes int) *Review {
	return &Review{System: system, Revert: revert, Items: items, LockoutMinutes: lockoutMinutes}
}

func (r *Review) Tick(time.Time) {}

func (r *Review) Key(k string) Event {
	switch k {
	case "ctrl+c", "q":
		return Quit
	case "right", "tab", "l":
		r.sel = (r.sel + 1) % r.buttonCount()
	case "left", "shift+tab", "h":
		r.sel = (r.sel + r.buttonCount() - 1) % r.buttonCount()
	case "enter":
		r.Result, r.ChangeAnswers = r.sel == 0, r.sel == 2
		return Done
	case "e", "esc", "b":
		r.Result, r.ChangeAnswers = false, false
		return Done
	case "c":
		if r.hasAnswers() {
			r.Result, r.ChangeAnswers = false, true
			return Done
		}
	case "a", "y":
		r.Result, r.ChangeAnswers = true, false
		return Done
	case "up", "k":
		r.top = max(r.top-1, 0)
	case "down", "j":
		r.top++
	case "pgup":
		r.top = max(r.top-8, 0)
	case "pgdown":
		r.top += 8
	case "home":
		r.top = 0
	}
	return None
}

// hasAnswers reports whether any control in the plan was asked something.
func (r *Review) hasAnswers() bool {
	for _, it := range r.Items {
		if len(it.Values) > 0 {
			return true
		}
	}
	return false
}

func (r *Review) buttonCount() int {
	if r.hasAnswers() {
		return 3
	}
	return 2
}

func (r *Review) verb() string {
	if r.Revert {
		return "revert"
	}
	return "apply"
}

func plural(n int, one, many string) string {
	if n == 1 {
		return strconv.Itoa(n) + " " + one
	}
	return strconv.Itoa(n) + " " + many
}

func (r *Review) rows(cw int) []Line {
	var rows []Line
	for i, it := range r.Items {
		title := Cat(L(fmt.Sprintf("%2d  ", i+1), Dim), L(it.Title))
		var tail Line
		if it.Added {
			tail = L("needed too", Dim)
		}
		if ic := rowIcons(it.Tags); ic != "" {
			tail = Cat(tail, L(" "+ic))
		}
		rows = append(rows, Right(cw, title, tail))
		for _, v := range it.Values {
			rows = append(rows, L("      "+v, Dim).Cut(cw))
		}
	}
	return rows
}

func (r *Review) notices(w int) []Line {
	var lock, irr, reboot int
	for _, it := range r.Items {
		if slices.Contains(it.Tags, control.TagLockout) {
			lock++
		}
		if slices.Contains(it.Tags, control.TagIrreversible) {
			irr++
		}
		if slices.Contains(it.Tags, control.TagReboot) {
			reboot++
		}
	}
	var out []Line
	add := func(icon, text string, st Style) {
		for i, ln := range Wrap(text, w-5) {
			lead := "    "
			if i == 0 {
				lead = " " + icon + " "
			}
			out = append(out, Cat(L(lead), L(ln, st)))
		}
	}
	if !r.Revert {
		if lock > 0 {
			add("🔒", plural(lock, "control can", "controls can")+" lock you out. Each is undone by itself after "+
				strconv.Itoa(r.LockoutMinutes)+" minutes unless you confirm from a new session.", Warn)
		}
		if irr > 0 {
			add("⛔", plural(irr, "control cannot", "controls cannot")+" be undone.", Warn)
		}
		if reboot > 0 {
			add("🔁", "A reboot is needed afterwards to finish "+plural(reboot, "control.", "controls."), Dim)
		}
	}
	return out
}

func (r *Review) View(w, h int) []Line {
	cw := modalWidth(w)
	if w >= 100 {
		cw = min(w-12, 100)
	}
	head := header(w, r.System, r.Host, L(""))
	room := bodyH(h, head)
	n := len(r.Items)
	title := "Ready to " + r.verb() + " " + plural(n, "control", "controls")
	sub := ""
	added := 0
	for _, it := range r.Items {
		if it.Added {
			added++
		}
	}
	if added > 0 {
		sub = "  (" + strconv.Itoa(added) + " added because others need them)"
	}
	notes := r.notices(w)
	rows := r.rows(cw - 4)
	// The list is as high as it needs to be, up to what the screen has left.
	inner := min(len(rows), max(room-6-len(notes), 3))
	r.top = min(r.top, max(len(rows)-inner, 0))
	view := rows[r.top:min(r.top+inner, len(rows))]
	more := ""
	if len(rows) > inner {
		more = fmt.Sprintf(" %d–%d of %d ", r.top+1, r.top+len(view), len(rows))
	}
	list := box("Run order"+more, pad(view, inner), cw, true)

	var body []Line
	body = append(body, Cat(L(" "), L(title, Bold), L(sub, Dim)))
	body = append(body, L(""))
	body = append(body, centered(list, w, len(list))...)
	body = append(body, notes...)
	body = append(body, L(""))
	body = append(body, r.buttons(w))
	return page(w, h, head, body,
		footer(w, r.hints(), []Hint{{"q", "quit"}}))
}

func (r *Review) hints() []Hint {
	h := []Hint{{"enter", r.verb()}, {"e", "edit selection"}}
	if r.hasAnswers() {
		h = append(h, Hint{"c", "change answers"})
	}
	return append(h, Hint{"↑↓", "scroll"})
}

func pad(rows []Line, n int) []Line {
	out := append([]Line(nil), rows...)
	for len(out) < n {
		out = append(out, L(""))
	}
	return out
}

func (r *Review) buttons(w int) Line {
	b := func(label string, on bool) Line {
		if on {
			return L(" "+label+" ", Accent, Bold, Cursor)
		}
		return L(" "+label+" ", Dim)
	}
	label := "Apply"
	if r.Revert {
		label = "Revert"
	}
	l := Cat(b(label, r.sel == 0), L("   "), b("Edit selection", r.sel == 1))
	if r.hasAnswers() {
		l = Cat(l, L("   "), b("Change answers", r.sel == 2))
	}
	pad := max((w-l.Width())/2, 0)
	return Cat(L(fmt.Sprintf("%*s", pad, "")), l)
}
