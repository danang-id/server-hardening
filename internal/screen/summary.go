// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Danang Galuh Tegar Prasetyo

package screen

import (
	"strconv"
	"time"
)

// Row is one line of the summary: a control and, if it has one, a reason.
type Row struct{ Title, Reason string }

// SummaryData is what the summary screen shows.
type SummaryData struct {
	System  string
	Revert  bool
	Dry     bool
	Done    []string
	Added   []string
	Skipped []Row
	Failed  []Row
	Partial []string
	Reboot  bool
	Elapsed string
	LogFile string
}

// Summary is the last screen of a run.
type Summary struct {
	hostLabel
	D   SummaryData
	top int
}

// NewSummary makes the summary screen.
func NewSummary(d SummaryData) *Summary { return &Summary{D: d} }

func (s *Summary) Tick(time.Time) {}

func (s *Summary) Key(k string) Event {
	switch k {
	case "enter", "q", "esc", "ctrl+c":
		return Done
	case "up", "k":
		s.top = max(s.top-1, 0)
	case "down", "j":
		s.top++
	case "pgup":
		s.top = max(s.top-8, 0)
	case "pgdown":
		s.top += 8
	}
	return None
}

func (s *Summary) headline() Line {
	d := s.D
	verb, past := "Applied", "applied"
	if d.Revert {
		verb, past = "Reverted", "reverted"
	}
	n := len(d.Done)
	switch {
	case d.Dry:
		return Cat(L(" ✔ ", OK, Bold), L("Dry run: "+plural(n, "control would", "controls would")+" run. Nothing was changed.", Bold))
	case len(d.Failed) > 0 && n == 0:
		return Cat(L(" ✖ ", Err, Bold), L("Nothing was "+past+".", Bold))
	case len(d.Failed) > 0:
		return Cat(L(" ✖ ", Err, Bold), L(verb+" "+strconv.Itoa(n)+", "+strconv.Itoa(len(d.Failed))+" failed.", Bold))
	case n == 0:
		return Cat(L(" – ", Dim, Bold), L("Nothing to do.", Bold))
	}
	return Cat(L(" ✔ ", OK, Bold), L(verb+" "+plural(n, "control.", "controls."), Bold))
}

func (s *Summary) rows(cw int) []Line {
	d := s.D
	var rows []Line
	section := func(title string, st Style) {
		if len(rows) > 0 {
			rows = append(rows, L(""))
		}
		rows = append(rows, L(title, st, Bold))
	}
	if len(d.Done) > 0 {
		t := "Applied"
		if d.Revert {
			t = "Reverted"
		}
		if d.Dry {
			t = "Would run"
		}
		section(t, OK)
		added := map[string]bool{}
		for _, x := range d.Added {
			added[x] = true
		}
		for _, x := range d.Done {
			l := Cat(L("  ✔ ", OK), L(x))
			if added[x] {
				l = Right(cw, l, L("needed too", Dim))
			}
			rows = append(rows, l.Cut(cw))
		}
	}
	if len(d.Failed) > 0 {
		section("Failed", Err)
		for _, x := range d.Failed {
			rows = append(rows, wrapHang(L("  ✖ ", Err), x.Title, Plain, cw)...)
			if x.Reason != "" {
				for _, ln := range Wrap(x.Reason, cw-6) {
					rows = append(rows, L("      "+ln, Dim))
				}
			}
		}
	}
	if len(d.Skipped) > 0 {
		section("Skipped", Warn)
		for _, x := range d.Skipped {
			rows = append(rows, wrapHang(L("  – ", Warn), x.Title, Plain, cw)...)
			if x.Reason != "" {
				for _, ln := range Wrap(x.Reason, cw-6) {
					rows = append(rows, L("      "+ln, Dim))
				}
			}
		}
	}
	if len(d.Partial) > 0 {
		section("Reverted only in part (see the revert limits in the reference)", Warn)
		for _, x := range d.Partial {
			rows = append(rows, wrapHang(L("  ~ ", Warn), x, Plain, cw)...)
		}
	}
	return rows
}

func (s *Summary) View(w, h int) []Line {
	d := s.D
	cw := modalWidth(w)
	if w >= 100 {
		cw = min(w-12, 100)
	}
	var notes []Line
	if d.Reboot && !d.Dry {
		notes = append(notes, Cat(L(" 🔁 ", Plain), L("Reboot to finish the changes: ", Plain), L("reboot", Accent)))
	}
	var meta string
	if d.Elapsed != "" {
		meta = "Took " + d.Elapsed
	}
	if d.LogFile != "" {
		if meta != "" {
			meta += sep
		}
		meta += "Log: " + d.LogFile
	}
	if meta != "" {
		notes = append(notes, L(" "+meta, Dim))
	}
	head := header(w, d.System, s.Host, L(""))
	room := bodyH(h, head)
	rows := s.rows(cw - 4)
	inner := min(len(rows), max(room-5-len(notes), 3))
	boxH := inner + 2
	s.top = min(s.top, max(len(rows)-inner, 0))
	view := rows[s.top:min(s.top+inner, len(rows))]
	var body []Line
	body = append(body, s.headline(), L(""))
	body = append(body, centered(box("Result", pad(view, inner), cw, true), w, boxH)...)
	body = append(body, L(""))
	body = append(body, notes...)
	return page(w, h, head, body,
		footer(w, []Hint{{"enter", "exit"}, {"↑↓", "scroll"}}, nil))
}

// Busy is shown while the program works and there is nothing to ask.
type Busy struct {
	hostLabel
	System string
	Msg    string
	Last   string // the last line of the log
	now    time.Time
}

func (b *Busy) Tick(now time.Time) { b.now = now }

func (b *Busy) Key(k string) Event {
	if k == "ctrl+c" {
		return Quit
	}
	return None
}

func (b *Busy) View(w, h int) []Line {
	sp := spinner[(b.now.UnixMilli()/100)%int64(len(spinner))]
	block := []Line{Cat(L(sp+" ", Accent), L(b.Msg, Bold))}
	if b.Last != "" {
		block = append(block, L(""), L(b.Last, Dim).Cut(w-8))
	}
	head := header(w, b.System, b.Host, L(""))
	return page(w, h, head, centered(block, w, bodyH(h, head)), footer(w, nil, []Hint{{"ctrl+c", "quit"}}))
}
