// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Danang Galuh Tegar Prasetyo

package screen

import (
	"fmt"
	"strings"
	"time"

	"github.com/danang-id/server-hardening/internal/control"
)

// Item is one control in the selection.
type Item struct {
	ID, Title   string
	Tags        []control.Tag
	Needs       []string // titles of the controls it requires
	What, Why   string
	Disabled    string // why it cannot be ticked, if it cannot
	Done        bool   // already applied (Disabled says so)
	Partial     bool   // applied in part
	Recommended bool
	Ticked      bool
}

// Group is one category in the selection.
type Group struct {
	Num   int
	Name  string
	NA    string // why the whole category is N/A, if it is
	Items []*Item
}

func (g *Group) tickable() (ticked, total int) {
	for _, it := range g.Items {
		if it.Disabled != "" {
			continue
		}
		total++
		if it.Ticked {
			ticked++
		}
	}
	return
}

// Select is the main screen: every category, every control, one screen.
type Select struct {
	hostLabel
	System string
	Revert bool
	Groups []*Group

	cat, row int // the cursor
	top      int // first visible row of the control list
	ctop     int // first visible row of the category list
	help     bool
	flash    string
	flashEnd time.Time
	now      time.Time
}

// NewSelect makes the selection screen.
func NewSelect(system string, revert bool, groups []*Group) *Select {
	return &Select{System: system, Revert: revert, Groups: groups}
}

// Selected returns the ticked IDs in screen order.
func (s *Select) Selected() []string {
	var ids []string
	for _, g := range s.Groups {
		for _, it := range g.Items {
			if it.Ticked && it.Disabled == "" {
				ids = append(ids, it.ID)
			}
		}
	}
	return ids
}

// Count is the number of ticked controls.
func (s *Select) Count() int { return len(s.Selected()) }

func (s *Select) group() *Group { return s.Groups[s.cat] }

func (s *Select) item() *Item {
	g := s.group()
	if s.row < 0 || s.row >= len(g.Items) {
		return nil
	}
	return g.Items[s.row]
}

func (s *Select) say(msg string) {
	s.flash = msg
	s.flashEnd = s.now.Add(3 * time.Second)
}

func (s *Select) setCat(i int) {
	s.cat = i
	s.row = 0
	s.top = 0
}

func (s *Select) Tick(now time.Time) {
	s.now = now
	if s.flash != "" && now.After(s.flashEnd) {
		s.flash = ""
	}
}

func (s *Select) move(d int) {
	switch {
	case d > 0 && s.row < len(s.group().Items)-1:
		s.row++
	case d > 0 && s.cat < len(s.Groups)-1:
		s.setCat(s.cat + 1)
	case d < 0 && s.row > 0:
		s.row--
	case d < 0 && s.cat > 0:
		s.setCat(s.cat - 1)
		s.row = max(len(s.group().Items)-1, 0)
	}
}

func (s *Select) Key(k string) Event {
	if s.help {
		s.help = false
		if k == "ctrl+c" {
			return Quit
		}
		return None
	}
	switch k {
	case "ctrl+c", "q":
		return Quit
	case "up", "k":
		s.move(-1)
	case "down", "j":
		s.move(1)
	case "left", "h":
		if s.cat > 0 {
			s.setCat(s.cat - 1)
		}
	case "right", "l":
		if s.cat < len(s.Groups)-1 {
			s.setCat(s.cat + 1)
		}
	case "tab":
		s.setCat((s.cat + 1) % len(s.Groups))
	case "shift+tab":
		s.setCat((s.cat + len(s.Groups) - 1) % len(s.Groups))
	case "home":
		s.row = 0
	case "end":
		s.row = max(len(s.group().Items)-1, 0)
	case "pgup":
		s.row = max(s.row-5, 0)
	case "pgdown":
		s.row = min(s.row+5, max(len(s.group().Items)-1, 0))
	case " ", "space", "x":
		s.toggle()
	case "a":
		s.toggleAll()
	case "r":
		for _, g := range s.Groups {
			for _, it := range g.Items {
				it.Ticked = it.Recommended && it.Disabled == ""
			}
		}
		s.say("Back to the recommended selection")
	case "n":
		for _, g := range s.Groups {
			for _, it := range g.Items {
				it.Ticked = false
			}
		}
		s.say("Cleared the selection")
	case "?":
		s.help = true
	case "enter":
		if s.Count() == 0 {
			s.say("Tick at least one control first (space)")
			return None
		}
		return Done
	}
	return None
}

func (s *Select) toggle() {
	it := s.item()
	if it == nil {
		return
	}
	if it.Disabled != "" {
		s.say(capital(it.Disabled))
		return
	}
	it.Ticked = !it.Ticked
}

func (s *Select) toggleAll() {
	g := s.group()
	ticked, total := g.tickable()
	if total == 0 {
		return
	}
	for _, it := range g.Items {
		if it.Disabled == "" {
			it.Ticked = ticked < total
		}
	}
}

func capital(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}

// View draws the screen.
func (s *Select) View(w, h int) []Line {
	var right Line
	switch {
	case s.flash != "":
		right = L(s.flash, Warn)
	case s.Count() > 0:
		right = L(fmt.Sprintf("%s selected", plural(s.Count(), "control", "controls")), Accent, Bold)
	default:
		right = L("nothing selected", Dim)
	}
	if s.Revert && s.flash == "" {
		right = Cat(L("revert", Warn), sepLine(), right)
	}
	head := header(w, s.System, s.Host, right)

	left := []Hint{{"↑↓", "move"}, {"space", "tick"}, {"←→", "category"}, {"a", "all"}, {"r", "reset"}, {"enter", "review"}}
	foot := footer(w, left, []Hint{{"?", "help"}, {"q", "quit"}})

	if s.help {
		return page(w, h, head, s.helpView(w, bodyH(h, head)), footer(w, nil, []Hint{{"any key", "close"}}))
	}

	room := bodyH(h, head)
	detailH := 6
	switch {
	case room >= 22:
		detailH = 8
	case room < 16:
		detailH = 5
	}
	panesH := room - detailH
	// Do not stretch the lists on a tall terminal: they only need to hold the
	// longest category.
	longest := len(s.Groups)
	for _, g := range s.Groups {
		longest = max(longest, len(g.Items))
	}
	panesH = min(panesH, max(longest+2, 12))
	lw := 30
	if w >= 100 {
		lw = 34
	}
	rw := w - lw

	cats := s.categoryPane(lw, panesH)
	list := s.listPane(rw, panesH)
	body := side(cats, list)
	body = append(body, s.detailPane(w, detailH)...)
	return page(w, h, head, body, foot)
}

func (s *Select) categoryPane(w, h int) []Line {
	inner := h - 2
	if s.cat < s.ctop {
		s.ctop = s.cat
	}
	if s.cat >= s.ctop+inner {
		s.ctop = s.cat - inner + 1
	}
	var rows []Line
	cw := w - 4
	for i := s.ctop; i < len(s.Groups) && len(rows) < inner; i++ {
		g := s.Groups[i]
		marker, mst := "  ", Plain
		if i == s.cat {
			marker, mst = "› ", Accent
		}
		ticked, total := g.tickable()
		var count Line
		switch {
		case g.NA != "":
			count = L("n/a", Dim)
		case total == 0:
			count = L("✔", OK)
		default:
			st := Dim
			if ticked > 0 {
				st = Accent
			}
			count = L(fmt.Sprintf("%d/%d", ticked, total), st)
		}
		nst := Plain
		if g.NA != "" {
			nst = Dim
		}
		name := ShortName(g.Num, g.Name)
		l := Right(cw,
			Cat(L(marker, mst), L(two(g.Num)+" ", Dim), L(name, nst)),
			count)
		if i == s.cat {
			l = l.Highlight()
		}
		rows = append(rows, l)
	}
	for len(rows) < inner {
		rows = append(rows, L(""))
	}
	return box("Categories", rows, w, false)
}

func (s *Select) listPane(w, h int) []Line {
	g := s.group()
	title := ShortName(g.Num, g.Name)
	inner := h - 2
	cw := w - 4
	var rows []Line
	switch {
	case g.NA != "":
		rows = append(rows, L("Not applicable on this system.", Dim))
		for _, ln := range Wrap(g.NA, cw) {
			rows = append(rows, L(ln, Dim))
		}
	default:
		if s.row < s.top {
			s.top = s.row
		}
		if s.row >= s.top+inner {
			s.top = s.row - inner + 1
		}
		for i := s.top; i < len(g.Items) && len(rows) < inner; i++ {
			rows = append(rows, s.itemRow(g.Items[i], i == s.row, cw))
		}
	}
	for len(rows) < inner {
		rows = append(rows, L(""))
	}
	return box(title, rows, w, true)
}

func (s *Select) itemRow(it *Item, cursor bool, w int) Line {
	marker, mst := "  ", Plain
	if cursor {
		marker, mst = "› ", Accent
	}
	var glyph Span
	tst := Plain
	switch {
	case it.Done:
		glyph, tst = Span{"✔ ", OK}, Dim
	case it.Disabled != "":
		glyph, tst = Span{"– ", Dim}, Dim
	case it.Ticked:
		glyph = Span{"◉ ", Accent}
	default:
		glyph = Span{"○ ", Dim}
	}
	var tail Line
	switch {
	case it.Done:
		tail = L("applied", Dim)
	default:
		if ic := rowIcons(it.Tags); ic != "" {
			tail = L(ic)
		}
	}
	l := Right(w, Cat(L(marker, mst), Line{glyph}, L(it.Title, tst)), tail)
	if cursor {
		l = l.Highlight()
	}
	return l
}

func (s *Select) detailPane(w, h int) []Line {
	cw := w - 4
	inner := h - 2
	var rows []Line
	g := s.group()
	it := s.item()
	switch {
	case g.NA != "":
		rows = append(rows, Cat(L(ShortName(g.Num, g.Name), Bold)))
		for _, ln := range Wrap(g.NA, cw) {
			rows = append(rows, L(ln, Dim))
		}
	case it == nil:
	default:
		rows = append(rows, Right(cw, L(it.Title, Bold), L(it.ID, Dim)))
		var status Line
		switch {
		case it.Done:
			status = L("✔ Already applied on this server", OK)
		case it.Disabled != "":
			status = L(capital(it.Disabled), Warn)
		case it.Partial:
			status = Cat(L("◐ Applied in part; applying again finishes it", Warn), L("   "), tagLine(it.Tags))
		default:
			status = tagLine(it.Tags)
		}
		if len(it.Needs) > 0 {
			status = Cat(status, L("   needs: "+strings.Join(it.Needs, ", "), Dim))
		}
		rows = append(rows, status)
		text := it.What
		if it.Why != "" {
			text += " " + it.Why
		}
		for _, ln := range Wrap(text, cw) {
			rows = append(rows, L(ln))
		}
		if len(rows) > inner {
			rows = rows[:inner]
			rows[inner-1] = rows[inner-1].Add(Span{"…", Plain})
		}
	}
	for len(rows) < inner {
		rows = append(rows, L(""))
	}
	return box("", rows[:inner], w, false)
}

func (s *Select) helpView(w, h int) []Line {
	bw := modalWidth(w)
	k := func(key, what string) Line {
		return Cat(L(fmt.Sprintf("%-12s", key), Accent), L(what))
	}
	rows := []Line{
		L("Choose what to do", Bold),
		k("↑ ↓", "move through the controls"),
		k("← →  tab", "switch category"),
		k("space", "tick or untick"),
		k("a", "tick all in this category, or none"),
		k("r  n", "recommended selection, or nothing"),
		k("enter", "review the choice"),
		k("q", "quit; nothing is changed"),
		L(""),
		L("Symbols", Bold),
	}
	for _, t := range tagOrder {
		rows = append(rows, Cat(L(tagInfos[t].icon+"  "), L(tagInfos[t].word)))
	}
	rows = append(rows, Cat(L("✔   ", OK), L("already applied")))
	return centered(box("Help", rows, bw, true), w, h)
}
