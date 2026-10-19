// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Danang Galuh Tegar Prasetyo

package screen

import (
	"strings"
	"time"
)

// Confirm asks a yes or no question in a dialog.
type Confirm struct {
	hostLabel
	System string
	Title  string
	Body   []string // paragraphs
	List   []string // bullet points under the body
	Yes    string
	No     string
	Warn   bool // the title is a warning

	// Result is the answer once the screen is done.
	Result bool
	yes    bool // the button under the cursor
	top    int  // first visible line of the list
}

// NewConfirm makes a dialog. The cursor starts on the "yes" button when
// defaultYes is true.
func NewConfirm(system, title string, body, list []string, yes, no string, defaultYes bool) *Confirm {
	return &Confirm{System: system, Title: title, Body: body, List: list, Yes: yes, No: no, yes: defaultYes}
}

func (c *Confirm) Tick(time.Time) {}

func (c *Confirm) Key(k string) Event {
	switch k {
	case "ctrl+c":
		return Quit
	case "left", "right", "tab", "shift+tab", "h", "l":
		c.yes = !c.yes
	case "y":
		c.Result = true
		return Done
	case "n", "esc":
		c.Result = false
		return Done
	case "enter":
		c.Result = c.yes
		return Done
	case "up", "k":
		c.top = max(c.top-1, 0)
	case "down", "j":
		c.top++
	}
	return None
}

func (c *Confirm) View(w, h int) []Line {
	bw := modalWidth(w)
	cw := bw - 4
	var rows []Line
	for _, p := range c.Body {
		for _, ln := range Wrap(p, cw) {
			rows = append(rows, L(ln))
		}
		rows = append(rows, L(""))
	}
	// Room for the bullets: what is left of the body area, minus the box
	// edges, the buttons and a blank line.
	head := header(w, c.System, c.Host, L(""))
	room := bodyH(h, head) - 2 - len(rows) - 3
	room = max(room, 3)
	if len(c.List) > 0 {
		// A bullet that is too long wraps, and its next lines line up under the
		// text, not under the bullet. Scrolling goes by line.
		var items []Line
		for _, it := range c.List {
			for i, ln := range Wrap(it, cw-2) {
				mark := "  "
				if i == 0 {
					mark = "• "
				}
				items = append(items, Cat(L(mark, Dim), L(ln)))
			}
		}
		c.top = min(c.top, max(len(items)-room, 0))
		end := min(c.top+room, len(items))
		rows = append(rows, items[c.top:end]...)
		if len(items) > room {
			rows = append(rows, L("↑↓ more ("+two(len(c.List))+" in all)", Dim))
		}
		rows = append(rows, L(""))
	}
	rows = append(rows, c.buttons(cw))
	dlg := box(c.Title, rows, bw, true)
	if c.Warn {
		dlg[0] = recolor(dlg[0], Warn)
	}
	return page(w, h, head, centered(dlg, w, bodyH(h, head)),
		footer(w, []Hint{{"←→", "choose"}, {"enter", "confirm"}, {"y", c.Yes}, {"n", c.No}}, []Hint{{"ctrl+c", "quit"}}))
}

// recolor changes the border style of a box line.
func recolor(l Line, st Style) Line {
	out := make(Line, len(l))
	for i, s := range l {
		if s.S&roleMask == Accent || s.S&roleMask == Border {
			s.S = s.S&^roleMask | st
		}
		out[i] = s
	}
	return out
}

func (c *Confirm) buttons(w int) Line {
	b := func(label string, on bool) Line {
		if on {
			return L(" "+label+" ", Accent, Bold, Cursor)
		}
		return L(" "+label+" ", Dim)
	}
	l := Cat(b(c.Yes, c.yes), L("   "), b(c.No, !c.yes))
	pad := max((w-l.Width())/2, 0)
	return Cat(L(strings.Repeat(" ", pad)), l)
}
