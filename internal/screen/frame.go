// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Danang Galuh Tegar Prasetyo

package screen

import (
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/danang-id/server-hardening/internal/control"
)

// Event is what a screen reports after a key press.
type Event int

const (
	None Event = iota // keep going
	Done              // the screen has its answer
	Back              // the user wants the previous screen
	Quit              // the user wants to stop everything
)

// Screen is one view of the interface, such as the selection or the review.
//
// Key receives a key as Bubble Tea names it: "up", "enter", "shift+tab",
// "ctrl+c", "a", " " for the space bar. Pasted text arrives as "paste:" and the
// text.
type Screen interface {
	Key(k string) Event
	// Tick tells the screen the time, a few times a second.
	Tick(now time.Time)
	// View draws the screen as exactly h lines of exactly w cells.
	View(w, h int) []Line
}

// Terminal sizes below these get a message instead of a screen.
const (
	MinWidth  = 64
	MinHeight = 18
)

// TooSmall is shown when the terminal is smaller than the minimum.
func TooSmall(w, h int) []Line {
	out := Blank(h, w)
	msg := L(fmt.Sprintf("Terminal too small: need %d x %d, have %d x %d", MinWidth, MinHeight, w, h), Warn)
	if h > 0 {
		out[h/2] = msg.Fit(w)
	}
	return out
}

// wrapHang wraps text to width w. The first line starts with first, and the
// next lines are indented to line up under the text, not under first.
func wrapHang(first Line, text string, st Style, w int) []Line {
	room := max(w-first.Width(), 1)
	indent := strings.Repeat(" ", first.Width())
	var out []Line
	for i, ln := range Wrap(text, room) {
		if i == 0 {
			out = append(out, Cat(first, Line{{ln, st}}))
		} else {
			out = append(out, Cat(L(indent), Line{{ln, st}}))
		}
	}
	if len(out) == 0 {
		out = append(out, first)
	}
	return out
}

// sep separates items on one row. A full-height bar is easier to see than a
// middle dot.
const sep = " │ "

// sepLine is sep as a line, dim so that it divides without shouting.
func sepLine() Line { return L(sep, Dim) }

// hostLabel is the machine name shown in the header. The app keeps it up to
// date while the screen is up, so a renamed host shows at once.
type hostLabel struct{ Host string }

// SetHost sets the name shown in the header.
func (h *hostLabel) SetHost(s string) { h.Host = s }

// HostSetter is a screen that shows the host name.
type HostSetter interface{ SetHost(string) }

// header is the top of the screen: the program name and the system on the
// left, and the host name with the text in right on the right. When they do
// not fit on one row, the right side moves to a second row under the name.
func header(w int, system, host string, right Line) []Line {
	return headerNamed(w, "server-hardening", system, host, right)
}

// headerNamed is header with another name for the tool.
func headerNamed(w int, program, system, host string, right Line) []Line {
	name := Cat(L(" 🔐 ", Plain), L(program, Bold))
	join := func(parts ...Line) Line {
		var out Line
		for _, p := range parts {
			if p.Width() == 0 {
				continue
			}
			if len(out) > 0 {
				out = append(out, sepLine()...)
			}
			out = append(out, p...)
		}
		return out
	}
	var sys, hst Line
	if system != "" {
		sys = L(system, Dim)
	}
	if host != "" {
		hst = L(host, Bold)
	}
	left, rest := join(Cat(name), sys), join(right, hst)
	if rest.Width() == 0 {
		return []Line{Right(w, left, L(" ")).Fit(w)}
	}
	if left.Width()+2+rest.Width()+1 <= w {
		return []Line{Right(w, left, Cat(rest, L(" "))).Fit(w)}
	}
	// Two rows. The second lines up under the name, past the icon.
	if left.Width() > w {
		left = Cat(name)
	}
	return []Line{left.Fit(w), Cat(L("    "), rest).Fit(w)}
}

// Hint is one key and what it does, for the bottom row.
type Hint struct{ Key, Label string }

// footer is the last row. Hints are dropped from the end of left until the
// row fits; right stays.
func footer(w int, left, right []Hint) Line {
	mk := func(hs []Hint) Line {
		var l Line
		for i, h := range hs {
			if i > 0 {
				l = append(l, Span{"  ", Plain})
			}
			l = append(l, Span{h.Key, Accent}, Span{" " + h.Label, Dim})
		}
		return l
	}
	r := mk(right)
	for n := len(left); n >= 0; n-- {
		l := mk(left[:n])
		if 1+l.Width()+2+r.Width()+1 <= w || n == 0 {
			return Right(w, Cat(L(" "), l), Cat(r, L(" "))).Fit(w)
		}
	}
	return L("").Fit(w)
}

// box draws a rounded frame of width w around inner lines. The title sits in
// the top edge. Inner lines are cut or padded to fit.
func box(title string, inner []Line, w int, strong bool) []Line {
	bs := Border
	if strong {
		bs = Accent
	}
	top := Line{{"╭─", bs}}
	if title != "" {
		top = append(top, Span{" ", Plain}, Span{title, Bold}, Span{" ", Plain})
	}
	used := top.Width()
	if fill := w - used - 1; fill > 0 {
		top = append(top, Span{strings.Repeat("─", fill), bs})
	}
	top = append(top, Span{"╮", bs})
	out := []Line{top.Fit(w)}
	for _, l := range inner {
		row := Cat(Line{{"│ ", bs}}, l.Fit(w-4), Line{{" │", bs}})
		out = append(out, row)
	}
	out = append(out, Line{{"╰" + strings.Repeat("─", max(w-2, 0)) + "╯", bs}}.Fit(w))
	return out
}

// side puts two blocks of lines next to each other.
func side(a, b []Line) []Line {
	n := max(len(a), len(b))
	out := make([]Line, n)
	for i := range out {
		var x, y Line
		if i < len(a) {
			x = a[i]
		}
		if i < len(b) {
			y = b[i]
		}
		out[i] = Cat(x, y)
	}
	return out
}

// bodyH is the height of the body on a screen of height h: what is left after
// the header, the empty row under it, and the footer.
func bodyH(h int, head []Line) int { return h - len(head) - 2 }

// page assembles a full screen: header, a gap, body, footer. The body is cut
// or padded to the room between them.
func page(w, h int, head []Line, body []Line, foot Line) []Line {
	room := bodyH(h, head)
	out := make([]Line, 0, h)
	for _, l := range head {
		out = append(out, l.Fit(w))
	}
	out = append(out, L("").Fit(w))
	for i := 0; i < room; i++ {
		if i < len(body) {
			out = append(out, body[i].Fit(w))
		} else {
			out = append(out, L("").Fit(w))
		}
	}
	return append(out, foot.Fit(w))
}

// centered puts a block in the middle of a w x room area.
func centered(block []Line, w, room int) []Line {
	if len(block) > room {
		block = block[:room]
	}
	top := (room - len(block)) / 2
	out := make([]Line, 0, room)
	for i := 0; i < top; i++ {
		out = append(out, L("").Fit(w))
	}
	for _, l := range block {
		pad := (w - l.Width()) / 2
		out = append(out, Cat(L(strings.Repeat(" ", max(pad, 0))), l).Fit(w))
	}
	return out
}

// modalWidth is the width of a dialog on a terminal of width w.
func modalWidth(w int) int { return min(max(w-8, 40), 72) }

// Symbols and words for the tags.
type tagInfo struct {
	icon, word string
}

var tagInfos = map[control.Tag]tagInfo{
	control.TagLockout:      {"🔒", "can lock you out"},
	control.TagIrreversible: {"⛔", "cannot be undone"},
	control.TagReboot:       {"🔁", "needs a reboot"},
	control.TagCompat:       {"🧩", "may break some software"},
	control.TagExternal:     {"🌐", "downloads from outside the system's own repositories"},
	control.TagInput:        {"📝", "asks you a question"},
	control.TagReadonly:     {"🔍", "only checks"},
}

// tagOrder is the order tags are shown in.
var tagOrder = []control.Tag{
	control.TagLockout, control.TagIrreversible, control.TagReboot,
	control.TagCompat, control.TagExternal, control.TagInput,
	control.TagReadonly,
}

// rowIcons is the short form of the tags at the end of a list row. Questions
// are left out, because most controls ask one.
func rowIcons(tags []control.Tag) string {
	var b strings.Builder
	for _, t := range tagOrder {
		if t == control.TagInput || t == control.TagReadonly {
			continue
		}
		if slices.Contains(tags, t) {
			if b.Len() > 0 {
				b.WriteByte(' ')
			}
			b.WriteString(tagInfos[t].icon)
		}
	}
	return b.String()
}

// tagLine is the long form of the tags, for the detail pane.
func tagLine(tags []control.Tag) Line {
	var l Line
	for _, t := range tagOrder {
		if !slices.Contains(tags, t) {
			continue
		}
		if len(l) > 0 {
			l = append(l, Span{"   ", Plain})
		}
		st := Dim
		if t == control.TagLockout || t == control.TagIrreversible {
			st = Warn
		}
		l = append(l, Span{tagInfos[t].icon + " " + tagInfos[t].word, st})
	}
	return l
}

// shortName is the category name used in the narrow list.
var shortName = map[int]string{
	1: "Baseline", 2: "Accounts", 3: "Remote access", 4: "Network",
	5: "Attack surface", 6: "Access control", 7: "Logging", 8: "System & kernel",
	9: "Filesystem", 10: "Miscellaneous",
}

// ShortName returns a name of at most 16 cells for category n, or the full name
// if n is not known.
func ShortName(n int, full string) string {
	if s, ok := shortName[n]; ok {
		return s
	}
	return full
}

// two formats n with at least two digits.
func two(n int) string { return fmt.Sprintf("%02d", n) }
