// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Danang Galuh Tegar Prasetyo

// Package screen holds the full-screen interface: the screens, how they look
// and how they react to keys. It does not talk to the terminal. A screen turns
// a key into a change of its own state and draws itself as lines of styled
// text, so all of it is tested without a terminal. internal/app connects it to
// Bubble Tea.
package screen

import (
	"strings"

	"github.com/charmbracelet/x/ansi"
)

// Style is the look of a span of text.
type Style uint8

// The low bits choose a color role. The flags add to it.
const (
	Plain Style = iota
	Accent
	Dim
	OK
	Warn
	Err
	Border

	roleMask Style = 0x0f
	Bold     Style = 0x10 // bold
	Sel      Style = 0x20 // the cursor row: a background
	Cursor   Style = 0x40 // the text caret: reverse video
)

// Span is text in one style.
type Span struct {
	T string
	S Style
}

// Line is one row of the screen.
type Line []Span

// L builds a line from a plain string.
func L(s string, st ...Style) Line {
	var x Style
	for _, v := range st {
		x |= v
	}
	return Line{{s, x}}
}

// Add returns the line with spans appended.
func (l Line) Add(spans ...Span) Line { return append(append(Line(nil), l...), spans...) }

// Cat joins lines into one.
func Cat(ls ...Line) Line {
	var out Line
	for _, l := range ls {
		out = append(out, l...)
	}
	return out
}

// Width is the number of terminal cells the line takes.
func (l Line) Width() int {
	n := 0
	for _, s := range l {
		n += ansi.StringWidth(s.T)
	}
	return n
}

// Plain is the text without styles.
func (l Line) Plain() string {
	var b strings.Builder
	for _, s := range l {
		b.WriteString(s.T)
	}
	return b.String()
}

// Cut returns the line cut to w cells. If it was longer, the last cell is an
// ellipsis. A shorter line is returned as it is.
func (l Line) Cut(w int) Line {
	if w <= 0 {
		return nil
	}
	if l.Width() <= w {
		return l
	}
	var out Line
	left := w - 1
	for _, s := range l {
		sw := ansi.StringWidth(s.T)
		if sw <= left {
			out = append(out, s)
			left -= sw
			continue
		}
		if left > 0 {
			out = append(out, Span{ansi.Truncate(s.T, left, ""), s.S})
		}
		out = append(out, Span{"…", s.S})
		return out
	}
	return out
}

// Fit cuts the line to w cells and pads it with spaces to exactly w.
func (l Line) Fit(w int) Line {
	l = l.Cut(w)
	if p := w - l.Width(); p > 0 {
		l = append(append(Line(nil), l...), Span{strings.Repeat(" ", p), padStyle(l)})
	}
	return l
}

// padStyle makes padding carry the cursor-row background of the line.
func padStyle(l Line) Style {
	if len(l) > 0 && l[len(l)-1].S&Sel != 0 {
		return Sel
	}
	return Plain
}

// Highlight gives every span the cursor-row background.
func (l Line) Highlight() Line {
	out := make(Line, len(l))
	for i, s := range l {
		out[i] = Span{s.T, s.S | Sel}
	}
	return out
}

// Right returns a line of width w with left at the left edge and right at the
// right edge. If they do not both fit, the left part is cut.
func Right(w int, left, right Line) Line {
	rw := right.Width()
	if rw >= w {
		return right.Fit(w)
	}
	gap := 1
	l := left.Cut(w - rw - gap)
	pad := w - l.Width() - rw
	return Cat(l, L(strings.Repeat(" ", pad)), right)
}

// Wrap breaks text into lines of at most w cells, at spaces.
func Wrap(text string, w int) []string {
	if w < 1 {
		return nil
	}
	var out []string
	for para := range strings.SplitSeq(text, "\n") {
		cur := ""
		for _, word := range strings.Fields(para) {
			switch {
			case cur == "":
				cur = word
			case ansi.StringWidth(cur)+1+ansi.StringWidth(word) <= w:
				cur += " " + word
			default:
				out = append(out, cur)
				cur = word
			}
			for ansi.StringWidth(cur) > w { // a word longer than a line
				out = append(out, ansi.Truncate(cur, w, ""))
				cur = ansi.Cut(cur, w, ansi.StringWidth(cur))
			}
		}
		out = append(out, cur)
	}
	return out
}

// Blank returns n empty lines of width w.
func Blank(n, w int) []Line {
	out := make([]Line, n)
	for i := range out {
		out[i] = L(strings.Repeat(" ", w))
	}
	return out
}

// ColorMode is how many colors the terminal has.
type ColorMode int

// The color modes: none, 16 colors and 256 colors.
const (
	ColorNone ColorMode = iota // no colors: bold and reverse only
	Color16
	Color256
)

// Theme turns styled lines into text for the terminal.
type Theme struct{ Mode ColorMode }

// DetectTheme chooses the color mode from the environment. getenv is
// os.Getenv, or a fake in tests.
func DetectTheme(getenv func(string) string) Theme {
	term := getenv("TERM")
	switch {
	case getenv("NO_COLOR") != "", term == "", term == "dumb":
		return Theme{ColorNone}
	case strings.Contains(term, "256color"), strings.HasPrefix(term, "xterm"),
		getenv("COLORTERM") != "", strings.Contains(term, "kitty"),
		strings.Contains(term, "alacritty"), strings.Contains(term, "foot"),
		strings.Contains(term, "wezterm"), strings.Contains(term, "ghostty"):
		return Theme{Color256}
	}
	return Theme{Color16}
}

var sgr256 = map[Style]string{
	Accent: "38;5;80", Dim: "38;5;245", OK: "38;5;114",
	Warn: "38;5;179", Err: "38;5;203", Border: "38;5;240",
}

var sgr16 = map[Style]string{
	Accent: "36", Dim: "90", OK: "32", Warn: "33", Err: "31", Border: "90",
}

func (t Theme) codes(s Style) string {
	var c []string
	if s&Bold != 0 {
		c = append(c, "1")
	}
	switch t.Mode {
	case Color256:
		if v, ok := sgr256[s&roleMask]; ok {
			c = append(c, v)
		}
		if s&Sel != 0 {
			c = append(c, "48;5;237")
		}
	case Color16:
		if v, ok := sgr16[s&roleMask]; ok {
			c = append(c, v)
		}
		if s&Sel != 0 {
			c = append(c, "7")
		}
	default:
		if s&Sel != 0 {
			c = append(c, "7")
		}
	}
	if s&Cursor != 0 {
		c = append(c, "7")
	}
	return strings.Join(c, ";")
}

// Render writes the lines as one string, one per row.
func (t Theme) Render(lines []Line) string {
	var b strings.Builder
	for i, l := range lines {
		if i > 0 {
			b.WriteByte('\n')
		}
		for _, s := range l {
			if s.T == "" {
				continue
			}
			if c := t.codes(s.S); c != "" {
				b.WriteString("\x1b[")
				b.WriteString(c)
				b.WriteString("m")
				b.WriteString(s.T)
				b.WriteString("\x1b[0m")
			} else {
				b.WriteString(s.T)
			}
		}
	}
	return b.String()
}
