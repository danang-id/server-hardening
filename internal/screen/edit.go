// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Danang Galuh Tegar Prasetyo

package screen

import (
	"strings"
	"unicode"
	"unicode/utf8"
)

// editor is a text field: one line, or several. It is used for every typed
// answer.
type editor struct {
	lines [][]rune
	r, c  int // the caret: line and column, in runes
	multi bool
	mask  bool // show dots instead of the text (a secret)
	x0    int  // first visible column of the caret line
	top   int  // first visible line
}

func newEditor(text string, multi, mask bool) *editor {
	e := &editor{multi: multi, mask: mask, lines: [][]rune{nil}}
	e.insert(text)
	return e
}

// text returns the content, lines joined with a line break.
func (e *editor) text() string {
	parts := make([]string, len(e.lines))
	for i, l := range e.lines {
		parts[i] = string(l)
	}
	return strings.Join(parts, "\n")
}

func (e *editor) cur() []rune { return e.lines[e.r] }

// insert puts text at the caret. In a one-line field, line breaks become
// spaces.
func (e *editor) insert(s string) {
	s = strings.ReplaceAll(strings.ReplaceAll(s, "\r\n", "\n"), "\r", "\n")
	if !e.multi {
		s = strings.Join(strings.Fields(strings.ReplaceAll(s, "\n", " ")), " ")
	}
	for _, r := range s {
		switch {
		case r == '\n':
			e.newline()
		case r == '\t':
			e.put(' ')
		case unicode.IsControl(r):
		default:
			e.put(r)
		}
	}
}

func (e *editor) put(r rune) {
	l := e.cur()
	l = append(l, 0)
	copy(l[e.c+1:], l[e.c:])
	l[e.c] = r
	e.lines[e.r] = l
	e.c++
}

func (e *editor) newline() {
	l := e.cur()
	rest := append([]rune(nil), l[e.c:]...)
	e.lines[e.r] = append([]rune(nil), l[:e.c]...)
	e.lines = append(e.lines, nil)
	copy(e.lines[e.r+2:], e.lines[e.r+1:])
	e.lines[e.r+1] = rest
	e.r++
	e.c = 0
}

func isPrintable(k string) (rune, bool) {
	rs := []rune(k)
	if len(rs) != 1 {
		return 0, false
	}
	r := rs[0]
	if unicode.IsControl(r) {
		return 0, false
	}
	return r, true
}

// key handles an editing key. It leaves enter, tab and esc to the form,
// except that enter makes a new line in a multi-line field.
func (e *editor) key(k string) {
	if text, ok := strings.CutPrefix(k, "paste:"); ok {
		e.insert(text)
		return
	}
	if r, ok := isPrintable(k); ok {
		e.put(r)
		return
	}
	// Text typed or pasted faster than the terminal reports keys arrives as
	// one chunk, without the paste marks. It is text, not a key name.
	if utf8.RuneCountInString(k) > 1 && !isKeyName(k) {
		e.insert(k)
		return
	}
	switch k {
	case "space":
		e.put(' ')
	case "enter":
		if e.multi {
			e.newline()
		}
	case "left":
		if e.c > 0 {
			e.c--
		} else if e.r > 0 {
			e.r--
			e.c = len(e.cur())
		}
	case "right":
		if e.c < len(e.cur()) {
			e.c++
		} else if e.r < len(e.lines)-1 {
			e.r++
			e.c = 0
		}
	case "up":
		if e.multi && e.r > 0 {
			e.r--
			e.c = min(e.c, len(e.cur()))
		}
	case "down":
		if e.multi && e.r < len(e.lines)-1 {
			e.r++
			e.c = min(e.c, len(e.cur()))
		}
	case "home", "ctrl+a":
		e.c = 0
	case "end", "ctrl+e":
		e.c = len(e.cur())
	case "backspace", "ctrl+h":
		switch {
		case e.c > 0:
			l := e.cur()
			e.lines[e.r] = append(l[:e.c-1], l[e.c:]...)
			e.c--
		case e.r > 0:
			prev := e.lines[e.r-1]
			e.c = len(prev)
			e.lines[e.r-1] = append(prev, e.cur()...)
			e.lines = append(e.lines[:e.r], e.lines[e.r+1:]...)
			e.r--
		}
	case "delete", "ctrl+d":
		l := e.cur()
		switch {
		case e.c < len(l):
			e.lines[e.r] = append(l[:e.c], l[e.c+1:]...)
		case e.r < len(e.lines)-1:
			e.lines[e.r] = append(l, e.lines[e.r+1]...)
			e.lines = append(e.lines[:e.r+1], e.lines[e.r+2:]...)
		}
	case "ctrl+u":
		e.lines[e.r] = append([]rune(nil), e.cur()[e.c:]...)
		e.c = 0
	case "ctrl+k":
		e.lines[e.r] = append([]rune(nil), e.cur()[:e.c]...)
	case "ctrl+w", "alt+backspace":
		l := e.cur()
		i := e.c
		for i > 0 && l[i-1] == ' ' {
			i--
		}
		for i > 0 && l[i-1] != ' ' {
			i--
		}
		e.lines[e.r] = append(l[:i], l[e.c:]...)
		e.c = i
	}
}

// view draws the field inside a frame of width w. A one-line field is one row
// high; a multi-line field is h rows.
func (e *editor) view(w, h int, focus bool) []Line {
	rows := 1
	if e.multi {
		rows = h
	}
	cw := w - 4
	if e.r < e.top {
		e.top = e.r
	}
	if e.r >= e.top+rows {
		e.top = e.r - rows + 1
	}
	// Keep the caret in view on its own line.
	if e.c < e.x0 {
		e.x0 = e.c
	}
	if e.c > e.x0+cw-2 {
		e.x0 = e.c - (cw - 2)
	}
	var inner []Line
	for i := e.top; i < len(e.lines) && len(inner) < rows; i++ {
		inner = append(inner, e.row(i, cw, focus))
	}
	for len(inner) < rows {
		inner = append(inner, L(""))
	}
	return box("", inner, w, focus)
}

func (e *editor) row(i, cw int, focus bool) Line {
	rs := e.lines[i]
	if e.mask {
		rs = []rune(strings.Repeat("•", len(rs)))
	}
	x0 := 0
	if i == e.r {
		x0 = e.x0
	}
	x0 = min(x0, len(rs))
	end := min(len(rs), x0+cw-1)
	vis := string(rs[x0:end])
	if !focus || i != e.r {
		l := L(vis)
		if x0 > 0 {
			l = Cat(L("…", Dim), L(string(rs[x0+1:end])))
		}
		if len(rs) > end {
			l = l.Add(Span{"…", Dim})
		}
		return l
	}
	pos := e.c - x0
	before := string(rs[x0:min(x0+pos, len(rs))])
	under, after := " ", ""
	if e.c < len(rs) {
		under = string(rs[e.c])
		after = string(rs[min(e.c+1, end):end])
	}
	return Cat(L(before), L(under, Cursor), L(after))
}

var keyNames = map[string]bool{
	"enter": true, "tab": true, "esc": true, "space": true, "backspace": true, "delete": true,
	"up": true, "down": true, "left": true, "right": true, "home": true, "end": true,
	"pgup": true, "pgdown": true, "insert": true,
}

// isKeyName reports whether k is the name of a key, as Bubble Tea writes it,
// and not typed text.
func isKeyName(k string) bool {
	if keyNames[k] {
		return true
	}
	for _, p := range []string{"ctrl+", "alt+", "shift+", "f"} {
		if strings.HasPrefix(k, p) && !strings.ContainsAny(k, " \t\n") {
			if p == "f" {
				return len(k) <= 3 && strings.Trim(k[1:], "0123456789") == ""
			}
			return true
		}
	}
	return false
}
