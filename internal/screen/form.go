// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Danang Galuh Tegar Prasetyo

package screen

import (
	"strings"
	"time"

	"github.com/danang-id/server-hardening/internal/control"
)

// field is one question on the form.
type field struct {
	in       control.Input
	label    string
	help     string
	ed       *editor
	cursor   int    // Choice and MultiChoice: the row under the cursor
	checked  []bool // MultiChoice
	repeatOf int    // for a "repeat to confirm" field, the field it repeats; else -1
	err      string
}

func (f *field) typed() bool {
	switch f.in.Kind {
	case control.Choice, control.MultiChoice:
		return false
	}
	return true
}

// Form asks the inputs of one control, one at a time.
type Form struct {
	hostLabel
	System string
	Title  string // the control
	Values control.Values

	fields []*field
	idx    int
}

// NewForm builds the form. Defaults are filled in.
func NewForm(system, title string, inputs []control.Input) *Form {
	f := &Form{System: system, Title: title}
	for _, in := range inputs {
		fl := &field{in: in, label: in.Label, help: in.Help, repeatOf: -1}
		switch in.Kind {
		case control.Choice:
			for i, o := range in.Options {
				if o.Value == in.Default {
					fl.cursor = i
				}
			}
		case control.MultiChoice:
			fl.checked = make([]bool, len(in.Options))
			for i, o := range in.Options {
				for _, d := range in.DefaultMulti {
					if d == o.Value {
						fl.checked[i] = true
					}
				}
			}
		default:
			fl.ed = newEditor(in.Default, in.Kind == control.TextArea, in.Kind == control.Secret)
		}
		f.fields = append(f.fields, fl)
		if in.Kind == control.Secret && in.Confirm {
			f.fields = append(f.fields, &field{
				in:       control.Input{Kind: control.Secret},
				label:    "Repeat to confirm",
				ed:       newEditor(in.Default, false, true),
				repeatOf: len(f.fields) - 1,
			})
		}
	}
	return f
}

func (f *Form) Tick(time.Time) {}

func (f *Form) cur() *field { return f.fields[f.idx] }

// validate checks the field under the cursor. It sets the field's error.
func (f *Form) validate(fl *field) bool {
	fl.err = ""
	if !fl.typed() {
		return true
	}
	s := fl.ed.text()
	empty := strings.TrimSpace(s) == ""
	if fl.repeatOf >= 0 {
		if s != f.fields[fl.repeatOf].ed.text() {
			fl.err = "The two entries differ."
			return false
		}
		return true
	}
	switch {
	case empty && !fl.in.Optional:
		fl.err = "A value is required."
		return false
	case !empty && fl.in.Validate != nil:
		if err := fl.in.Validate(s); err != nil {
			fl.err = capital(err.Error())
			if !strings.HasSuffix(fl.err, ".") {
				fl.err += "."
			}
			return false
		}
	}
	return true
}

func (f *Form) next() Event {
	if !f.validate(f.cur()) {
		return None
	}
	if f.idx < len(f.fields)-1 {
		f.idx++
		return None
	}
	f.finish()
	return Done
}

func (f *Form) finish() {
	f.Values = control.Values{}
	for _, fl := range f.fields {
		if fl.repeatOf >= 0 {
			continue
		}
		switch fl.in.Kind {
		case control.Choice:
			if len(fl.in.Options) > 0 {
				f.Values[fl.in.Key] = []string{fl.in.Options[fl.cursor].Value}
			} else {
				f.Values[fl.in.Key] = []string{""}
			}
		case control.MultiChoice:
			var v []string
			for i, o := range fl.in.Options {
				if fl.checked[i] {
					v = append(v, o.Value)
				}
			}
			f.Values[fl.in.Key] = v
		case control.TextArea:
			f.Values[fl.in.Key] = []string{strings.TrimRight(fl.ed.text(), "\n ")}
		default:
			f.Values[fl.in.Key] = []string{fl.ed.text()}
		}
	}
}

func (f *Form) Key(k string) Event {
	fl := f.cur()
	switch k {
	case "ctrl+c":
		return Quit
	case "esc":
		return Back
	case "shift+tab":
		if f.idx > 0 {
			f.idx--
		}
		return None
	case "tab":
		return f.next()
	}
	if strings.HasPrefix(k, "paste:") && fl.typed() {
		fl.err = ""
		fl.ed.key(k)
		return None
	}
	if fl.typed() {
		if k == "enter" && !fl.ed.multi {
			return f.next()
		}
		fl.err = ""
		fl.ed.key(k)
		return None
	}
	n := len(fl.in.Options)
	switch k {
	case "enter":
		return f.next()
	case "up", "k":
		if fl.cursor > 0 {
			fl.cursor--
		}
	case "down", "j":
		if fl.cursor < n-1 {
			fl.cursor++
		}
	case " ", "space", "x":
		if fl.in.Kind == control.MultiChoice && n > 0 {
			fl.checked[fl.cursor] = !fl.checked[fl.cursor]
		}
	case "a":
		if fl.in.Kind == control.MultiChoice {
			all := true
			for _, c := range fl.checked {
				all = all && c
			}
			for i := range fl.checked {
				fl.checked[i] = !all
			}
		}
	}
	return None
}

func (f *Form) View(w, h int) []Line {
	fl := f.cur()
	bw := modalWidth(w)
	cw := bw - 4
	var rows []Line
	if len(f.fields) > 1 {
		rows = append(rows, Right(cw, L(""), L("question "+two(f.idx+1)+" of "+two(len(f.fields)), Dim)))
	}
	for _, ln := range Wrap(fl.label, cw) {
		rows = append(rows, L(ln, Bold))
	}
	for _, ln := range Wrap(fl.help, cw) {
		if ln != "" {
			rows = append(rows, L(ln, Dim))
		}
	}
	rows = append(rows, L(""))
	rows = append(rows, f.widget(fl, cw, h)...)
	if fl.err != "" {
		rows = append(rows, wrapHang(L("✖ ", Err), fl.err, Err, cw)...)
	}
	foot := f.footer(w, fl)
	head := header(w, f.System, f.Host, L(""))
	room := bodyH(h, head)
	return page(w, h, head, centered(box(f.Title, rows, bw, true), w, room), foot)
}

func (f *Form) widget(fl *field, cw, h int) []Line {
	switch fl.in.Kind {
	case control.Choice, control.MultiChoice:
		return optionRows(fl, cw)
	}
	lines := 1
	if fl.ed.multi {
		lines = max(min(h-17, 8), 3)
	}
	return fl.ed.view(cw, lines, true)
}

func optionRows(fl *field, cw int) []Line {
	var rows []Line
	for i, o := range fl.in.Options {
		cur := i == fl.cursor
		var mark string
		if fl.in.Kind == control.Choice {
			mark = "( ) "
			if cur {
				mark = "(●) "
			}
		} else {
			mark = "[ ] "
			if fl.checked[i] {
				mark = "[x] "
			}
		}
		mst, tst := Dim, Plain
		if cur {
			mst, tst = Accent, Bold
		}
		if fl.in.Kind == control.MultiChoice && fl.checked[i] {
			mst = Accent
		}
		pre := "  "
		if cur {
			pre = "› "
		}
		rows = append(rows, wrapHang(Cat(L(pre, Accent), L(mark, mst)), o.Label, tst, cw)...)
		if cur && o.Help != "" {
			for _, ln := range Wrap(o.Help, cw-6) {
				rows = append(rows, L("      "+ln, Dim))
			}
		}
	}
	return rows
}

func (f *Form) footer(w int, fl *field) Line {
	last := f.idx == len(f.fields)-1
	next := "next"
	if last {
		next = "continue"
	}
	var left []Hint
	switch {
	case fl.typed() && fl.ed.multi:
		left = []Hint{{"enter", "new line"}, {"tab", next}}
	case fl.typed():
		left = []Hint{{"enter", next}}
	case fl.in.Kind == control.MultiChoice:
		left = []Hint{{"↑↓", "move"}, {"space", "tick"}, {"enter", next}}
	default:
		left = []Hint{{"↑↓", "choose"}, {"enter", next}}
	}
	if f.idx > 0 {
		left = append(left, Hint{"shift+tab", "prev"})
	}
	left = append(left, Hint{"esc", "back"})
	return footer(w, left, []Hint{{"ctrl+c", "quit"}})
}
