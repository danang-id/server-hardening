// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Danang Galuh Tegar Prasetyo

package screen

import (
	"strings"
	"time"

	"github.com/danang-id/server-hardening/internal/sysdetect"
)

// ProgramName is what the start screen shows as the name of the tool.
const ProgramName = "server-hardening"

// Title and Repository are the two lines above the machine on the start screen.
const (
	Title      = "Interactive Server Hardening"
	Repository = "github.com/danang-id/server-hardening"
)

// Welcome is the first screen: it tells what computer the tool is on, whether
// it can harden it, and offers to start or to leave.
type Welcome struct {
	hostLabel
	Machine sysdetect.Machine
	// Reasons is why the computer is not supported, one sentence each. Empty
	// means supported.
	Reasons []string

	// Start is true when the user chose to go on. It is only ever true on a
	// supported computer.
	Start bool
	exit  bool // the cursor is on Exit
}

// NewWelcome makes the start screen. The cursor starts on Start, or on Exit
// when Start cannot be used.
func NewWelcome(m sysdetect.Machine, reasons []string) *Welcome {
	return &Welcome{Machine: m, Reasons: reasons, exit: len(reasons) > 0}
}

// Supported reports whether the tool can harden this computer.
func (c *Welcome) Supported() bool { return len(c.Reasons) == 0 }

func (c *Welcome) Tick(time.Time) {}

func (c *Welcome) Key(k string) Event {
	switch k {
	case "ctrl+c", "q", "esc":
		return Quit
	case "left", "right", "tab", "shift+tab", "h", "l":
		if c.Supported() {
			c.exit = !c.exit
		}
	case "s":
		if c.Supported() {
			c.Start = true
			return Done
		}
	case "enter":
		if c.exit || !c.Supported() {
			return Quit
		}
		c.Start = true
		return Done
	}
	return None
}

const welcomeLabel = 16

func (c *Welcome) View(w, h int) []Line {
	bw := modalWidth(w)
	cw := bw - 4

	label := func(s string) Line { return L(s+strings.Repeat(" ", max(welcomeLabel-len(s), 1)), Dim) }
	row := func(name, text string, st Style) []Line { return wrapHang(label(name), text, st, cw) }

	var rows []Line
	rows = append(rows, row("OS", c.Machine.OS, Bold)...)
	rows = append(rows, row("Kernel", c.Machine.Kernel, Bold)...)
	rows = append(rows, row("Architecture", c.Machine.Arch, Bold)...)
	if c.Supported() {
		rows = append(rows, row("Support status", "✔ SUPPORTED", OK|Bold)...)
	} else {
		rows = append(rows, row("Support status", "✘ NOT SUPPORTED", Err|Bold)...)
		// One reason is a sentence. Several are points, each wrapped under its
		// own text.
		for i, r := range c.Reasons {
			name, mark := "", ""
			if i == 0 {
				name = "Reason"
			}
			if len(c.Reasons) > 1 {
				mark = "• "
			}
			rows = append(rows, wrapHang(Cat(label(name), L(mark, Dim)), r, Warn, cw)...)
		}
	}
	rows = append(rows, L(""), c.buttons(cw))

	block := []Line{L(Title, Bold), L(Repository, Dim), L("")}
	block = append(block, box("This machine", rows, bw, c.Supported())...)

	head := headerNamed(w, ProgramName, "", c.Host, L(""))
	hints := []Hint{{"←→", "choose"}, {"enter", "confirm"}, {"s", "start"}}
	if !c.Supported() {
		hints = []Hint{{"enter", "exit"}}
	}
	return page(w, h, head, centered(block, w, bodyH(h, head)),
		footer(w, hints, []Hint{{"q", "exit"}}))
}

func (c *Welcome) buttons(w int) Line {
	start := L(" Start ", Border) // not available
	if c.Supported() {
		start = L(" Start ", Dim)
		if !c.exit {
			start = L(" Start ", Accent, Bold, Cursor)
		}
	}
	exit := L(" Exit ", Dim)
	if c.exit {
		exit = L(" Exit ", Accent, Bold, Cursor)
	}
	l := Cat(start, L("   "), exit)
	return Cat(L(strings.Repeat(" ", max((w-l.Width())/2, 0))), l)
}
