// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Danang Galuh Tegar Prasetyo

package screen

import (
	"fmt"
	"strings"
	"testing"

	"github.com/danang-id/server-hardening/internal/control"
)

func TestFormTextWithDefaultAndEnter(t *testing.T) {
	f := NewForm("Debian 13", "Set the hostname", []control.Input{
		{Key: "name", Label: "Host name", Help: "Short name, letters and digits.", Default: "web-01"},
	})
	v := f.View(80, 24)
	sized(t, v, 80, 24)
	contains(t, v, "Set the hostname", "Host name", "Short name", "web-01", "enter continue")
	if ev := press(f, "enter"); ev != Done {
		t.Fatal("enter accepts the suggestion")
	}
	if got := f.Values.String("name"); got != "web-01" {
		t.Fatalf("got %q", got)
	}
}

func TestFormEditsTheDefault(t *testing.T) {
	f := NewForm("x", "t", []control.Input{{Key: "n", Label: "N", Default: "abc"}})
	press(f, "backspace", "backspace")
	typed(f, "XY")
	press(f, "left", "left", "delete")
	press(f, "enter")
	if got := f.Values.String("n"); got != "aY" {
		// "abc" -> "a" -> "aXY" -> caret after a, delete X -> "aY"
		t.Fatalf("got %q", got)
	}
}

func TestFormValidationShowsErrorAndKeepsFocus(t *testing.T) {
	f := NewForm("x", "t", []control.Input{{
		Key: "port", Label: "Port",
		Validate: func(s string) error {
			if s == "22" {
				return fmt.Errorf("port 22 is where SSH is now")
			}
			return nil
		},
	}})
	if ev := press(f, "enter"); ev != None {
		t.Fatal("empty and required")
	}
	contains(t, f.View(80, 24), "A value is required.")
	typed(f, "22")
	if ev := press(f, "enter"); ev != None {
		t.Fatal("validator must stop")
	}
	contains(t, f.View(80, 24), "Port 22 is where SSH is now.")
	press(f, "backspace")
	lacks(t, f.View(80, 24), "Port 22 is where")
	press(f, "backspace")
	typed(f, "2222")
	if ev := press(f, "enter"); ev != Done || f.Values.String("port") != "2222" {
		t.Fatalf("ev %v values %v", ev, f.Values)
	}
}

func TestFormOptionalMayBeEmpty(t *testing.T) {
	f := NewForm("x", "t", []control.Input{{Key: "k", Label: "K", Optional: true,
		Validate: func(string) error { return fmt.Errorf("never called for empty") }}})
	if ev := press(f, "enter"); ev != Done {
		t.Fatal("optional empty must pass")
	}
}

func TestFormSecretIsHiddenAndConfirmed(t *testing.T) {
	f := NewForm("x", "t", []control.Input{{Key: "pw", Label: "Password", Kind: control.Secret, Confirm: true}})
	typed(f, "hunter2")
	contains(t, f.View(80, 24), "•••••••")
	lacks(t, f.View(80, 24), "hunter2")
	press(f, "enter")
	contains(t, f.View(80, 24), "Repeat to confirm", "question 02 of 02")
	typed(f, "hunter3")
	if ev := press(f, "enter"); ev != None {
		t.Fatal("mismatch must stop")
	}
	contains(t, f.View(80, 24), "The two entries differ.")
	press(f, "backspace")
	typed(f, "2")
	if ev := press(f, "enter"); ev != Done || f.Values.String("pw") != "hunter2" {
		t.Fatalf("ev %v values %v", ev, f.Values)
	}
	if _, ok := f.Values[""]; ok || len(f.Values) != 1 {
		t.Fatalf("the repeat field must not be an answer: %v", f.Values)
	}
}

func TestFormChoice(t *testing.T) {
	f := NewForm("x", "t", []control.Input{{Key: "m", Label: "Mode", Kind: control.Choice, Default: "b",
		Options: []control.Option{{Value: "a", Label: "Alpha"}, {Value: "b", Label: "Beta", Help: "The second one."}, {Value: "c", Label: "Gamma"}}}})
	contains(t, f.View(80, 24), "(●) Beta", "The second one.", "( ) Alpha")
	press(f, "down", "enter")
	if f.Values.String("m") != "c" {
		t.Fatalf("got %v", f.Values)
	}
}

func TestFormMultiChoice(t *testing.T) {
	f := NewForm("x", "t", []control.Input{{Key: "p", Label: "Ports", Kind: control.MultiChoice, DefaultMulti: []string{"80"},
		Options: []control.Option{{Value: "80", Label: "80/tcp"}, {Value: "443", Label: "443/tcp"}}}})
	contains(t, f.View(80, 24), "[x] 80/tcp", "[ ] 443/tcp")
	press(f, "down", " ", "enter")
	if got := strings.Join(f.Values.List("p"), ","); got != "80,443" {
		t.Fatalf("got %q", got)
	}
	g := NewForm("x", "t", []control.Input{{Key: "p", Kind: control.MultiChoice, Options: []control.Option{{Value: "1", Label: "one"}}}})
	press(g, "enter")
	if len(g.Values.List("p")) != 0 {
		t.Fatal("nothing ticked gives nothing")
	}
}

func TestFormTextAreaEnterMakesALineAndTabContinues(t *testing.T) {
	f := NewForm("x", "t", []control.Input{{Key: "ports", Label: "Ports", Kind: control.TextArea}})
	typed(f, "80/tcp")
	if ev := press(f, "enter"); ev != None {
		t.Fatal("enter in a text area is a new line")
	}
	typed(f, "443/tcp")
	v := f.View(80, 24)
	sized(t, v, 80, 24)
	contains(t, v, "80/tcp", "443/tcp", "enter new line", "tab continue")
	if ev := press(f, "tab"); ev != Done {
		t.Fatal("tab continues")
	}
	if got := f.Values.String("ports"); got != "80/tcp\n443/tcp" {
		t.Fatalf("got %q", got)
	}
}

func TestFormTextAreaEditingAcrossLines(t *testing.T) {
	f := NewForm("x", "t", []control.Input{{Key: "t", Kind: control.TextArea, Default: "one\ntwo"}})
	press(f, "up", "end")
	typed(f, "!")
	press(f, "down", "home", "backspace") // joins "one!" and "two"
	press(f, "tab")
	if got := f.Values.String("t"); got != "one!two" {
		t.Fatalf("got %q", got)
	}
}

func TestFormPasteKeepsLinesInATextAreaAndFlattensInALine(t *testing.T) {
	f := NewForm("x", "t", []control.Input{{Key: "t", Kind: control.TextArea}, {Key: "s", Label: "S"}})
	f.Key("paste:ssh-ed25519 AAAA one\nssh-ed25519 BBBB two\n")
	press(f, "tab")
	if got := f.Values; got != nil {
		t.Fatal("not done yet")
	}
	f.Key("paste:a\nb")
	press(f, "enter")
	if f.Values.String("t") != "ssh-ed25519 AAAA one\nssh-ed25519 BBBB two" {
		t.Fatalf("text area: %q", f.Values.String("t"))
	}
	if f.Values.String("s") != "a b" {
		t.Fatalf("one line: %q", f.Values.String("s"))
	}
}

func TestFormBackAndPrevious(t *testing.T) {
	f := NewForm("x", "t", []control.Input{{Key: "a", Label: "A", Default: "1"}, {Key: "b", Label: "B", Default: "2"}})
	press(f, "enter")
	if f.idx != 1 {
		t.Fatal("moved to the second")
	}
	press(f, "shift+tab")
	if f.idx != 0 {
		t.Fatal("moved back")
	}
	if press(f, "esc") != Back {
		t.Fatal("esc is back")
	}
	if press(f, "ctrl+c") != Quit {
		t.Fatal("ctrl+c quits")
	}
}

func TestFormLongLineScrollsAndStaysInsideTheBox(t *testing.T) {
	long := strings.Repeat("abcdefghij", 20)
	f := NewForm("x", "t", []control.Input{{Key: "k", Label: "Key", Default: long}})
	v := f.View(80, 24)
	sized(t, v, 80, 24)
	f2 := NewForm("x", "t", []control.Input{{Key: "k", Kind: control.TextArea, Label: "Key", Default: long + "\n" + long}})
	sized(t, f2.View(80, 24), 80, 24)
	sized(t, f2.View(64, 18), 64, 18)
}

func TestEditorMultiByteAndWide(t *testing.T) {
	e := newEditor("héllo", false, false)
	e.key("backspace")
	e.key("backspace")
	if e.text() != "hél" {
		t.Fatalf("got %q", e.text())
	}
	e.key("ctrl+u")
	if e.text() != "" {
		t.Fatalf("got %q", e.text())
	}
	e.insert("one two three")
	e.key("ctrl+w")
	if e.text() != "one two " {
		t.Fatalf("ctrl+w: %q", e.text())
	}
}

func TestFormTextArrivingAsOneChunkIsText(t *testing.T) {
	f := NewForm("x", "t", []control.Input{{Key: "k", Label: "K"}})
	f.Key("ssh-ed25519 AAAAC3 demo")
	f.Key("fast")
	press(f, "enter")
	if got := f.Values.String("k"); got != "ssh-ed25519 AAAAC3 demofast" {
		t.Fatalf("got %q", got)
	}
	for _, name := range []string{"enter", "ctrl+a", "alt+b", "shift+tab", "f5", "pgdown"} {
		if !isKeyName(name) {
			t.Errorf("%q is a key name", name)
		}
	}
	for _, text := range []string{"fast", "ab", "file", "ctrl+ a", "altitude"} {
		if isKeyName(text) {
			t.Errorf("%q is text", text)
		}
	}
}

// Long questions, errors and choices wrap. Nothing is cut with an ellipsis.
func TestFormWrapsLongTextInsteadOfCuttingIt(t *testing.T) {
	label := "Static addresses with prefix length (IPv4 and IPv6, separated by spaces), such as 203.0.113.5/24"
	f := NewForm("x", "t", []control.Input{
		{Key: "a", Label: label, Validate: func(string) error {
			return fmt.Errorf("%q is not an address with a prefix length, such as 203.0.113.5/24 or 2001:db8::5/64", "eth0")
		}},
		{Key: "c", Label: "Pick", Kind: control.Choice, Options: []control.Option{
			{Value: "x", Label: "A very long choice that describes in detail what happens when you pick it, more than one line"},
		}},
	})
	typed(f, "eth0")
	press(f, "enter")
	for _, w := range []int{64, 80} {
		v := f.View(w, 24)
		sized(t, v, w, 24)
		text := plain(v)
		if strings.Contains(text, "…") {
			t.Fatalf("w=%d: text was cut:\n%s", w, text)
		}
		flat := strings.Join(strings.Fields(strings.ReplaceAll(text, "│", " ")), " ")
		for _, want := range []string{"such as 203.0.113.5/24", "or 2001:db8::5/64"} {
			if !strings.Contains(flat, want) {
				t.Fatalf("w=%d: lost %q:\n%s", w, want, text)
			}
		}
	}
}
