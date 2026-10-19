// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Danang Galuh Tegar Prasetyo

package screen

import (
	"strings"
	"testing"
	"unicode/utf8"
)

func TestConfirmButtons(t *testing.T) {
	c := NewConfirm("Debian 13", "Add these too?", []string{"The controls below are needed by the ones you ticked."},
		[]string{"Install zsh (needed by Oh My Zsh)", "Install a firewall"}, "Add them", "Skip", true)
	v := c.View(80, 24)
	sized(t, v, 80, 24)
	contains(t, v, "Add these too?", "needed by the ones you ticked", "• Install zsh", "Add them", "Skip")
	if ev := press(c, "enter"); ev != Done || !c.Result {
		t.Fatal("enter on yes")
	}
	c = NewConfirm("x", "t", nil, nil, "Yes", "No", true)
	press(c, "right")
	if ev := press(c, "enter"); ev != Done || c.Result {
		t.Fatal("enter on no")
	}
	c = NewConfirm("x", "t", nil, nil, "Yes", "No", false)
	if ev := press(c, "y"); ev != Done || !c.Result {
		t.Fatal("y")
	}
	c = NewConfirm("x", "t", nil, nil, "Yes", "No", true)
	if ev := press(c, "esc"); ev != Done || c.Result {
		t.Fatal("esc is no")
	}
	if press(NewConfirm("x", "t", nil, nil, "Yes", "No", true), "ctrl+c") != Quit {
		t.Fatal("ctrl+c")
	}
}

func TestConfirmLongListScrolls(t *testing.T) {
	var l []string
	for i := 0; i < 40; i++ {
		l = append(l, "Item "+two(i))
	}
	c := NewConfirm("x", "t", []string{"Body text."}, l, "Yes", "No", true)
	sized(t, c.View(80, 24), 80, 24)
	contains(t, c.View(80, 24), "Item 00", "more (40 in all)")
	press(c, "down", "down", "down")
	lacks(t, c.View(80, 24), "Item 00")
	sized(t, c.View(64, 18), 64, 18)
}

// A long bullet wraps under its own text. Nothing is cut with an ellipsis.
func TestConfirmWrapsLongBullets(t *testing.T) {
	item := "Move the network configuration to systemd-networkd  (needed by: Configure the DNS resolver, Harden network stack settings)"
	for _, w := range []int{64, 80, 120} {
		c := NewConfirm("x", "Add the controls they need?", []string{"Some of the controls you ticked need these first."}, []string{item, "Another control"}, "Add them", "Skip", false)
		v := c.View(w, 24)
		sized(t, v, w, 24)
		text := plain(v)
		if strings.Contains(text, "…") {
			t.Fatalf("w=%d: a bullet was cut:\n%s", w, text)
		}
		// Every word of the bullet is on the screen, in order.
		flat := strings.Join(strings.Fields(strings.NewReplacer("│", " ", "•", " ").Replace(text)), " ")
		if !strings.Contains(flat, strings.Join(strings.Fields(item), " ")) {
			t.Fatalf("w=%d: the bullet is not whole:\n%s", w, text)
		}
		// The second line of the bullet lines up under the text, not the bullet.
		lines := strings.Split(text, "\n")
		for i, l := range lines {
			if strings.Contains(l, "• Move the network") && i+1 < len(lines) {
				col := func(s, sub string) int { return utf8.RuneCountInString(s[:strings.Index(s, sub)]) }
				next := lines[i+1]
				a := col(l, "Move")
				b := col(next, strings.Fields(strings.ReplaceAll(next, "│", " "))[0])
				if a != b {
					t.Fatalf("w=%d: continuation starts at %d, text at %d:\n%s", w, b, a, text)
				}
			}
		}
	}
}
