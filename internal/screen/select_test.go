// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Danang Galuh Tegar Prasetyo

package screen

import (
	"strings"
	"testing"
	"time"
)

func TestSelectLayoutAtCommonSizes(t *testing.T) {
	for _, sz := range [][2]int{{80, 24}, {100, 30}, {64, 18}, {140, 50}} {
		s := NewSelect("Debian 13 (trixie)", false, sampleGroups())
		v := s.View(sz[0], sz[1])
		sized(t, v, sz[0], sz[1])
		contains(t, v, "server-hardening", "Debian 13 (trixie)", "Categories", "Remote access", "Set the hostname", "4 controls selected")
	}
}

func TestSelectShowsDetailOfTheRowUnderTheCursor(t *testing.T) {
	s := NewSelect("Debian 13", false, sampleGroups())
	press(s, "right", "down")
	v := s.View(80, 24)
	contains(t, v, "Disable password login over SSH", "remote-access.ssh-key-only", "can lock you out", "Does the thing for", "03 Remote access")
}

func TestSelectTickAndCounts(t *testing.T) {
	s := NewSelect("Debian 13", false, sampleGroups())
	if s.Count() != 4 {
		t.Fatalf("recommended ticks: %d", s.Count())
	}
	press(s, " ") // untick hostname
	if s.Count() != 3 {
		t.Fatalf("after untick: %d", s.Count())
	}
	press(s, "right") // category 3
	press(s, "a")     // 2 of 3 ticked -> all
	if g := s.Groups[1]; func() bool { _, tot := g.tickable(); tk, _ := g.tickable(); return tk != tot }() {
		t.Fatal("a should tick all")
	}
	press(s, "a")
	if tk, _ := s.Groups[1].tickable(); tk != 0 {
		t.Fatal("a again should clear")
	}
	press(s, "r")
	if s.Count() != 4 {
		t.Fatalf("reset: %d", s.Count())
	}
	press(s, "n")
	if s.Count() != 0 {
		t.Fatal("n should clear")
	}
}

func TestSelectAppliedRowCannotBeTicked(t *testing.T) {
	s := NewSelect("x", false, sampleGroups())
	press(s, "down", " ")
	if s.Groups[0].Items[1].Ticked {
		t.Fatal("applied row ticked")
	}
	v := s.View(80, 24)
	contains(t, v, "Already applied")
}

func TestSelectMovesAcrossCategories(t *testing.T) {
	s := NewSelect("x", false, sampleGroups())
	press(s, "down", "down", "down")
	if s.cat != 1 || s.row != 0 {
		t.Fatalf("down past the end: cat %d row %d", s.cat, s.row)
	}
	press(s, "up")
	if s.cat != 0 || s.row != 2 {
		t.Fatalf("up past the start: cat %d row %d", s.cat, s.row)
	}
	press(s, "tab", "tab", "tab")
	if s.cat != 0 {
		t.Fatalf("tab wraps: %d", s.cat)
	}
}

func TestSelectNotApplicableCategory(t *testing.T) {
	s := NewSelect("x", false, sampleGroups())
	press(s, "right", "right")
	v := s.View(80, 24)
	contains(t, v, "Not applicable", "AppArmor is not part")
	press(s, " ", "a") // nothing to tick, no panic
}

func TestSelectEnterNeedsATick(t *testing.T) {
	s := NewSelect("x", false, sampleGroups())
	press(s, "n")
	if ev := press(s, "enter"); ev != None {
		t.Fatal("enter with nothing ticked must not continue")
	}
	contains(t, s.View(80, 24), "Tick at least one")
	s.Tick(time.Now().Add(time.Hour))
	s.Tick(time.Now().Add(2 * time.Hour))
	lacks(t, s.View(80, 24), "Tick at least one")
	press(s, " ")
	if ev := press(s, "enter"); ev != Done {
		t.Fatal("enter should finish")
	}
	if got := strings.Join(s.Selected(), ","); got != "baseline.hostname" {
		t.Fatalf("selected %q", got)
	}
}

func TestSelectQuitAndHelp(t *testing.T) {
	s := NewSelect("x", false, sampleGroups())
	press(s, "?")
	v := s.View(80, 24)
	sized(t, v, 80, 24)
	contains(t, v, "Help", "Symbols", "can lock you out")
	if ev := press(s, "q"); ev != None { // closes help only
		t.Fatal("any key closes help")
	}
	if ev := press(s, "q"); ev != Quit {
		t.Fatal("q quits")
	}
	if ev := NewSelect("x", false, sampleGroups()).Key("ctrl+c"); ev != Quit {
		t.Fatal("ctrl+c quits")
	}
}

func TestSelectScrollsALongList(t *testing.T) {
	var items []*Item
	for i := 0; i < 30; i++ {
		items = append(items, &Item{ID: "a.b", Title: "Control " + two(i)})
	}
	s := NewSelect("x", false, []*Group{{Num: 3, Name: "Remote Access", Items: items}})
	for i := 0; i < 25; i++ {
		press(s, "down")
	}
	v := s.View(80, 20)
	sized(t, v, 80, 20)
	contains(t, v, "Control 25")
	lacks(t, v, "Control 00")
}

func TestTooSmall(t *testing.T) {
	v := TooSmall(40, 10)
	sized(t, v, 40, 10)
	contains(t, v, "too small")
}
