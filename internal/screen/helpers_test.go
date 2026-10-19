// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Danang Galuh Tegar Prasetyo

package screen

import (
	"strings"
	"testing"

	"github.com/charmbracelet/x/ansi"
	"github.com/danang-id/server-hardening/internal/control"
)

// plain turns a view into text.
func plain(ls []Line) string {
	var b strings.Builder
	for i, l := range ls {
		if i > 0 {
			b.WriteByte('\n')
		}
		b.WriteString(l.Plain())
	}
	return b.String()
}

// sized fails the test when a view is not exactly w x h cells.
func sized(t *testing.T, ls []Line, w, h int) {
	t.Helper()
	if len(ls) != h {
		t.Fatalf("view has %d lines, want %d\n%s", len(ls), h, plain(ls))
	}
	for i, l := range ls {
		if got := l.Width(); got != w {
			t.Fatalf("line %d is %d cells wide, want %d: %q", i, got, w, l.Plain())
		}
	}
}

// press sends keys to a screen and returns the last event.
func press(s Screen, keys ...string) Event {
	var ev Event
	for _, k := range keys {
		ev = s.Key(k)
	}
	return ev
}

// typed sends a string as one key per character.
func typed(s Screen, text string) {
	for _, r := range text {
		s.Key(string(r))
	}
}

func contains(t *testing.T, ls []Line, want ...string) {
	t.Helper()
	p := plain(ls)
	for _, w := range want {
		if !strings.Contains(p, w) {
			t.Errorf("view lacks %q:\n%s", w, p)
		}
	}
}

func lacks(t *testing.T, ls []Line, bad ...string) {
	t.Helper()
	p := plain(ls)
	for _, w := range bad {
		if strings.Contains(p, w) {
			t.Errorf("view has %q:\n%s", w, p)
		}
	}
}

var _ = ansi.StringWidth

func sampleGroups() []*Group {
	mk := func(id, title string, def bool, tags ...control.Tag) *Item {
		return &Item{ID: id, Title: title, Tags: tags, Recommended: def, Ticked: def,
			What: "Does the thing for " + title + ".", Why: "It lowers a risk."}
	}
	applied := mk("baseline.timezone", "Set the time zone", false)
	applied.Done, applied.Disabled, applied.Ticked = true, "already applied", false
	return []*Group{
		{Num: 1, Name: "Operating System Baseline", Items: []*Item{
			mk("baseline.hostname", "Set the hostname", true, control.TagInput),
			applied,
			mk("baseline.system-upgrade", "Upgrade all installed packages", true, control.TagReboot, control.TagIrreversible),
		}},
		{Num: 3, Name: "Remote Access", Items: []*Item{
			mk("remote-access.ssh-port", "Move SSH to another port", false, control.TagLockout, control.TagInput),
			mk("remote-access.ssh-key-only", "Disable password login over SSH", true, control.TagLockout),
			mk("remote-access.sftp", "Enable SFTP (and therefore `scp`)", true),
		}},
		{Num: 6, Name: "Mandatory Access Control (MAC)", NA: "AppArmor is not part of this system."},
	}
}
