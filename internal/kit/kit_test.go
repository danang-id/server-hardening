// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Danang Galuh Tegar Prasetyo

package kit

import "testing"

const ini = "[commands]\nupgrade_type = default\n# apply_updates = no\napply_updates = no\n\n[emitters]\nemit_via = stdio,motd\n\n[base]\ndebuglevel = 1\n"

func TestSetINIReplacesInsideTheRightSection(t *testing.T) {
	got := SetINI(ini, "commands", "upgrade_type", "security")
	want := "[commands]\nupgrade_type = security\n# apply_updates = no\napply_updates = no\n\n[emitters]\nemit_via = stdio,motd\n\n[base]\ndebuglevel = 1\n"
	if got != want {
		t.Fatalf("got:\n%s", got)
	}
	// The same key in another section is not touched.
	got = SetINI("[a]\nx = 1\n[b]\nx = 2\n", "b", "x", "9")
	if got != "[a]\nx = 1\n[b]\nx = 9\n" {
		t.Fatalf("got:\n%s", got)
	}
}

func TestSetINIAddsAMissingKeyAtTheEndOfItsSection(t *testing.T) {
	got := SetINI(ini, "commands", "reboot", "when-needed")
	want := "[commands]\nupgrade_type = default\n# apply_updates = no\napply_updates = no\nreboot = when-needed\n\n[emitters]\nemit_via = stdio,motd\n\n[base]\ndebuglevel = 1\n"
	if got != want {
		t.Fatalf("got:\n%s", got)
	}
}

func TestSetINIAddsAMissingSectionAndKeepsDuplicatesQuiet(t *testing.T) {
	if got := SetINI("[a]\nx = 1\n", "b", "y", "2"); got != "[a]\nx = 1\n\n[b]\ny = 2\n" {
		t.Fatalf("got:\n%s", got)
	}
	if got := SetINI("", "b", "y", "2"); got != "[b]\ny = 2\n" {
		t.Fatalf("got:\n%s", got)
	}
	got := SetINI("[a]\nx = 1\nx = 2\n", "a", "x", "3")
	if got != "[a]\nx = 3\n# (replaced by server-hardening) x = 2\n" {
		t.Fatalf("got:\n%s", got)
	}
}

func TestGetINI(t *testing.T) {
	if v, ok := GetINI(ini, "commands", "apply_updates"); !ok || v != "no" {
		t.Fatalf("%q %v", v, ok)
	}
	if _, ok := GetINI(ini, "emitters", "apply_updates"); ok {
		t.Fatal("a key of another section must not be found")
	}
	if v, ok := GetINI(ini, "emitters", "emit_via"); !ok || v != "stdio,motd" {
		t.Fatalf("%q %v", v, ok)
	}
}
