// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Danang Galuh Tegar Prasetyo

package registry

import "testing"

func TestParseReference(t *testing.T) {
	md := "# Title\r\n\r\n### not.a.control-before-heading\r\n\r\n### a.b\r\n\r\n| | |\r\n\r\n" +
		"**What it does.** Moves `sshd`  to a **new** port, see [the guide](x.md).\r\n\r\n" +
		"**Why.** Less noise.\r\n\r\n**What it changes.** Files.\r\n\r\n### c.d\r\n\r\n**Why.** Only why.\r\n"
	got := ParseReference(md)
	if d := got["a.b"]; d.What != "Moves sshd to a new port, see the guide." || d.Why != "Less noise." {
		t.Fatalf("a.b = %+v", d)
	}
	if d := got["c.d"]; d.What != "" || d.Why != "Only why." {
		t.Fatalf("c.d = %+v", d)
	}
	if _, ok := got["x"]; ok {
		t.Fatal("unexpected entry")
	}
}

func TestSystemDoc(t *testing.T) {
	s := &System{Reference: "### a.b\n\n**What it does.** Does it.\n"}
	if s.Doc("a.b").What != "Does it." || s.Doc("zz").What != "" {
		t.Fatal("Doc lookup is wrong")
	}
}
