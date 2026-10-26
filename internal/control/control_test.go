// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Danang Galuh Tegar Prasetyo

package control

import "testing"

func TestInputShownFor(t *testing.T) {
	always := Input{Key: "a"}
	if !always.ShownFor(nil) {
		t.Fatal("an input without a condition is always asked")
	}
	in := Input{Key: "theme", OnlyIf: &OnlyIf{Key: "fw", Is: []string{"omz", "other"}}}
	for _, c := range []struct {
		v    Values
		want bool
	}{
		{Values{"fw": {"omz"}}, true},
		{Values{"fw": {"other"}}, true},
		{Values{"fw": {"none"}}, false},
		{Values{"fw": {"none", "omz"}}, true}, // a multiple choice: any one is enough
		{Values{"fw": nil}, false},
		{Values{}, false}, // the earlier question was not asked either
	} {
		if got := in.ShownFor(c.v); got != c.want {
			t.Fatalf("%v: got %v", c.v, got)
		}
	}
}
