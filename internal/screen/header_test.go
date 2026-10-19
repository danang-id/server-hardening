// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Danang Galuh Tegar Prasetyo

package screen

import (
	"strings"
	"testing"
)

func hl(ls []Line) string { return plain(ls) }

func TestHeaderShowsHostAndSeparators(t *testing.T) {
	got := hl(header(80, "Debian 13 (trixie)", "web-01", L("39 controls selected")))
	for _, want := range []string{"server-hardening │ Debian 13 (trixie)", "39 controls selected │ web-01"} {
		if !strings.Contains(got, want) {
			t.Fatalf("header lacks %q:\n%q", want, got)
		}
	}
	if strings.Contains(got, "·") {
		t.Fatalf("header still uses a middle dot: %q", got)
	}
}

func TestHeaderWithoutRightSideStillShowsHost(t *testing.T) {
	got := hl(header(80, "Debian 13", "web-01", L("")))
	if !strings.HasSuffix(strings.TrimRight(got, " "), "web-01") || strings.Contains(got, "│ │") {
		t.Fatalf("header = %q", got)
	}
}

func TestHeaderUsesTwoRowsWhenNarrow(t *testing.T) {
	right := L("39 controls selected")
	for _, c := range []struct {
		w, rows int
	}{
		{120, 1},
		{90, 1},
		{72, 2},
		{64, 2},
	} {
		head := header(c.w, "Debian 13 (trixie)", "a-long-host.example.com", right)
		if len(head) != c.rows {
			t.Fatalf("w=%d: %d rows, want %d:\n%s", c.w, len(head), c.rows, plain(head))
		}
		for _, l := range head {
			if l.Width() > c.w {
				t.Fatalf("w=%d: row too wide: %q", c.w, l.Plain())
			}
		}
		got := plain(head)
		for _, want := range []string{"Debian 13 (trixie)", "a-long-host.example.com", "39 controls selected"} {
			if !strings.Contains(got, want) {
				t.Errorf("w=%d: lost %q:\n%s", c.w, want, got)
			}
		}
	}
}

func TestNarrowHeaderKeepsRoomForTheBody(t *testing.T) {
	head := header(64, "Debian 13 (trixie)", "a-long-host.example.com", L("39 controls selected"))
	v := page(64, 18, head, []Line{L("body")}, L("foot"))
	sized(t, v, 64, 18)
	if !strings.Contains(v[3].Plain(), "body") || strings.TrimSpace(v[2].Plain()) != "" {
		t.Fatalf("layout:\n%s", plain(v))
	}
}

func TestPageLeavesAGapUnderTheHeader(t *testing.T) {
	v := page(70, 20, []Line{L("head")}, []Line{L("body")}, L("foot"))
	if len(v) != 20 || v[0].Plain() == "" || strings.TrimSpace(v[1].Plain()) != "" || !strings.Contains(v[2].Plain(), "body") {
		t.Fatalf("page layout: %q / %q / %q", v[0].Plain(), v[1].Plain(), v[2].Plain())
	}
}

func TestHostFollowsSetHost(t *testing.T) {
	s := NewSelect("Debian 13", false, []*Group{{Num: 1, Name: "Baseline", Items: []*Item{{ID: "a", Title: "A"}}}})
	s.SetHost("web-01")
	out := plain(s.View(80, 24))
	if !strings.Contains(out, "web-01") {
		t.Fatalf("no host in view:\n%s", out)
	}
	s.SetHost("db-02")
	out = plain(s.View(80, 24))
	if strings.Contains(out, "web-01") || !strings.Contains(out, "db-02") {
		t.Fatalf("host did not change:\n%s", out)
	}
}
