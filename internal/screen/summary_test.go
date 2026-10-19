// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Danang Galuh Tegar Prasetyo

package screen

import (
	"strings"
	"testing"
)

func TestSummaryShowsSkippedWithItsReasonWhole(t *testing.T) {
	d := SummaryData{
		System: "Debian 13",
		Done:   []string{"Set the hostname"},
		Skipped: []Row{
			{Title: "Move the network configuration to systemd-networkd", Reason: "you chose not to continue"},
			{Title: "Resolve names through systemd-resolved", Reason: "needs Move the network configuration to systemd-networkd, which did not run"},
		},
	}
	for _, w := range []int{64, 100} {
		v := NewSummary(d).View(w, 24)
		sized(t, v, w, 24)
		text := plain(v)
		if strings.Contains(text, "…") {
			t.Fatalf("w=%d: text was cut:\n%s", w, text)
		}
		flat := strings.Join(strings.Fields(strings.ReplaceAll(text, "│", " ")), " ")
		for _, want := range []string{"you chose not to continue", "which did not run", "Skipped"} {
			if !strings.Contains(flat, want) {
				t.Fatalf("w=%d: lost %q:\n%s", w, want, text)
			}
		}
	}
}

func TestRunShowsASkippedStep(t *testing.T) {
	r := sampleRun()
	r.Skip(1, "you chose not to continue")
	v := r.View(100, 30)
	contains(t, v, "you chose not to continue")
	if done, _ := r.counts(); done != 1 {
		t.Fatalf("a skipped step counts as done, got %d", done)
	}
}
