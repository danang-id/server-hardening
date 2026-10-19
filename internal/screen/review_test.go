// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Danang Galuh Tegar Prasetyo

package screen

import (
	"testing"

	"github.com/danang-id/server-hardening/internal/control"
)

func sampleReview(revert bool) *Review {
	return NewReview("Debian 13", revert, []ReviewItem{
		{Title: "Set the hostname", Values: []string{"Host name: web-01"}},
		{Title: "Install zsh", Added: true},
		{Title: "Move SSH to another port", Tags: []control.Tag{control.TagLockout}, Values: []string{"New port: 2222"}},
		{Title: "Upgrade all installed packages", Tags: []control.Tag{control.TagReboot, control.TagIrreversible}},
	}, 10)
}

func TestReviewShowsOrderValuesAndNotices(t *testing.T) {
	r := sampleReview(false)
	v := r.View(80, 24)
	sized(t, v, 80, 24)
	contains(t, v, "Ready to apply 4 controls", "1 added because others need them", "Run order",
		" 1  Set the hostname", "Host name: web-01", "needed too", "New port: 2222",
		"1 control can lock you out", "after 10 minutes", "1 control cannot be undone", "A reboot is needed", "Apply", "Edit selection")
}

func TestReviewRevertWording(t *testing.T) {
	v := sampleReview(true).View(80, 24)
	contains(t, v, "Ready to revert 4 controls", "Revert")
	lacks(t, v, "lock you out", "reboot")
}

func TestReviewKeys(t *testing.T) {
	r := sampleReview(false)
	if press(r, "enter") != Done || !r.Result {
		t.Fatal("enter applies")
	}
	r = sampleReview(false)
	press(r, "right")
	if press(r, "enter") != Done || r.Result {
		t.Fatal("enter on edit goes back")
	}
	r = sampleReview(false)
	if press(r, "e") != Done || r.Result {
		t.Fatal("e edits")
	}
	if press(sampleReview(false), "q") != Quit {
		t.Fatal("q quits")
	}
}

func TestReviewChangeAnswers(t *testing.T) {
	r := sampleReview(false)
	contains(t, r.View(80, 24), "Change answers")
	press(r, "right")
	press(r, "right")
	if press(r, "enter") != Done || r.Result || !r.ChangeAnswers {
		t.Fatal("third button changes the answers")
	}
	r = sampleReview(false)
	if press(r, "c") != Done || !r.ChangeAnswers {
		t.Fatal("c changes the answers")
	}
	r = sampleReview(false)
	press(r, "e")
	if r.ChangeAnswers {
		t.Fatal("e only edits the selection")
	}
	// Nothing was asked: no such button, no such key, and the buttons wrap after two.
	r = NewReview("Debian 13", false, []ReviewItem{{Title: "Install zsh"}}, 10)
	lacks(t, r.View(80, 24), "Change answers")
	if press(r, "c") == Done {
		t.Fatal("c does nothing without answers")
	}
	press(r, "right")
	press(r, "right")
	if press(r, "enter") != Done || !r.Result {
		t.Fatal("two buttons wrap back to apply")
	}
}

func TestReviewScrollsWhenLong(t *testing.T) {
	var items []ReviewItem
	for i := 0; i < 50; i++ {
		items = append(items, ReviewItem{Title: "Control " + two(i), Values: []string{"a: b"}})
	}
	r := NewReview("x", false, items, 10)
	v := r.View(80, 24)
	sized(t, v, 80, 24)
	contains(t, v, "Control 00", "Edit selection", "enter apply")
	for i := 0; i < 30; i++ {
		press(r, "down")
	}
	v = r.View(80, 24)
	lacks(t, v, "Control 00")
	contains(t, v, "Edit selection")
	sized(t, v, 80, 24)
	sized(t, r.View(64, 18), 64, 18)
	contains(t, r.View(64, 18), "Edit selection")
	sized(t, r.View(140, 50), 140, 50)
}
