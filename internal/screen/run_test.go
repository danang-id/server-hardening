// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Danang Galuh Tegar Prasetyo

package screen

import (
	"testing"
	"time"
)

var t0 = time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC)

func sampleRun() *Run {
	r := NewRun("Debian 13", false, []string{"Set the hostname", "Move SSH to another port", "Enable SFTP"}, t0)
	r.Tick(t0.Add(42 * time.Second))
	return r
}

func TestRunShowsStepsAndLog(t *testing.T) {
	r := sampleRun()
	r.Start(0)
	r.Log(false, "Step 1 / 3: Set the hostname")
	r.Finish(0, true, "")
	r.Start(1)
	r.Log(true, "something odd")
	v := r.View(80, 24)
	sized(t, v, 80, 24)
	contains(t, v, "Applying", "✔ Set the hostname", "Move SSH to another port", "· Enable SFTP", "1 / 3", "00:42",
		"Log", "Step 1 / 3: Set the hostname", "! something odd", "ctrl+c stop")
	r.Finish(1, false, "port in use")
	contains(t, r.View(80, 24), "✖ Move SSH to another port  port in use", "2 / 3")
}

func TestRunLockoutPrompt(t *testing.T) {
	r := sampleRun()
	r.Start(1)
	r.AskLockout("Move SSH to another port", 10*time.Minute)
	if !r.Asking() {
		t.Fatal("asking")
	}
	v := r.View(80, 24)
	sized(t, v, 80, 24)
	contains(t, v, "Check your access", "NEW terminal", "Move SSH to another port", "Automatic undo in 10:00", "Yes, it works", "No, undo it")
	r.Tick(t0.Add(42*time.Second + 9*time.Minute + 30*time.Second))
	contains(t, r.View(80, 24), "Automatic undo in 00:30")
	r.Tick(t0.Add(time.Hour))
	contains(t, r.View(80, 24), "The automatic undo is running")
	if ev := press(r, "y"); ev != Done || !r.Result || r.Asking() {
		t.Fatalf("y: ev %v result %v", ev, r.Result)
	}
	r.AskLockout("x", time.Minute)
	if ev := press(r, "enter"); ev != Done || r.Result {
		t.Fatal("enter alone must not confirm: the cursor starts on No")
	}
	r.AskLockout("x", time.Minute)
	if ev := press(r, "right", "enter"); ev != Done || !r.Result {
		t.Fatal("enter on Yes after moving")
	}
	r.AskLockout("x", time.Minute)
	if ev := press(r, "ctrl+c"); ev != Quit {
		t.Fatal("ctrl+c leaves the question unanswered")
	}
}

func TestRunWarnPrompt(t *testing.T) {
	r := sampleRun()
	r.AskWarn("Move the network to systemd-networkd")
	contains(t, r.View(80, 24), "This cannot be undone", "provider's web console", "Continue", "Skip this one", "rest of the run goes on")
	if ev := press(r, "n"); ev != Done || r.Result {
		t.Fatal("n skips")
	}
}

func TestRunCtrlCAsksBeforeStopping(t *testing.T) {
	r := sampleRun()
	if ev := press(r, "ctrl+c"); ev != None {
		t.Fatal("first ctrl+c only asks")
	}
	contains(t, r.View(80, 24), "Stop now?", "Keep going")
	if ev := press(r, "esc"); ev != None || r.p != nil {
		t.Fatal("esc keeps going")
	}
	press(r, "ctrl+c")
	if ev := press(r, "y"); ev != Quit {
		t.Fatal("y stops")
	}
}

func TestRunManyStepsWindowFollowsTheCurrentOne(t *testing.T) {
	var titles []string
	for i := 0; i < 40; i++ {
		titles = append(titles, "Control "+two(i))
	}
	r := NewRun("x", true, titles, t0)
	for i := 0; i < 30; i++ {
		r.Start(i)
		r.Finish(i, true, "")
	}
	r.Start(30)
	v := r.View(80, 24)
	sized(t, v, 80, 24)
	contains(t, v, "Reverting", "Control 30")
	lacks(t, v, "Control 00")
	sized(t, r.View(64, 18), 64, 18)
	for i := 0; i < 1000; i++ {
		r.Log(false, "line")
	}
	if len(r.logs) > 500 {
		t.Fatal("log is capped")
	}
}

func TestSummaryViews(t *testing.T) {
	s := NewSummary(SummaryData{System: "Debian 13", Done: []string{"Set the hostname", "Install zsh"},
		Added: []string{"Install zsh"}, Skipped: []Row{{"Install a firewall", "already applied"}},
		Failed: []Row{{"Move SSH to another port", "port 2222 is in use by another service"}},
		Reboot: true, Elapsed: "1m12s", LogFile: "/var/log/server-hardening.log"})
	v := s.View(80, 24)
	sized(t, v, 80, 24)
	contains(t, v, "Applied 2, 1 failed.", "needed too", "Skipped", "already applied", "port 2222 is in use", "Reboot to finish", "Took 1m12s", "/var/log/server-hardening.log")
	if press(s, "enter") != Done {
		t.Fatal("enter exits")
	}
	d := NewSummary(SummaryData{System: "x", Dry: true, Done: []string{"a"}}).View(80, 24)
	contains(t, d, "Dry run: 1 control would run. Nothing was changed.")
	lacks(t, d, "Reboot")
	contains(t, NewSummary(SummaryData{System: "x", Revert: true, Done: []string{"a", "b"}}).View(80, 24), "Reverted 2 controls.")
	contains(t, NewSummary(SummaryData{System: "x", Failed: []Row{{"a", "b"}}}).View(80, 24), "Nothing was applied.")
	contains(t, NewSummary(SummaryData{System: "x"}).View(80, 24), "Nothing to do.")
	sized(t, NewSummary(SummaryData{System: "x", Done: []string{"a"}}).View(64, 18), 64, 18)
}

func TestBusy(t *testing.T) {
	b := &Busy{System: "Debian 13", Msg: "Checking this system…", Last: "baseline.hostname: check failed"}
	b.Tick(t0)
	v := b.View(80, 24)
	sized(t, v, 80, 24)
	contains(t, v, "Checking this system", "check failed")
	if b.Key("ctrl+c") != Quit {
		t.Fatal("ctrl+c")
	}
}

func TestThemeRender(t *testing.T) {
	l := []Line{Cat(L("a", Accent, Bold), L("b"), L("c", Dim, Sel))}
	got := Theme{Color256}.Render(l)
	want := "\x1b[1;38;5;80ma\x1b[0mb\x1b[38;5;245;48;5;237mc\x1b[0m"
	if got != want {
		t.Fatalf("got %q want %q", got, want)
	}
	if got := (Theme{ColorNone}).Render(l); got != "\x1b[1ma\x1b[0mb\x1b[7mc\x1b[0m" {
		t.Fatalf("none: %q", got)
	}
	env := func(m map[string]string) func(string) string { return func(k string) string { return m[k] } }
	for _, c := range []struct {
		env  map[string]string
		want ColorMode
	}{
		{map[string]string{"TERM": "xterm-256color"}, Color256},
		{map[string]string{"TERM": "xterm-256color", "NO_COLOR": "1"}, ColorNone},
		{map[string]string{"TERM": "dumb"}, ColorNone},
		{map[string]string{}, ColorNone},
		{map[string]string{"TERM": "linux"}, Color16},
		{map[string]string{"TERM": "screen", "COLORTERM": "truecolor"}, Color256},
	} {
		if got := DetectTheme(env(c.env)).Mode; got != c.want {
			t.Errorf("%v: got %v want %v", c.env, got, c.want)
		}
	}
}

func TestLineCutAndFit(t *testing.T) {
	l := Cat(L("hello "), L("wörld", Dim))
	if got := l.Cut(8).Plain(); got != "hello w…" {
		t.Fatalf("cut: %q", got)
	}
	if got := l.Fit(14); got.Width() != 14 {
		t.Fatalf("fit: %d", got.Width())
	}
	wide := L("🔒🔒🔒")
	if wide.Width() != 6 || wide.Cut(4).Width() > 4 {
		t.Fatalf("wide: %d %d", wide.Width(), wide.Cut(4).Width())
	}
	if got := Wrap("one two three four", 9); len(got) != 3 || got[0] != "one two" || got[1] != "three" || got[2] != "four" {
		t.Fatalf("wrap: %q", got)
	}
}
