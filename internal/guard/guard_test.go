// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Danang Galuh Tegar Prasetyo

package guard

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type fake struct {
	calls []string
	fail  map[string]bool
}

func (f *fake) Run(_ context.Context, name string, args ...string) ([]byte, error) {
	c := name + " " + strings.Join(args, " ")
	f.calls = append(f.calls, c)
	if f.fail[c] {
		return nil, errors.New("failed")
	}
	return nil, nil
}
func (f *fake) RunStdin(ctx context.Context, _ string, name string, args ...string) ([]byte, error) {
	return f.Run(ctx, name, args...)
}

func setup(t *testing.T) (*Systemd, *fake) {
	t.Helper()
	dir := t.TempDir()
	exe := filepath.Join(t.TempDir(), "hardening-original")
	if err := os.WriteFile(exe, []byte("binary-bytes"), 0o755); err != nil {
		t.Fatal(err)
	}
	f := &fake{fail: map[string]bool{}}
	return &Systemd{Run: f, Dir: dir, Exe: exe}, f
}

func TestUnitName(t *testing.T) {
	if got := UnitName("remote-access.ssh-port"); got != "server-hardening-undo-remote-access-ssh-port" {
		t.Fatal(got)
	}
}

func TestArmCopiesTheBinaryAndStartsATimer(t *testing.T) {
	g, f := setup(t)
	disarm, err := g.Arm(context.Background(), "remote-access.ssh-key-only", 10*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(g.BinPath())
	if err != nil || string(b) != "binary-bytes" {
		t.Fatalf("copy of the binary: %q %v", b, err)
	}
	if fi, _ := os.Stat(g.BinPath()); fi.Mode().Perm() != 0o700 {
		t.Fatalf("mode %v", fi.Mode().Perm())
	}
	want := "systemd-run --unit=server-hardening-undo-remote-access-ssh-key-only --on-active=600s --collect " +
		"--description=Undo remote-access.ssh-key-only unless it is confirmed " + g.BinPath() + " --undo remote-access.ssh-key-only"
	found := false
	for _, c := range f.calls {
		if c == want {
			found = true
		}
	}
	if !found {
		t.Fatalf("calls: %q\nwant %q", f.calls, want)
	}

	f.calls = nil
	if err := disarm(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(f.calls) != 1 || f.calls[0] != "systemctl stop server-hardening-undo-remote-access-ssh-key-only.timer" {
		t.Fatalf("disarm calls: %q", f.calls)
	}
}

func TestArmStopsAnOldTimerFirst(t *testing.T) {
	g, f := setup(t)
	if _, err := g.Arm(context.Background(), "remote-access.ssh-port", time.Minute); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(f.calls[0], "systemctl stop server-hardening-undo-remote-access-ssh-port.timer") {
		t.Fatalf("calls: %q", f.calls)
	}
}

func TestArmFailsWhenTheTimerCannotStart(t *testing.T) {
	g, f := setup(t)
	f.fail["systemd-run --unit=server-hardening-undo-x-y --on-active=60s --collect --description=Undo x.y unless it is confirmed "+g.BinPath()+" --undo x.y"] = true
	if _, err := g.Arm(context.Background(), "x.y", time.Minute); err == nil {
		t.Fatal("must fail when systemd-run fails")
	}
}

func TestArmFailsWithoutTheBinary(t *testing.T) {
	g, _ := setup(t)
	g.Exe = filepath.Join(t.TempDir(), "missing")
	if _, err := g.Arm(context.Background(), "x.y", time.Minute); err == nil {
		t.Fatal("must fail when the binary cannot be copied")
	}
}

func TestDisarmReportsATimerThatAlreadyFired(t *testing.T) {
	g, f := setup(t)
	disarm, err := g.Arm(context.Background(), "x.y", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	f.fail["systemctl stop server-hardening-undo-x-y.timer"] = true
	if disarm(context.Background()) == nil {
		t.Fatal("a timer that is gone must be reported")
	}
}

func TestShortWindowIsRefused(t *testing.T) {
	g, _ := setup(t)
	if _, err := g.Arm(context.Background(), "x.y", 100*time.Millisecond); err == nil {
		t.Fatal("window under a second must be refused")
	}
}
