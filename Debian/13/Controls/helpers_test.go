// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Danang Galuh Tegar Prasetyo

package controls

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/danang-id/server-hardening/internal/control"
	"github.com/danang-id/server-hardening/internal/records"
)

// fakeRunner records commands and answers from canned output. A command in
// fail returns an error. hook can change the canned answers as commands run.
type fakeRunner struct {
	calls []string
	stdin map[string]string // stdin given to a command, by command line
	out   map[string]string
	fail  map[string]bool
	hook  func(f *fakeRunner, cmd string)
}

func (f *fakeRunner) Run(_ context.Context, name string, args ...string) ([]byte, error) {
	c := strings.TrimSpace(name + " " + strings.Join(args, " "))
	f.calls = append(f.calls, c)
	if f.hook != nil {
		f.hook(f, c)
	}
	if f.fail[c] {
		return []byte(f.out[c]), errors.New("failed: " + c)
	}
	return []byte(f.out[c]), nil
}

func (f *fakeRunner) RunStdin(ctx context.Context, stdin string, name string, args ...string) ([]byte, error) {
	if f.stdin == nil {
		f.stdin = map[string]string{}
	}
	f.stdin[strings.TrimSpace(name+" "+strings.Join(args, " "))] = stdin
	return f.Run(ctx, name, args...)
}

// did reports whether a command containing sub was run.
func (f *fakeRunner) did(sub string) bool {
	for _, c := range f.calls {
		if strings.Contains(c, sub) {
			return true
		}
	}
	return false
}

type nopLog struct{}

func (nopLog) Infof(string, ...any) {}
func (nopLog) Warnf(string, ...any) {}

// testEnv builds a small fake Debian 13 root in a temporary directory.
func testEnv(t *testing.T) (*control.Env, *fakeRunner) {
	t.Helper()
	root := t.TempDir()
	put := func(p, s string) {
		p = filepath.Join(root, p)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(s), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	put("etc/hostname", "debian\n")
	put("etc/hosts", "127.0.0.1\tlocalhost\n127.0.1.1\tdebian\n::1 localhost\n")
	put("etc/cloud/cloud.cfg.d/.keep", "")
	put("etc/os-release", "ID=debian\nVERSION_ID=\"13\"\nVERSION_CODENAME=trixie\n")
	put("etc/timezone", "Etc/UTC\n")
	put("usr/share/zoneinfo/Etc/UTC", "tz")
	put("usr/share/zoneinfo/Asia/Jakarta", "tz")
	put("etc/apt/sources.list", "deb http://old.example/debian trixie main\n# a comment\n")
	put("etc/apt/sources.list.d/debian.sources", "Types: deb\nURIs: http://old.example/debian\n")
	r := &fakeRunner{out: map[string]string{}, fail: map[string]bool{}}
	return &control.Env{Root: root, Run: r, Rec: records.New(filepath.Join(t.TempDir(), "rec")), Log: nopLog{}}, r
}

func read(t *testing.T, env *control.Env, p string) string {
	t.Helper()
	b, err := os.ReadFile(env.Path(p))
	if err != nil {
		return "<missing>"
	}
	return string(b)
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func state(t *testing.T, c control.Control, env *control.Env) control.State {
	t.Helper()
	st, err := c.Check(context.Background(), env)
	must(t, err)
	return st
}
