// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Danang Galuh Tegar Prasetyo

package main

import (
	"context"
	"testing"
	"time"

	"github.com/danang-id/server-hardening/internal/control"
)

func TestUTF8Locale(t *testing.T) {
	env := func(m map[string]string) func(string) string { return func(k string) string { return m[k] } }
	for _, c := range []struct {
		env  map[string]string
		want bool
	}{
		{map[string]string{"LANG": "en_US.UTF-8"}, true},
		{map[string]string{"LANG": "C.utf8"}, true},
		{map[string]string{"LANG": "C"}, false},
		{map[string]string{}, false},
		// LC_ALL wins over LANG, as in the C library.
		{map[string]string{"LC_ALL": "C", "LANG": "en_US.UTF-8"}, false},
		{map[string]string{"LC_ALL": "en_US.UTF-8", "LANG": "C"}, true},
	} {
		if got := utf8Locale(env(c.env)); got != c.want {
			t.Errorf("%v: got %v want %v", c.env, got, c.want)
		}
	}
}

func TestDemoSystemIsUsable(t *testing.T) {
	for _, revert := range []bool{false, true} {
		sys, env, cleanup, _, err := demoSystem(revert)
		if err != nil {
			t.Fatal(err)
		}
		defer cleanup()
		env.Log = nopLog{}
		ctx := context.Background()
		applied := 0
		for _, c := range sys.Controls() {
			st, err := c.Check(ctx, env)
			if err != nil {
				t.Fatalf("%s: %v", c.Meta().ID, err)
			}
			if st == control.Applied {
				applied++
			}
			if _, err := c.Inputs(ctx, env); err != nil {
				t.Fatalf("%s: inputs: %v", c.Meta().ID, err)
			}
		}
		if revert && applied < 10 {
			t.Errorf("a revert demo needs controls to revert, has %d", applied)
		}
		if !revert && (applied == 0 || applied > 8) {
			t.Errorf("an apply demo starts with a few applied, has %d", applied)
		}
		if sys.Doc("baseline.hostname").What == "" {
			t.Error("the demo shows descriptions")
		}
	}
}

func TestDemoApplyAndRevertChangeState(t *testing.T) {
	sys, env, cleanup, _, err := demoSystem(false)
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	env.Log = nopLog{}
	c, _ := sys.Get("baseline.hostname")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := c.Apply(ctx, env, nil); err != nil {
		t.Fatal(err)
	}
	if st, _ := c.Check(ctx, env); st != control.Applied {
		t.Fatal("not applied")
	}
	if err := c.Revert(ctx, env); err != nil {
		t.Fatal(err)
	}
	if st, _ := c.Check(ctx, env); st != control.NotApplied {
		t.Fatal("not reverted")
	}
	swap, _ := sys.Get("misc.swapfile")
	if err := swap.Apply(ctx, env, nil); err == nil {
		t.Fatal("the demo shows one failure")
	}
}

type nopLog struct{}

func (nopLog) Infof(string, ...any) {}
func (nopLog) Warnf(string, ...any) {}
