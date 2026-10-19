// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Danang Galuh Tegar Prasetyo

package controls

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/danang-id/server-hardening/internal/control"
)

func enforceControl() *apparmorEnforce {
	return &apparmorEnforce{control.Base{M: control.Meta{ID: enforceID}}}
}

// aaSim answers aa-status --json and switches modes for aa-enforce/aa-complain.
func aaSim(f *fakeRunner, modes map[string]string) {
	prev := f.hook
	f.hook = func(f *fakeRunner, cmd string) {
		if prev != nil {
			prev(f, cmd)
		}
		fields := strings.Fields(cmd)
		switch {
		case cmd == "aa-status --json":
			b, _ := json.Marshal(map[string]any{"version": "2", "profiles": modes})
			f.out[cmd] = string(b)
		case fields[0] == "aa-enforce":
			modes[fields[1]] = "enforce"
		case fields[0] == "aa-complain":
			modes[fields[1]] = "complain"
		}
	}
}

func TestEnforceListsAndEnforcesComplainProfiles(t *testing.T) {
	ctx := context.Background()
	env, run, _ := sysEnv(t)
	modes := map[string]string{"/usr/sbin/cupsd": "complain", "lsb_release": "enforce", "man_filter": "complain", "x": "unconfined"}
	aaSim(run, modes)
	c := enforceControl()
	if state(t, c, env) != control.NotApplied {
		t.Fatal("should start not applied")
	}
	in, err := c.Inputs(ctx, env)
	must(t, err)
	if len(in) != 1 || strings.Join(in[0].DefaultMulti, ",") != "/usr/sbin/cupsd,man_filter" {
		t.Fatalf("inputs: %+v", in)
	}
	must(t, c.Apply(ctx, env, control.Values{"profiles": {"man_filter"}}))
	if modes["man_filter"] != "enforce" || modes["/usr/sbin/cupsd"] != "complain" {
		t.Fatalf("modes: %v", modes)
	}
	if state(t, c, env) != control.Applied {
		t.Fatal("the chosen profile is enforced")
	}
	modes["man_filter"] = "complain"
	if state(t, c, env) != control.Partial {
		t.Fatal("a profile back in complain mode is partial")
	}
	modes["man_filter"] = "enforce"
	must(t, c.Revert(ctx, env))
	if modes["man_filter"] != "complain" || env.Rec.Has(enforceID) {
		t.Fatalf("revert: %v", modes)
	}
}

func TestEnforceRollsBackOnFailure(t *testing.T) {
	env, run, _ := sysEnv(t)
	modes := map[string]string{"a": "complain", "b": "complain"}
	aaSim(run, modes)
	run.fail["aa-enforce b"] = true
	err := enforceControl().Apply(context.Background(), env, control.Values{"profiles": {"a", "b"}})
	if err == nil {
		t.Fatal("expected an error")
	}
	if modes["a"] != "complain" {
		t.Fatal("profile a must be put back")
	}
}

func TestEnforceRefusesProfileNotInComplainMode(t *testing.T) {
	env, run, _ := sysEnv(t)
	modes := map[string]string{"a": "enforce"}
	aaSim(run, modes)
	if err := enforceControl().Apply(context.Background(), env, control.Values{"profiles": {"a"}}); err == nil {
		t.Fatal("expected an error")
	}
}

func TestEnforceNothingToDo(t *testing.T) {
	env, run, _ := sysEnv(t)
	aaSim(run, map[string]string{"a": "enforce"})
	c := enforceControl()
	in, _ := c.Inputs(context.Background(), env)
	if in != nil {
		t.Fatal("no complain profile, no question")
	}
	if state(t, c, env) != control.Applied {
		t.Fatal("nothing in complain mode is applied")
	}
}
