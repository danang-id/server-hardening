// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Danang Galuh Tegar Prasetyo

package controls

import (
	"context"
	"testing"

	"github.com/danang-id/server-hardening/internal/control"
)

func debsumsControl() *debsumsBaseline {
	return &debsumsBaseline{control.Base{M: control.Meta{ID: debsumsID}}}
}

func TestDebsumsInstallsAndRecordsBaseline(t *testing.T) {
	ctx := context.Background()
	env, run, s := sysEnv(t)
	run.out["debsums -c"] = "/usr/bin/ls\n/usr/sbin/sshd\n"
	run.fail["debsums -c"] = true // debsums exits with an error when files differ
	c := debsumsControl()
	if state(t, c, env) != control.NotApplied {
		t.Fatal("should start not applied")
	}
	must(t, c.Apply(ctx, env, nil))
	if !s.installed["debsums"] {
		t.Fatal("debsums should be installed")
	}
	got, _, _ := env.Rec.Get(debsumsID, "changed")
	if got != "/usr/bin/ls\n/usr/sbin/sshd" {
		t.Fatalf("baseline: %q", got)
	}
	if state(t, c, env) != control.Partial {
		t.Fatal("changed files make it partial")
	}
	if err := c.Revert(ctx, env); err != control.ErrNoRevert {
		t.Fatalf("want ErrNoRevert, got %v", err)
	}
}

func TestDebsumsCleanSystem(t *testing.T) {
	env, _, _ := sysEnv(t)
	c := debsumsControl()
	must(t, c.Apply(context.Background(), env, nil))
	if state(t, c, env) != control.Applied {
		t.Fatal("no changed file is applied")
	}
}

func TestDebsumsFailureWithoutOutputIsAnError(t *testing.T) {
	env, run, _ := sysEnv(t)
	run.fail["debsums -c"] = true
	if err := debsumsControl().Apply(context.Background(), env, nil); err == nil {
		t.Fatal("a failing debsums with no output is an error")
	}
	if env.Rec.Has(debsumsID) {
		t.Fatal("nothing may be recorded after a failure")
	}
}
