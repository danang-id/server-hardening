// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Danang Galuh Tegar Prasetyo

package controls

import (
	"context"
	"testing"

	"github.com/danang-id/server-hardening/internal/control"
)

func epelControl() *epel { return &epel{control.Base{M: control.Meta{ID: epelID}}} }

func TestEPELRoundTrip(t *testing.T) {
	ctx := context.Background()
	env, run := testEnv(t)
	must(t, writeTestFile(env, crbRepo, "[crb]\nname=CRB\nenabled=0\n"))
	run.fail["rpm -q --quiet epel-release"] = true // not installed yet
	c := epelControl()

	must(t, c.Apply(ctx, env, control.Values{"crb": {"yes"}}))
	for _, want := range []string{"dnf -y install epel-release", "crb enable", "dnf -y makecache"} {
		if !run.did(want) {
			t.Errorf("missing command %q in %v", want, run.calls)
		}
	}
	// The package and the crb script would now have changed the files.
	must(t, writeTestFile(env, epelRepo, "[epel]\nname=EPEL\nenabled=1\n"))
	if state(t, c, env) != control.Partial {
		t.Fatal("CRB is still off, so the control is only partly applied")
	}
	must(t, writeTestFile(env, crbRepo, "[crb]\nname=CRB\nenabled=1\n"))
	if state(t, c, env) != control.Applied {
		t.Fatal("not applied")
	}

	must(t, c.Revert(ctx, env))
	if !run.did("crb disable") || !run.did("dnf -y remove epel-release") {
		t.Fatalf("revert calls: %v", run.calls)
	}
	if env.Rec.Has(epelID) {
		t.Fatal("record should be deleted")
	}
}

func TestEPELRevertKeepsWhatWasThereBefore(t *testing.T) {
	ctx := context.Background()
	env, run := testEnv(t) // rpm -q succeeds: epel-release is already installed
	must(t, writeTestFile(env, crbRepo, "[crb]\nenabled=1\n"))
	c := epelControl()
	must(t, c.Apply(ctx, env, control.Values{"crb": {"yes"}}))
	must(t, c.Revert(ctx, env))
	if run.did("crb disable") || run.did("remove epel-release") {
		t.Fatalf("revert must leave what was there before: %v", run.calls)
	}
}

func TestEPELWithoutCRB(t *testing.T) {
	env, run := testEnv(t)
	must(t, epelControl().Apply(context.Background(), env, control.Values{"crb": {"no"}}))
	if run.did("crb enable") {
		t.Fatal("CRB was not asked for")
	}
}
