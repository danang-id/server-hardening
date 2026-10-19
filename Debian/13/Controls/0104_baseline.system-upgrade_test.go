// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Danang Galuh Tegar Prasetyo

package controls

import (
	"context"
	"errors"
	"testing"

	"github.com/danang-id/server-hardening/internal/control"
)

func TestSystemUpgrade(t *testing.T) {
	ctx := context.Background()
	env, run := testEnv(t)
	c := &systemUpgrade{control.Base{M: control.Meta{ID: upgradeID}}}

	// An action: whatever apt says about the (possibly stale) lists, the
	// control is never reported as applied.
	run.out["apt-get -s full-upgrade"] = "Reading package lists...\n"
	if state(t, c, env) != control.NotApplied {
		t.Fatal("an upgrade is a job, never already applied")
	}
	if run.did("apt-get") {
		t.Fatal("the check must not touch apt")
	}

	must(t, c.Apply(ctx, env, nil))
	if len(run.calls) < 2 || run.calls[len(run.calls)-2] != "apt-get update" || !run.did("full-upgrade") {
		t.Fatalf("calls: %v", run.calls)
	}
	if !run.did("DEBIAN_FRONTEND=noninteractive") || !run.did("--force-confold") {
		t.Fatal("upgrade must be non-interactive and keep existing configuration")
	}
	if err := c.Revert(ctx, env); !errors.Is(err, control.ErrNoRevert) {
		t.Fatalf("revert: %v", err)
	}
}

func TestSystemUpgradeIsAnAction(t *testing.T) {
	c, ok := System.Get(upgradeID)
	if !ok || !c.Meta().Action {
		t.Fatal("system-upgrade must be an action")
	}
}
