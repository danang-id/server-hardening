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

	// An action: whatever dnf says about the (possibly stale) metadata, the
	// control is never reported as applied.
	run.out["dnf check-update"] = "Last metadata expiration check\n"
	if state(t, c, env) != control.NotApplied {
		t.Fatal("an upgrade is a job, never already applied")
	}
	if run.did("dnf") {
		t.Fatal("the check must not touch dnf")
	}

	must(t, c.Apply(ctx, env, nil))
	if len(run.calls) != 1 || run.calls[0] != "dnf -y upgrade --refresh" {
		t.Fatalf("calls: %v", run.calls)
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
