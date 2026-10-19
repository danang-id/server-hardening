// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Danang Galuh Tegar Prasetyo

package controls

import (
	"context"

	"github.com/danang-id/server-hardening/internal/apt"
	"github.com/danang-id/server-hardening/internal/control"
)

const upgradeID = "baseline.system-upgrade"

type systemUpgrade struct{ control.Base }

func init() {
	System.Add(&systemUpgrade{control.Base{M: control.Meta{
		ID:             upgradeID,
		Category:       control.Baseline,
		Number:         4,
		Title:          "Upgrade all installed packages",
		Default:        true,
		Action:         true,
		Tags:           []control.Tag{control.TagReboot, control.TagIrreversible},
		NoRevertReason: "Downgrading packages is not safe, so upgrades are never undone.",
	}}})
}

// Check is never asked: this control is an action (see control.Meta.Action),
// so it is always offered. The package lists on a new image are old, which
// makes "nothing to upgrade" from them meaningless until apt update has run.
func (u *systemUpgrade) Check(context.Context, *control.Env) (control.State, error) {
	return control.NotApplied, nil
}

// Apply refreshes the package lists, then installs every update. full-upgrade
// is the same as dist-upgrade: it may add or remove packages when a new
// version needs it, which a plain upgrade would hold back.
func (u *systemUpgrade) Apply(ctx context.Context, env *control.Env, _ control.Values) error {
	if err := apt.Update(ctx, env); err != nil {
		return err
	}
	env.Log.Infof("upgrading installed packages, this can take a few minutes")
	return apt.FullUpgrade(ctx, env)
}

func (u *systemUpgrade) Revert(context.Context, *control.Env) error { return control.ErrNoRevert }
