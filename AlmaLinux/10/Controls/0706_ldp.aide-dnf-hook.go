// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Danang Galuh Tegar Prasetyo

package controls

import (
	"context"

	"github.com/danang-id/server-hardening/internal/control"
	"github.com/danang-id/server-hardening/internal/dnf"
	"github.com/danang-id/server-hardening/internal/files"
)

const (
	aideHookID   = "ldp.aide-dnf-hook"
	aideHookFile = "/etc/dnf/plugins/post-transaction-actions.d/server-hardening-aide.action"
	// The plugin that runs commands after a dnf transaction.
	aideHookPlugin = "python3-dnf-plugin-post-transaction-actions"
)

type aideDnfHook struct{ control.Base }

func init() {
	System.Add(&aideDnfHook{control.Base{M: control.Meta{
		ID:           aideHookID,
		Category:     control.LDP,
		Number:       6,
		Title:        "Keep the AIDE database in step with dnf runs",
		Default:      true,
		Weight:       940,
		Requires:     []string{aideID},
		RevertLimits: "The baseline stays as it was last updated. The plugin package stays installed.",
	}}})
}

// The hook only updates the baseline. dnf 4 has no hook that runs before a
// transaction, so there is no check of the state before the change. The
// plugin runs a command once per transaction, and the script never fails dnf.
func aideHookContent() string {
	return managed(aideHookID) + "\n*:any:" + aideRunPath + " update\n"
}

func (a *aideDnfHook) Check(ctx context.Context, env *control.Env) (control.State, error) {
	if !hasMarker(env, aideHookFile, aideHookID) {
		return control.NotApplied, nil
	}
	if !files.Exists(env.Path(aideRunPath)) || !dnf.Installed(ctx, env, aideHookPlugin) {
		return control.Partial, nil
	}
	return control.Applied, nil
}

func (a *aideDnfHook) Apply(ctx context.Context, env *control.Env, _ control.Values) error {
	if !files.Exists(env.Path(aideRunPath)) {
		return errMissing(aideID, aideRunPath)
	}
	if err := dnf.Install(ctx, env, aideHookPlugin); err != nil {
		return err
	}
	if err := env.Rec.Put(aideHookID, "applied", "yes"); err != nil {
		return err
	}
	return putFile(env, aideHookID, aideHookFile, aideHookContent(), 0o644)
}

func (a *aideDnfHook) Revert(_ context.Context, env *control.Env) error {
	if !env.Rec.Has(aideHookID) {
		env.Log.Warnf("%s: no record, leaving the dnf configuration alone", aideHookID)
		return nil
	}
	if err := restoreFile(env, aideHookID, aideHookFile); err != nil {
		return err
	}
	return env.Rec.Delete(aideHookID)
}
