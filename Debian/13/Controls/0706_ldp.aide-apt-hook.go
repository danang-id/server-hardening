// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Danang Galuh Tegar Prasetyo

package controls

import (
	"context"

	"github.com/danang-id/server-hardening/internal/control"
	"github.com/danang-id/server-hardening/internal/files"
)

const (
	aideHookID   = "ldp.aide-apt-hook"
	aideHookFile = "/etc/apt/apt.conf.d/99-server-hardening-aide"
)

type aideAptHook struct{ control.Base }

func init() {
	System.Add(&aideAptHook{control.Base{M: control.Meta{
		ID:           aideHookID,
		Category:     control.LDP,
		Number:       6,
		Title:        "Keep the AIDE database in step with apt runs",
		Default:      true,
		Weight:       940,
		Requires:     []string{aideID},
		Tags:         []control.Tag{control.TagInput},
		RevertLimits: "The baseline stays as it was last updated.",
	}}})
}

func (a *aideAptHook) Inputs(context.Context, *control.Env) ([]control.Input, error) {
	return []control.Input{{
		Key: "before", Label: "Also check for differences before a package operation?", Kind: control.Choice, Default: "yes",
		Help: "The check makes sure tampering that happened earlier is logged, not silently accepted. Without it, apt runs take about half as long.",
		Options: []control.Option{
			{Value: "yes", Label: "Yes (recommended)"},
			{Value: "no", Label: "No, only update the baseline afterwards"},
		},
	}}, nil
}

// The hook only logs. "|| true" keeps a failure of AIDE from stopping apt.
func aideHookContent(before bool) string {
	s := "// " + managed(aideHookID)[2:] + "\n"
	if before {
		s += "DPkg::Pre-Invoke { \"" + aideRunPath + " pre || true\"; };\n"
	}
	s += "DPkg::Post-Invoke { \"" + aideRunPath + " update || true\"; };\n"
	return s
}

func (a *aideAptHook) Check(_ context.Context, env *control.Env) (control.State, error) {
	b, err := files.ReadOptional(env.Path(aideHookFile))
	if err != nil || len(b) == 0 {
		return control.NotApplied, err
	}
	if !files.Exists(env.Path(aideRunPath)) {
		return control.Partial, nil
	}
	return control.Applied, nil
}

func (a *aideAptHook) Apply(_ context.Context, env *control.Env, in control.Values) error {
	if !files.Exists(env.Path(aideRunPath)) {
		return errMissing(aideID, aideRunPath)
	}
	if err := env.Rec.Put(aideHookID, "before", in.String("before")); err != nil {
		return err
	}
	return putFile(env, aideHookID, aideHookFile, aideHookContent(in.String("before") != "no"), 0o644)
}

func (a *aideAptHook) Revert(_ context.Context, env *control.Env) error {
	if !env.Rec.Has(aideHookID) {
		env.Log.Warnf("%s: no record, leaving the apt configuration alone", aideHookID)
		return nil
	}
	if err := restoreFile(env, aideHookID, aideHookFile); err != nil {
		return err
	}
	return env.Rec.Delete(aideHookID)
}
