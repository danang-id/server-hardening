// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Danang Galuh Tegar Prasetyo

package controls

import (
	"context"

	"github.com/danang-id/server-hardening/internal/control"
	"github.com/danang-id/server-hardening/internal/dnf"
	"github.com/danang-id/server-hardening/internal/files"
	"github.com/danang-id/server-hardening/internal/kit"
)

const (
	epelID      = "baseline.epel"
	epelPackage = "epel-release"
	epelRepo    = "/etc/yum.repos.d/epel.repo"
	crbRepo     = "/etc/yum.repos.d/almalinux-crb.repo"
)

type epel struct{ control.Base }

func init() {
	System.Add(&epel{control.Base{M: control.Meta{
		ID:           epelID,
		Category:     control.Baseline,
		Number:       7,
		Title:        "Enable the EPEL repository",
		Tags:         []control.Tag{control.TagExternal, control.TagInput},
		RevertLimits: "Packages that were installed from EPEL stay installed, but no longer get updates.",
	}}})
}

func (e *epel) Inputs(context.Context, *control.Env) ([]control.Input, error) {
	return []control.Input{{
		Key:   "crb",
		Label: "Also enable the CodeReady Builder (CRB) repository?",
		Help:  "Many EPEL packages need libraries from CRB. CRB comes from AlmaLinux itself.",
		Kind:  control.Choice,
		Options: []control.Option{
			{Value: "yes", Label: "Yes, enable CRB"},
			{Value: "no", Label: "No, leave CRB as it is"},
		},
		Default: "yes",
	}}, nil
}

// repoEnabled reads a repository file and reports whether the section is on.
func repoEnabled(env *control.Env, file, section string) bool {
	b, err := files.ReadOptional(env.Path(file))
	if err != nil {
		return false
	}
	v, ok := kit.GetINI(string(b), section, "enabled")
	return ok && v == "1"
}

func (e *epel) Check(_ context.Context, env *control.Env) (control.State, error) {
	if _, ok, err := env.Rec.Get(epelID, "applied"); err != nil || !ok {
		return control.NotApplied, err
	}
	if !files.Exists(env.Path(epelRepo)) || !repoEnabled(env, epelRepo, "epel") {
		return control.NotApplied, nil
	}
	if want, _, _ := env.Rec.Get(epelID, "crb"); want == "yes" && !repoEnabled(env, crbRepo, "crb") {
		return control.Partial, nil
	}
	return control.Applied, nil
}

func (e *epel) Apply(ctx context.Context, env *control.Env, in control.Values) error {
	if err := env.Rec.Put(epelID, "had-epel", kit.YesNo(dnf.Installed(ctx, env, epelPackage))); err != nil {
		return err
	}
	if err := dnf.Install(ctx, env, epelPackage); err != nil {
		return err
	}
	if in.String("crb") == "yes" {
		if _, ok, _ := env.Rec.Get(epelID, "crb-before"); !ok {
			if err := env.Rec.Put(epelID, "crb-before", kit.YesNo(repoEnabled(env, crbRepo, "crb"))); err != nil {
				return err
			}
		}
		if _, err := env.Run.Run(ctx, "crb", "enable"); err != nil {
			return err
		}
	}
	if err := env.Rec.Put(epelID, "crb", in.String("crb")); err != nil {
		return err
	}
	if err := dnf.MakeCache(ctx, env); err != nil {
		return err
	}
	env.Log.Infof("EPEL is enabled")
	return env.Rec.Put(epelID, "applied", "yes")
}

func (e *epel) Revert(ctx context.Context, env *control.Env) error {
	if !env.Rec.Has(epelID) {
		env.Log.Warnf("%s: no record, leaving the repositories alone", epelID)
		return nil
	}
	if before, _, _ := env.Rec.Get(epelID, "crb-before"); before == "no" {
		if _, err := env.Run.Run(ctx, "crb", "disable"); err != nil {
			return err
		}
	}
	if had, _, _ := env.Rec.Get(epelID, "had-epel"); had != "yes" {
		if err := dnf.Remove(ctx, env, epelPackage); err != nil {
			return err
		}
	}
	return env.Rec.Delete(epelID)
}
