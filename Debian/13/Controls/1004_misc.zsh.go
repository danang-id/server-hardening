// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Danang Galuh Tegar Prasetyo

package controls

import (
	"context"
	"fmt"
	"strings"

	"github.com/danang-id/server-hardening/internal/apt"
	"github.com/danang-id/server-hardening/internal/control"
	"github.com/danang-id/server-hardening/internal/files"
)

const (
	zshID   = "misc.zsh"
	zshPath = "/usr/bin/zsh"
)

type zsh struct{ control.Base }

func init() {
	System.Add(&zsh{control.Base{M: control.Meta{
		ID:           zshID,
		Category:     control.Misc,
		Number:       4,
		Title:        "Install zsh",
		Default:      false,
		Tags:         []control.Tag{control.TagInput},
		RevertLimits: "The zsh package stays installed. Open sessions keep their current shell until the next login.",
	}}})
}

// loginAccounts lists the normal accounts that have a login shell, plus root.
func loginAccounts(env *control.Env) ([]account, error) {
	all, err := readPasswd(env)
	if err != nil {
		return nil, err
	}
	var out []account
	for _, a := range all {
		if (a.UID >= firstHumanUID && a.UID < 65534) || a.UID == 0 {
			if !strings.HasSuffix(a.Shell, "/nologin") && !strings.HasSuffix(a.Shell, "/false") {
				out = append(out, a)
			}
		}
	}
	return out, nil
}

func (z *zsh) Inputs(_ context.Context, env *control.Env) ([]control.Input, error) {
	accts, err := loginAccounts(env)
	if err != nil {
		return nil, err
	}
	admins, _ := adminAccounts(env)
	var opts []control.Option
	for _, a := range accts {
		help := "login shell now: " + a.Shell
		if a.UID == 0 {
			help += ". A working root shell matters most when something is broken"
		}
		opts = append(opts, control.Option{Value: a.Name, Label: a.Name, Help: help})
	}
	if len(opts) == 0 {
		return nil, nil
	}
	return []control.Input{{
		Key: "accounts", Label: "Which accounts get zsh as their login shell?",
		Help: "The package is installed in any case.",
		Kind: control.MultiChoice, Options: opts, DefaultMulti: admins,
	}}, nil
}

func (z *zsh) Check(ctx context.Context, env *control.Env) (control.State, error) {
	if !env.Rec.Has(zshID) {
		return control.NotApplied, nil
	}
	if !apt.Installed(ctx, env, "zsh") {
		return control.Partial, nil
	}
	v, _, _ := env.Rec.Get(zshID, "accounts")
	for _, u := range lines(v) {
		if a, ok, _ := findAccount(env, u); ok && a.Shell != zshPath {
			return control.Partial, nil
		}
	}
	return control.Applied, nil
}

func (z *zsh) Apply(ctx context.Context, env *control.Env, in control.Values) error {
	if err := apt.Install(ctx, env, "zsh"); err != nil {
		return err
	}
	shells, _ := files.ReadOptional(env.Path("/etc/shells"))
	if len(in.List("accounts")) > 0 && !strings.Contains(string(shells), zshPath+"\n") {
		return fmt.Errorf("%s is not listed in /etc/shells, so it cannot be a login shell", zshPath)
	}
	// Check every name before changing anything.
	var todo []account
	for _, u := range in.List("accounts") {
		a, ok, err := findAccount(env, u)
		if err != nil {
			return err
		}
		if !ok {
			return fmt.Errorf("there is no account %q", u)
		}
		todo = append(todo, a)
	}
	prev, _, _ := env.Rec.Get(zshID, "accounts")
	all := lines(prev)
	if err := env.Rec.Put(zshID, "accounts", strings.Join(all, "\n")); err != nil {
		return err
	}
	var done []account
	rollback := func() {
		for _, a := range done {
			_, _ = env.Run.Run(ctx, "usermod", "-s", a.Shell, a.Name)
		}
	}
	for _, a := range todo {
		if a.Shell == zshPath {
			continue
		}
		if _, ok, _ := env.Rec.Get(zshID, "shell:"+a.Name); !ok {
			if err := env.Rec.Put(zshID, "shell:"+a.Name, a.Shell); err != nil {
				rollback()
				return err
			}
		}
		if _, err := env.Run.Run(ctx, "usermod", "-s", zshPath, a.Name); err != nil {
			rollback()
			return fmt.Errorf("cannot change the shell of %s: %w", a.Name, err)
		}
		done = append(done, a)
		if !contains(all, a.Name) {
			all = append(all, a.Name)
		}
		env.Log.Infof("%s now uses zsh", a.Name)
	}
	return env.Rec.Put(zshID, "accounts", strings.Join(all, "\n"))
}

func (z *zsh) Revert(ctx context.Context, env *control.Env) error {
	if !env.Rec.Has(zshID) {
		env.Log.Warnf("%s: no record, leaving login shells alone", zshID)
		return nil
	}
	v, _, _ := env.Rec.Get(zshID, "accounts")
	for _, u := range lines(v) {
		shell, ok, _ := env.Rec.Get(zshID, "shell:"+u)
		if !ok {
			continue
		}
		if _, exists, _ := findAccount(env, u); !exists {
			continue
		}
		if _, err := env.Run.Run(ctx, "usermod", "-s", shell, u); err != nil {
			return fmt.Errorf("cannot put the shell of %s back to %s: %w", u, shell, err)
		}
	}
	return env.Rec.Delete(zshID)
}
