// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Danang Galuh Tegar Prasetyo

package controls

import (
	"context"
	"fmt"
	"strconv"
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
		Tags:         []control.Tag{control.TagInput, control.TagExternal},
		RevertLimits: "The zsh package stays installed, and so do git and curl if a framework needed them. Open sessions keep their current shell until the next login. Changes made inside a framework directory are lost.",
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

// hasOption reports whether an option with the value is in the list.
func hasOption(opts []control.Option, value string) bool {
	for _, o := range opts {
		if o.Value == value {
			return true
		}
	}
	return false
}

func (z *zsh) Inputs(_ context.Context, env *control.Env) ([]control.Input, error) {
	accts, err := loginAccounts(env)
	if err != nil {
		return nil, err
	}
	admins, _ := expectedAdmins(env)
	var opts []control.Option
	for _, a := range accts {
		help := "login shell now: " + a.Shell
		if a.UID == 0 {
			help += ". A working root shell matters most when something is broken"
		}
		opts = append(opts, control.Option{Value: a.Name, Label: a.Name, Help: help})
	}
	if p := plannedAdmin(env); p != "" && !hasOption(opts, p) {
		opts = append(opts, control.Option{Value: p, Label: p + " (to be created)", Help: "the administrator account that this run creates"})
	}
	if len(opts) == 0 {
		return nil, nil
	}
	in := []control.Input{{
		Key: "accounts", Label: "Which accounts get zsh as their login shell?",
		Help: "The package is installed in any case.",
		Kind: control.MultiChoice, Options: opts, DefaultMulti: admins,
	}}
	return append(in, frameworkInputs()...), nil
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
	v, _, _ = env.Rec.Get(zshID, "frameworks")
	for _, u := range lines(v) {
		a, ok, _ := findAccount(env, u)
		if !ok {
			continue
		}
		name, _, _ := env.Rec.Get(zshID, "framework:"+u)
		if fw := frameworkNamed(name); fw != nil && !fw.Healthy(env, a) {
			return control.Partial, nil
		}
	}
	return control.Applied, nil
}

func (z *zsh) Apply(ctx context.Context, env *control.Env, in control.Values) error {
	var fw zshFramework
	if name := in.String("framework"); name != "" && name != zshNoFramework {
		if fw = frameworkNamed(name); fw == nil {
			return fmt.Errorf("there is no zsh framework %q", name)
		}
		if err := fw.Verify(in); err != nil {
			return err
		}
	}
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
		if fw != nil {
			if err := frameworkFits(env, fw, a); err != nil {
				return err
			}
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
	if err := env.Rec.Put(zshID, "accounts", strings.Join(all, "\n")); err != nil {
		return err
	}
	if fw == nil || len(todo) == 0 {
		return nil
	}
	return setUpFramework(ctx, env, fw, todo, in)
}

// frameworkFits refuses to set a framework up in an account that has another
// one from this control, or has files of its own where the framework goes.
func frameworkFits(env *control.Env, fw zshFramework, a account) error {
	cur, _, _ := env.Rec.Get(zshID, "framework:"+a.Name)
	switch {
	case cur == fw.Name():
		return nil // ours: a repair
	case cur != "":
		return fmt.Errorf("%s has %s already. Revert this control to remove it first, or leave the account out", a.Name, cur)
	}
	if why := fw.Occupied(env, a); why != "" {
		return fmt.Errorf("%s: %s", a.Name, why)
	}
	return nil
}

// setUpFramework puts the framework in the home directory of each account. The
// choice is recorded before the download, so that an install that fails half
// way shows as partial and the next run repairs it.
func setUpFramework(ctx context.Context, env *control.Env, fw zshFramework, todo []account, in control.Values) error {
	if err := apt.Install(ctx, env, fw.Packages()...); err != nil {
		return err
	}
	env.Log.Warnf("downloading %s. It runs third-party code in the shell of every chosen account", fw.Source())
	prev, _, _ := env.Rec.Get(zshID, "frameworks")
	users := lines(prev)
	for _, a := range todo {
		cur, _, _ := env.Rec.Get(zshID, "framework:"+a.Name)
		if cur == fw.Name() && fw.Healthy(env, a) {
			continue
		}
		if cur == fw.Name() {
			env.Log.Warnf("%s: %s is incomplete, installing it again", a.Name, fw.Name())
			if err := fw.Remove(env, a); err != nil {
				return fmt.Errorf("%s: %w", a.Name, err)
			}
		}
		if err := env.Rec.Put(zshID, "framework:"+a.Name, fw.Name()); err != nil {
			return err
		}
		if !contains(users, a.Name) {
			users = append(users, a.Name)
			if err := env.Rec.Put(zshID, "frameworks", strings.Join(users, "\n")); err != nil {
				return err
			}
		}
		if err := fw.Install(ctx, env, a, in); err != nil {
			return fmt.Errorf("%s: %w", a.Name, err)
		}
		env.Log.Infof("installed %s for %s", fw.Name(), a.Name)
	}
	return nil
}

func (z *zsh) Revert(ctx context.Context, env *control.Env) error {
	if !env.Rec.Has(zshID) {
		env.Log.Warnf("%s: no record, leaving login shells alone", zshID)
		return nil
	}
	fv, _, _ := env.Rec.Get(zshID, "frameworks")
	for _, u := range lines(fv) {
		a, ok, _ := findAccount(env, u)
		if !ok {
			continue
		}
		name, _, _ := env.Rec.Get(zshID, "framework:"+u)
		fw := frameworkNamed(name)
		if fw == nil {
			continue
		}
		if err := fw.Remove(env, a); err != nil {
			return err
		}
		for _, p := range fw.Files(a) {
			if err := restoreFile(env, zshID, p); err != nil {
				return err
			}
			if files.Exists(env.Path(p)) {
				_, _ = env.Run.Run(ctx, "chown", strconv.Itoa(a.UID)+":"+strconv.Itoa(a.GID), p)
			}
		}
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
