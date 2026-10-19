// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Danang Galuh Tegar Prasetyo

package controls

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/danang-id/server-hardening/internal/apt"
	"github.com/danang-id/server-hardening/internal/control"
	"github.com/danang-id/server-hardening/internal/files"
)

const (
	omzID   = "misc.oh-my-zsh"
	omzRepo = "https://github.com/ohmyzsh/ohmyzsh.git"
	// omzCommit is the release of the framework this tool installs: the last
	// commit of the master branch on 2026-08-30. It is not the newest one on
	// purpose. Change it to a newer commit only after reading the changes.
	omzCommit = "a5ecff7560b2e26f612032c632a12c75a3048bd0"
)

type ohMyZsh struct{ control.Base }

func init() {
	System.Add(&ohMyZsh{control.Base{M: control.Meta{
		ID:           omzID,
		Category:     control.Misc,
		Number:       5,
		Title:        "Install Oh My Zsh",
		Default:      false,
		Requires:     []string{zshID},
		Tags:         []control.Tag{control.TagInput, control.TagExternal},
		RevertLimits: "Changes made inside the framework directory are lost. zsh and git stay installed.",
	}}})
}

var omzName = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)

func (o *ohMyZsh) Inputs(_ context.Context, env *control.Env) ([]control.Input, error) {
	accts, err := loginAccounts(env)
	if err != nil {
		return nil, err
	}
	admins, _ := adminAccounts(env)
	var opts []control.Option
	for _, a := range accts {
		opts = append(opts, control.Option{Value: a.Name, Label: a.Name, Help: "home: " + a.Home})
	}
	in := []control.Input{}
	if len(opts) > 0 {
		in = append(in, control.Input{
			Key: "accounts", Label: "Which accounts get Oh My Zsh?",
			Help: "It runs third-party code from the internet in the shell of each account. Do not choose accounts that reach sensitive data.",
			Kind: control.MultiChoice, Options: opts, DefaultMulti: admins,
		})
	}
	nameCheck := func(s string) error {
		for _, n := range listItems(s) {
			if !omzName.MatchString(n) {
				return fmt.Errorf("%q is not a valid name (letters, digits, - and _)", n)
			}
		}
		return nil
	}
	return append(in,
		control.Input{Key: "theme", Label: "Theme", Default: "robbyrussell", Validate: func(s string) error {
			if !omzName.MatchString(strings.TrimSpace(s)) {
				return fmt.Errorf("use letters, digits, - and _")
			}
			return nil
		}},
		control.Input{Key: "plugins", Label: "Plugins, separated by spaces", Default: "git", Optional: true, Validate: nameCheck},
	), nil
}

func omzDir(a account) string { return filepath.Join(a.Home, ".oh-my-zsh") }
func omzRC(a account) string  { return filepath.Join(a.Home, ".zshrc") }

func omzZshrc(theme string, plugins []string) string {
	return managed(omzID) + "\n" +
		"export ZSH=\"$HOME/.oh-my-zsh\"\n" +
		"ZSH_THEME=\"" + theme + "\"\n" +
		"plugins=(" + strings.Join(plugins, " ") + ")\n" +
		"source $ZSH/oh-my-zsh.sh\n"
}

func (o *ohMyZsh) Check(_ context.Context, env *control.Env) (control.State, error) {
	if !env.Rec.Has(omzID) {
		return control.NotApplied, nil
	}
	v, _, _ := env.Rec.Get(omzID, "accounts")
	for _, u := range lines(v) {
		a, ok, _ := findAccount(env, u)
		if !ok {
			continue
		}
		if !files.Exists(env.Path(filepath.Join(omzDir(a), "oh-my-zsh.sh"))) || !hasMarker(env, omzRC(a), omzID) {
			return control.Partial, nil
		}
	}
	return control.Applied, nil
}

func (o *ohMyZsh) Apply(ctx context.Context, env *control.Env, in control.Values) error {
	theme := strings.TrimSpace(in.String("theme"))
	if !omzName.MatchString(theme) {
		return fmt.Errorf("the theme %q is not a valid name", theme)
	}
	plugins := listItems(in.String("plugins"))
	for _, p := range plugins {
		if !omzName.MatchString(p) {
			return fmt.Errorf("the plugin %q is not a valid name", p)
		}
	}
	var todo []account
	for _, u := range in.List("accounts") {
		a, ok, err := findAccount(env, u)
		if err != nil {
			return err
		}
		if !ok {
			return fmt.Errorf("there is no account %q", u)
		}
		if files.Exists(env.Path(omzDir(a))) {
			return fmt.Errorf("%s has %s already. Remove it or leave the account out", u, omzDir(a))
		}
		todo = append(todo, a)
	}
	if len(todo) == 0 {
		env.Log.Infof("no account chosen, nothing installed")
		return nil
	}
	if err := apt.Install(ctx, env, "git"); err != nil {
		return err
	}
	env.Log.Warnf("downloading Oh My Zsh from %s at commit %s. It runs third-party code in the shell of every chosen account", omzRepo, omzCommit[:12])

	prev, _, _ := env.Rec.Get(omzID, "accounts")
	all := lines(prev)
	for _, a := range todo {
		if err := o.install(ctx, env, a, theme, plugins); err != nil {
			return fmt.Errorf("%s: %w", a.Name, err)
		}
		if !contains(all, a.Name) {
			all = append(all, a.Name)
			if err := env.Rec.Put(omzID, "accounts", strings.Join(all, "\n")); err != nil {
				return err
			}
		}
		env.Log.Infof("installed Oh My Zsh for %s", a.Name)
	}
	return nil
}

// install puts the framework in the home directory of one account.
func (o *ohMyZsh) install(ctx context.Context, env *control.Env, a account, theme string, plugins []string) error {
	dir, rc := omzDir(a), omzRC(a)
	asUser := func(args ...string) error {
		cmd := append([]string{"-u", a.Name, "--", "env", "HOME=" + a.Home}, args...)
		if out, err := env.Run.Run(ctx, "runuser", cmd...); err != nil {
			return fmt.Errorf("%s failed: %w: %s", args[0]+" "+args[1], err, strings.TrimSpace(string(out)))
		}
		return nil
	}
	undo := func() {
		_ = os.RemoveAll(env.Path(dir))
		_ = restoreFile(env, omzID, rc)
	}
	// Fetch exactly one commit and check it out. Nothing is run from it here.
	for _, step := range [][]string{
		{"git", "init", "-q", dir},
		{"git", "-C", dir, "remote", "add", "origin", omzRepo},
		{"git", "-C", dir, "fetch", "-q", "--depth", "1", "origin", omzCommit},
		{"git", "-C", dir, "checkout", "-q", "FETCH_HEAD"},
	} {
		if err := asUser(step...); err != nil {
			undo()
			return err
		}
	}
	if !files.Exists(env.Path(filepath.Join(dir, "themes", theme+".zsh-theme"))) {
		undo()
		return fmt.Errorf("the framework has no theme %q", theme)
	}
	for _, p := range plugins {
		if !files.Exists(env.Path(filepath.Join(dir, "plugins", p))) {
			undo()
			return fmt.Errorf("the framework has no plugin %q", p)
		}
	}
	if err := putFile(env, omzID, rc, omzZshrc(theme, plugins), 0o644); err != nil {
		undo()
		return err
	}
	if _, err := env.Run.Run(ctx, "chown", strconv.Itoa(a.UID)+":"+strconv.Itoa(a.GID), rc); err != nil {
		undo()
		return fmt.Errorf("cannot give %s to its owner: %w", rc, err)
	}
	return nil
}

func (o *ohMyZsh) Revert(ctx context.Context, env *control.Env) error {
	if !env.Rec.Has(omzID) {
		env.Log.Warnf("%s: no record, leaving the accounts alone", omzID)
		return nil
	}
	v, _, _ := env.Rec.Get(omzID, "accounts")
	for _, u := range lines(v) {
		a, ok, _ := findAccount(env, u)
		if !ok {
			continue
		}
		if err := os.RemoveAll(env.Path(omzDir(a))); err != nil {
			return err
		}
		if err := restoreFile(env, omzID, omzRC(a)); err != nil {
			return err
		}
		if files.Exists(env.Path(omzRC(a))) {
			_, _ = env.Run.Run(ctx, "chown", strconv.Itoa(a.UID)+":"+strconv.Itoa(a.GID), omzRC(a))
		}
	}
	return env.Rec.Delete(omzID)
}
