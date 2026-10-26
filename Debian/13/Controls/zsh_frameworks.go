// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Danang Galuh Tegar Prasetyo

package controls

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/danang-id/server-hardening/internal/control"
	"github.com/danang-id/server-hardening/internal/files"
)

// A zshFramework is a framework that misc.zsh can set up in the home directory
// of an account, such as Oh My Zsh. To support another one, add a type that
// implements this interface and list it in zshFrameworks.
//
// Every framework runs third-party code in the shell of the account, so each
// one is pinned: it fetches a fixed commit or a file with a fixed checksum,
// never "the latest". Change a pin only after reading what changed.
type zshFramework interface {
	// Name is the value of the "framework" answer.
	Name() string
	// Option is how the question offers the framework.
	Option() control.Option
	// Inputs are extra questions. Each one must have OnlyIf set to the Name.
	Inputs() []control.Input
	// Verify checks the answers before anything is downloaded.
	Verify(in control.Values) error
	// Packages are the packages that Install needs.
	Packages() []string
	// Source says where the code comes from, for the log.
	Source() string
	// Occupied returns the reason why the framework cannot go into the account
	// without overwriting something of the user, or "" when it can.
	Occupied(env *control.Env, a account) string
	// Healthy reports whether the framework is complete for the account.
	Healthy(env *control.Env, a account) bool
	// Install sets the framework up. It removes what it made if it fails.
	Install(ctx context.Context, env *control.Env, a account, in control.Values) error
	// Remove deletes the directories of the framework. It does not touch the
	// files that Files lists: the control puts those back.
	Remove(env *control.Env, a account) error
	// Files lists the files in the home directory that Install writes.
	Files(a account) []string
}

// zshFrameworks lists the frameworks, in the order the question offers them.
var zshFrameworks = []zshFramework{ohMyZsh{}, zimfw{}}

const zshNoFramework = "none"

// frameworkNamed finds a framework by its name. It returns nil for "none".
func frameworkNamed(name string) zshFramework {
	for _, f := range zshFrameworks {
		if f.Name() == name {
			return f
		}
	}
	return nil
}

// frameworkInputs are the questions about the frameworks: the choice, then
// the questions of each framework that has some.
func frameworkInputs() []control.Input {
	opts := []control.Option{{Value: zshNoFramework, Label: "None", Help: "Only zsh, as it comes."}}
	for _, f := range zshFrameworks {
		opts = append(opts, f.Option())
	}
	in := []control.Input{{
		Key: "framework", Label: "Which zsh framework do you want?",
		Help: "It is set up for the accounts you chose above. A framework runs third-party code from the internet in the shell of each of those accounts, so do not choose it for accounts that reach sensitive data.",
		Kind: control.Choice, Options: opts, Default: zshNoFramework,
	}}
	for _, f := range zshFrameworks {
		in = append(in, f.Inputs()...)
	}
	return in
}

// asUser runs a command as the account, with its home directory set. The
// extra entries are environment variables for the command.
func asUser(ctx context.Context, env *control.Env, a account, extra []string, args ...string) error {
	cmd := append([]string{"-u", a.Name, "--", "env", "HOME=" + a.Home}, extra...)
	cmd = append(cmd, args...)
	if out, err := env.Run.Run(ctx, "runuser", cmd...); err != nil {
		what := args[0]
		if len(args) > 1 {
			what += " " + args[1]
		}
		return fmt.Errorf("%s failed: %w: %s", what, err, strings.TrimSpace(string(out)))
	}
	return nil
}

// putOwned writes a file in the home directory, as the account's own.
func putOwned(ctx context.Context, env *control.Env, a account, path, content string) error {
	if err := putFile(env, zshID, path, content, 0o644); err != nil {
		return err
	}
	if _, err := env.Run.Run(ctx, "chown", strconv.Itoa(a.UID)+":"+strconv.Itoa(a.GID), path); err != nil {
		return fmt.Errorf("cannot give %s to its owner: %w", path, err)
	}
	return nil
}

// fetchCommit puts one commit of a repository in a new directory, as the
// account. It fetches exactly that commit and checks it out. Nothing is run
// from it here.
func fetchCommit(ctx context.Context, env *control.Env, a account, dir, repo, commit string) error {
	for _, step := range [][]string{
		{"git", "init", "-q", dir},
		{"git", "-C", dir, "remote", "add", "origin", repo},
		{"git", "-C", dir, "fetch", "-q", "--depth", "1", "origin", commit},
		{"git", "-C", dir, "checkout", "-q", "FETCH_HEAD"},
	} {
		if err := asUser(ctx, env, a, nil, step...); err != nil {
			return err
		}
	}
	return nil
}

// ---- Oh My Zsh ----

const (
	omzName = "oh-my-zsh"
	omzRepo = "https://github.com/ohmyzsh/ohmyzsh.git"
	// omzCommit is the release of the framework this tool installs: the last
	// commit of the master branch on 2026-08-30. It is not the newest one on
	// purpose. Change it to a newer commit only after reading the changes.
	omzCommit = "a5ecff7560b2e26f612032c632a12c75a3048bd0"
)

var omzWord = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)

type ohMyZsh struct{}

func omzDir(a account) string  { return filepath.Join(a.Home, ".oh-my-zsh") }
func zshrcOf(a account) string { return filepath.Join(a.Home, ".zshrc") }

func (ohMyZsh) Name() string { return omzName }
func (ohMyZsh) Option() control.Option {
	return control.Option{Value: omzName, Label: "Oh My Zsh", Help: "A large collection of themes and plugins. Code from github.com/ohmyzsh at a fixed commit."}
}

func (ohMyZsh) Inputs() []control.Input {
	only := &control.OnlyIf{Key: "framework", Is: []string{omzName}}
	return []control.Input{
		{Key: "theme", Label: "Oh My Zsh theme", Default: "robbyrussell", OnlyIf: only, Validate: func(s string) error {
			if !omzWord.MatchString(strings.TrimSpace(s)) {
				return fmt.Errorf("use letters, digits, - and _")
			}
			return nil
		}},
		{Key: "plugins", Label: "Oh My Zsh plugins, separated by spaces", Default: "git", Optional: true, OnlyIf: only, Validate: func(s string) error {
			for _, n := range listItems(s) {
				if !omzWord.MatchString(n) {
					return fmt.Errorf("%q is not a valid name (letters, digits, - and _)", n)
				}
			}
			return nil
		}},
	}
}

func (ohMyZsh) Verify(in control.Values) error {
	if theme := strings.TrimSpace(in.String("theme")); !omzWord.MatchString(theme) {
		return fmt.Errorf("the theme %q is not a valid name", theme)
	}
	for _, p := range listItems(in.String("plugins")) {
		if !omzWord.MatchString(p) {
			return fmt.Errorf("the plugin %q is not a valid name", p)
		}
	}
	return nil
}

func (ohMyZsh) Packages() []string { return []string{"git"} }
func (ohMyZsh) Source() string {
	return "Oh My Zsh from " + omzRepo + " at commit " + omzCommit[:12]
}

func (ohMyZsh) Occupied(env *control.Env, a account) string {
	if files.Exists(env.Path(omzDir(a))) {
		return omzDir(a) + " exists. Remove it or leave the account out"
	}
	return ""
}

func (ohMyZsh) Healthy(env *control.Env, a account) bool {
	return files.Exists(env.Path(filepath.Join(omzDir(a), "oh-my-zsh.sh"))) && hasMarker(env, zshrcOf(a), zshID)
}

func (ohMyZsh) Files(a account) []string { return []string{zshrcOf(a)} }

func (ohMyZsh) Remove(env *control.Env, a account) error { return os.RemoveAll(env.Path(omzDir(a))) }

func omzZshrc(theme string, plugins []string) string {
	return managed(zshID) + "\n" +
		"export ZSH=\"$HOME/.oh-my-zsh\"\n" +
		"ZSH_THEME=\"" + theme + "\"\n" +
		"plugins=(" + strings.Join(plugins, " ") + ")\n" +
		"source $ZSH/oh-my-zsh.sh\n"
}

func (o ohMyZsh) Install(ctx context.Context, env *control.Env, a account, in control.Values) error {
	theme := strings.TrimSpace(in.String("theme"))
	plugins := listItems(in.String("plugins"))
	dir := omzDir(a)
	undo := func() { undoFramework(env, o, a) }
	if err := fetchCommit(ctx, env, a, dir, omzRepo, omzCommit); err != nil {
		undo()
		return err
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
	if err := putOwned(ctx, env, a, zshrcOf(a), omzZshrc(theme, plugins)); err != nil {
		undo()
		return err
	}
	return nil
}

// undoFramework removes what a failed install made and puts the files back.
func undoFramework(env *control.Env, f zshFramework, a account) {
	_ = f.Remove(env, a)
	for _, p := range f.Files(a) {
		_ = restoreFile(env, zshID, p)
	}
}

// ---- Zim ----

const (
	zimName    = "zimfw"
	zimVersion = "v1.20.1"
	zimURL     = "https://github.com/zimfw/zimfw/releases/download/" + zimVersion + "/zimfw.zsh"
)

// zimChecksum is the SHA-256 of zimfw.zsh in the release above. The file is
// checked before anything runs it. It is a variable so that tests can use their own file.
var zimChecksum = "730f7a86f7aac9c87b137e85ecf0ebec19530ab6af065289bcd0d60cb13d8689"

// zimModules are the modules of the default setup, each at a fixed commit of
// the main branch on 2026-10-26. The completion module comes last, as Zim asks.
var zimModules = []struct{ name, commit string }{
	{"environment", "d4bceaa3da89cd819843334dba1a5bf7dc137e14"},
	{"git", "7d38eb4d9e595241bbbcdd62f836d1ee668317fc"},
	{"input", "bdec2b372f8bd16a072d30ebc447a22dad52cfb4"},
	{"termtitle", "b0de7783181804d21cc73fbb109fb89e8b021327"},
	{"utility", "e1d1c23f578420e285cbea41dbd5cef75b35ca5b"},
	{"duration-info", "c887236aa21e2b070e128d2182c9576972697ba0"},
	{"asciiship", "56c0a723b8b0d035dae78234f45997b6baa22d35"},
	{"completion", "8d3e0f4e6272f4d3bad659eaa13929f9dd96f123"},
}

type zimfw struct{}

func zimDir(a account) string { return filepath.Join(a.Home, ".zim") }
func zimRC(a account) string  { return filepath.Join(a.Home, ".zimrc") }

func (zimfw) Name() string { return zimName }
func (zimfw) Option() control.Option {
	return control.Option{Value: zimName, Label: "Zim (zimfw)", Help: "Small and fast, with a few modules. Code from github.com/zimfw at fixed versions."}
}
func (zimfw) Inputs() []control.Input                  { return nil }
func (zimfw) Verify(control.Values) error              { return nil }
func (zimfw) Packages() []string                       { return []string{"git", "curl"} }
func (zimfw) Files(a account) []string                 { return []string{zimRC(a), zshrcOf(a)} }
func (zimfw) Remove(env *control.Env, a account) error { return os.RemoveAll(env.Path(zimDir(a))) }
func (zimfw) Source() string {
	return "Zim " + zimVersion + " and its modules from github.com/zimfw"
}

func (zimfw) Occupied(env *control.Env, a account) string {
	switch {
	case files.Exists(env.Path(zimDir(a))):
		return zimDir(a) + " exists. Remove it or leave the account out"
	case files.Exists(env.Path(zimRC(a))):
		return zimRC(a) + " exists. Remove it or leave the account out"
	}
	return ""
}

func (zimfw) Healthy(env *control.Env, a account) bool {
	for _, p := range []string{"zimfw.zsh", "init.zsh"} {
		if !files.Exists(env.Path(filepath.Join(zimDir(a), p))) {
			return false
		}
	}
	return files.Exists(env.Path(zimRC(a))) && hasMarker(env, zshrcOf(a), zshID)
}

func zimrc() string {
	var b strings.Builder
	b.WriteString(managed(zshID))
	b.WriteString("\n# The modules of Zim. Add a line to use another one, then open a new shell.\n")
	b.WriteString("# See https://zimfw.sh/docs/modules/\n")
	for _, m := range zimModules {
		b.WriteString("zmodule ")
		b.WriteString(m.name)
		b.WriteString("\n")
	}
	return b.String()
}

func zimZshrc() string {
	return managed(zshID) + `
# History: drop an older duplicate when a command is added again.
setopt HIST_IGNORE_ALL_DUPS
# Emacs keys on the command line.
bindkey -e
# A / ends a word, so Ctrl-W deletes one path part.
WORDCHARS=${WORDCHARS//[\/]}

ZIM_HOME=${HOME}/.zim
# Install new modules and rebuild the init script when .zimrc has changed.
if [[ ! ${ZIM_HOME}/init.zsh -nt ${ZIM_CONFIG_FILE:-${HOME}/.zimrc} ]]; then
  source ${ZIM_HOME}/zimfw.zsh init
fi
source ${ZIM_HOME}/init.zsh
`
}

func (z zimfw) Install(ctx context.Context, env *control.Env, a account, _ control.Values) error {
	dir := zimDir(a)
	script := filepath.Join(dir, "zimfw.zsh")
	undo := func() { undoFramework(env, z, a) }
	if err := asUser(ctx, env, a, nil, "mkdir", "-p", filepath.Join(dir, "modules")); err != nil {
		undo()
		return err
	}
	if err := asUser(ctx, env, a, nil, "curl", "--proto", "=https", "--tlsv1.2", "-fsSL", "-o", script, zimURL); err != nil {
		undo()
		return err
	}
	b, err := os.ReadFile(env.Path(script))
	if err != nil {
		undo()
		return fmt.Errorf("cannot read the downloaded %s: %w", script, err)
	}
	if sum := sha256.Sum256(b); hex.EncodeToString(sum[:]) != zimChecksum {
		undo()
		return fmt.Errorf("the downloaded zimfw.zsh does not match the checksum that this tool expects for Zim %s, so it was removed", zimVersion)
	}
	for _, m := range zimModules {
		if err := fetchCommit(ctx, env, a, filepath.Join(dir, "modules", m.name), "https://github.com/zimfw/"+m.name+".git", m.commit); err != nil {
			undo()
			return fmt.Errorf("module %s: %w", m.name, err)
		}
	}
	if err := putOwned(ctx, env, a, zimRC(a), zimrc()); err != nil {
		undo()
		return err
	}
	if err := putOwned(ctx, env, a, zshrcOf(a), zimZshrc()); err != nil {
		undo()
		return err
	}
	// The modules are in place, so this only writes init.zsh. It needs no network.
	if err := asUser(ctx, env, a, []string{"ZIM_HOME=" + dir}, "zsh", script, "build"); err != nil {
		undo()
		return err
	}
	return nil
}
