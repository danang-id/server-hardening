// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Danang Galuh Tegar Prasetyo

package controls

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/danang-id/server-hardening/internal/control"
)

func omzControl() *ohMyZsh { return &ohMyZsh{control.Base{M: control.Meta{ID: omzID}}} }

// omzEnv simulates the download: the checkout step fills the directory.
func omzEnv(t *testing.T) (*control.Env, *fakeRunner, *sysSim) {
	env, run, s := sysEnv(t)
	writeFile(t, env, "/etc/passwd", basePasswd)
	writeFile(t, env, "/etc/group", baseGroup)
	prev := run.hook
	run.hook = func(f *fakeRunner, cmd string) {
		prev(f, cmd)
		if strings.Contains(cmd, "checkout -q FETCH_HEAD") && !f.fail[cmd] {
			dir := env.Path("/home/alice/.oh-my-zsh")
			for _, p := range []string{"oh-my-zsh.sh", "themes/robbyrussell.zsh-theme", "themes/agnoster.zsh-theme", "plugins/git/git.plugin.zsh", "plugins/sudo/sudo.plugin.zsh"} {
				must(t, os.MkdirAll(filepath.Dir(filepath.Join(dir, p)), 0o755))
				must(t, os.WriteFile(filepath.Join(dir, p), []byte("x"), 0o644))
			}
		}
	}
	return env, run, s
}

func omzValues() control.Values {
	return control.Values{"accounts": {"alice"}, "theme": {"agnoster"}, "plugins": {"git sudo"}}
}

func TestOhMyZshInstallsPinnedCommitAsTheUser(t *testing.T) {
	ctx := context.Background()
	env, run, s := omzEnv(t)
	c := omzControl()
	writeFile(t, env, "/home/alice/.zshrc", "# my own\n")
	must(t, c.Apply(ctx, env, omzValues()))
	if !s.installed["git"] {
		t.Fatal("git must be installed")
	}
	if !run.did("runuser -u alice -- env HOME=/home/alice git -C /home/alice/.oh-my-zsh fetch -q --depth 1 origin " + omzCommit) {
		t.Fatalf("pinned fetch missing: %v", run.calls)
	}
	rc := read(t, env, "/home/alice/.zshrc")
	for _, w := range []string{managed(omzID), `ZSH_THEME="agnoster"`, "plugins=(git sudo)", "source $ZSH/oh-my-zsh.sh"} {
		if !strings.Contains(rc, w) {
			t.Fatalf("missing %q in\n%s", w, rc)
		}
	}
	if !run.did("chown 1000:1000 /home/alice/.zshrc") {
		t.Fatal(".zshrc must go to its owner")
	}
	if state(t, c, env) != control.Applied {
		t.Fatal("should be applied")
	}
	must(t, c.Revert(ctx, env))
	if read(t, env, "/home/alice/.zshrc") != "# my own\n" {
		t.Fatal("the old .zshrc must come back")
	}
	if _, err := os.Stat(env.Path("/home/alice/.oh-my-zsh")); err == nil {
		t.Fatal("the framework directory must go")
	}
	if env.Rec.Has(omzID) {
		t.Fatal("record must go")
	}
}

func TestOhMyZshRevertWithoutOldZshrcRemovesIt(t *testing.T) {
	ctx := context.Background()
	env, _, _ := omzEnv(t)
	c := omzControl()
	must(t, c.Apply(ctx, env, omzValues()))
	must(t, c.Revert(ctx, env))
	noFile(t, env, "/home/alice/.zshrc")
}

func TestOhMyZshRefusalsAndRollback(t *testing.T) {
	ctx := context.Background()
	env, run, _ := omzEnv(t)
	c := omzControl()

	bad := omzValues()
	bad["theme"] = []string{"../evil"}
	if err := c.Apply(ctx, env, bad); err == nil {
		t.Fatal("a theme with a path must be refused")
	}
	bad = omzValues()
	bad["plugins"] = []string{"git;rm"}
	if err := c.Apply(ctx, env, bad); err == nil {
		t.Fatal("a plugin with odd characters must be refused")
	}
	bad = omzValues()
	bad["accounts"] = []string{"ghost"}
	if err := c.Apply(ctx, env, bad); err == nil {
		t.Fatal("an unknown account must be refused")
	}
	// Nothing was downloaded for any of those.
	if run.did("fetch") {
		t.Fatal("must refuse before downloading")
	}

	// A theme the framework does not have: the directory is removed again.
	bad = omzValues()
	bad["theme"] = []string{"nosuchtheme"}
	if err := c.Apply(ctx, env, bad); err == nil {
		t.Fatal("a missing theme must fail")
	}
	if _, err := os.Stat(env.Path("/home/alice/.oh-my-zsh")); err == nil {
		t.Fatal("failed install must clean up")
	}
	noFile(t, env, "/home/alice/.zshrc")

	// A failing fetch also cleans up.
	run.fail["runuser -u alice -- env HOME=/home/alice git -C /home/alice/.oh-my-zsh fetch -q --depth 1 origin "+omzCommit] = true
	if err := c.Apply(ctx, env, omzValues()); err == nil {
		t.Fatal("a failed fetch must fail")
	}
	if _, err := os.Stat(env.Path("/home/alice/.oh-my-zsh")); err == nil {
		t.Fatal("failed fetch must clean up")
	}

	// An existing directory is never touched.
	delete(run.fail, "runuser -u alice -- env HOME=/home/alice git -C /home/alice/.oh-my-zsh fetch -q --depth 1 origin "+omzCommit)
	writeFile(t, env, "/home/alice/.oh-my-zsh/keep", "mine")
	if err := c.Apply(ctx, env, omzValues()); err == nil {
		t.Fatal("an existing directory must be refused")
	}
	if read(t, env, "/home/alice/.oh-my-zsh/keep") != "mine" {
		t.Fatal("existing directory must stay")
	}
}

func TestOhMyZshInputsAndPartial(t *testing.T) {
	ctx := context.Background()
	env, _, _ := omzEnv(t)
	c := omzControl()
	in, err := c.Inputs(ctx, env)
	must(t, err)
	if len(in) != 3 || in[0].Key != "accounts" || in[1].Validate("a/b") == nil || in[2].Validate("git sudo") != nil || in[2].Validate("x y!") == nil {
		t.Fatalf("inputs: %+v", in)
	}
	must(t, c.Apply(ctx, env, omzValues()))
	must(t, os.RemoveAll(env.Path("/home/alice/.oh-my-zsh")))
	if state(t, c, env) != control.Partial {
		t.Fatal("a missing directory is partial")
	}
}
