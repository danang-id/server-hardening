// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Danang Galuh Tegar Prasetyo

package controls

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/danang-id/server-hardening/internal/control"
)

const fakeZimfw = "# a stand-in for zimfw.zsh\n"

// zshFwEnv is zshEnv with the downloads simulated: a checkout fills the
// directory, curl writes a file with a known checksum, and the zimfw build
// writes init.zsh.
func zshFwEnv(t *testing.T) (*control.Env, *fakeRunner, *sysSim) {
	env, run, s := zshEnv(t)
	sum := sha256.Sum256([]byte(fakeZimfw))
	old := zimChecksum
	zimChecksum = hex.EncodeToString(sum[:])
	t.Cleanup(func() { zimChecksum = old })
	prev := run.hook
	run.hook = func(f *fakeRunner, cmd string) {
		prev(f, cmd)
		if f.fail[cmd] {
			return
		}
		fields := strings.Fields(cmd)
		switch {
		case strings.HasSuffix(cmd, "checkout -q FETCH_HEAD") && strings.Contains(cmd, "/.oh-my-zsh "):
			dir := env.Path("/home/alice/.oh-my-zsh")
			for _, p := range []string{"oh-my-zsh.sh", "themes/robbyrussell.zsh-theme", "themes/agnoster.zsh-theme", "plugins/git/git.plugin.zsh", "plugins/sudo/sudo.plugin.zsh"} {
				must(t, os.MkdirAll(filepath.Dir(filepath.Join(dir, p)), 0o755))
				must(t, os.WriteFile(filepath.Join(dir, p), []byte("x"), 0o644))
			}
		case strings.HasSuffix(cmd, "checkout -q FETCH_HEAD") && strings.Contains(cmd, "/.zim/modules/"):
			for i, w := range fields {
				if w == "-C" {
					must(t, os.MkdirAll(env.Path(fields[i+1]), 0o755))
					must(t, os.WriteFile(filepath.Join(env.Path(fields[i+1]), "init.zsh"), []byte("x"), 0o644))
				}
			}
		case strings.Contains(cmd, " curl "):
			for i, w := range fields {
				if w == "-o" {
					must(t, os.MkdirAll(filepath.Dir(env.Path(fields[i+1])), 0o755))
					must(t, os.WriteFile(env.Path(fields[i+1]), []byte(fakeZimfw), 0o644))
				}
			}
		case strings.Contains(cmd, " zsh /home/alice/.zim/zimfw.zsh build"):
			must(t, os.WriteFile(env.Path("/home/alice/.zim/init.zsh"), []byte("x"), 0o644))
		}
	}
	return env, run, s
}

func fwValues(framework string) control.Values {
	return control.Values{"accounts": {"alice"}, "framework": {framework}, "theme": {"agnoster"}, "plugins": {"git sudo"}}
}

func noDir(t *testing.T, env *control.Env, p string) {
	t.Helper()
	if _, err := os.Stat(env.Path(p)); err == nil {
		t.Fatalf("%s must not exist", p)
	}
}

func TestZshAsksForAFrameworkAndItsDetails(t *testing.T) {
	env, _, _ := zshFwEnv(t)
	in, err := zshControl().Inputs(context.Background(), env)
	must(t, err)
	var keys []string
	for _, i := range in {
		keys = append(keys, i.Key)
	}
	if strings.Join(keys, ",") != "accounts,framework,theme,plugins" {
		t.Fatalf("questions: %v", keys)
	}
	fw := in[1]
	if fw.Kind != control.Choice || fw.Default != "none" || optionValues(fw) != "none,oh-my-zsh,zimfw" {
		t.Fatalf("framework question: default %q, options %s", fw.Default, optionValues(fw))
	}
	// The theme and the plugins belong to Oh My Zsh alone.
	for _, i := range in[2:] {
		for name, want := range map[string]bool{"none": false, "oh-my-zsh": true, "zimfw": false} {
			if got := i.ShownFor(control.Values{"framework": {name}}); got != want {
				t.Fatalf("%s with %s: shown %v", i.Key, name, got)
			}
		}
	}
	if in[2].Validate("a/b") == nil || in[3].Validate("git sudo") != nil || in[3].Validate("x y!") == nil {
		t.Fatal("theme and plugin names are checked")
	}
	reg, ok := System.Get(zshID)
	if !ok || !slices.Contains(reg.Meta().Tags, control.TagExternal) {
		t.Fatal("the control can download code, so it carries the external tag")
	}
}

func TestZshWithoutAFrameworkDownloadsNothing(t *testing.T) {
	for _, v := range []string{"none", ""} {
		ctx := context.Background()
		env, run, s := zshFwEnv(t)
		in := fwValues(v)
		if v == "" {
			delete(in, "framework")
		}
		must(t, zshControl().Apply(ctx, env, in))
		if s.installed["git"] || s.installed["curl"] || run.did("fetch") || run.did("curl") {
			t.Fatalf("framework %q: nothing may be downloaded", v)
		}
		noDir(t, env, "/home/alice/.oh-my-zsh")
		noDir(t, env, "/home/alice/.zim")
	}
}

func TestZshInstallsOhMyZshPinnedAsTheUser(t *testing.T) {
	ctx := context.Background()
	env, run, s := zshFwEnv(t)
	c := zshControl()
	writeFile(t, env, "/home/alice/.zshrc", "# my own\n")
	must(t, c.Apply(ctx, env, fwValues("oh-my-zsh")))
	if !s.installed["git"] || !s.installed["zsh"] {
		t.Fatal("zsh and git must be installed")
	}
	if shellOf(t, env, "alice") != zshPath {
		t.Fatal("the login shell is changed as well")
	}
	if !run.did("runuser -u alice -- env HOME=/home/alice git -C /home/alice/.oh-my-zsh fetch -q --depth 1 origin " + omzCommit) {
		t.Fatalf("pinned fetch missing: %v", run.calls)
	}
	rc := read(t, env, "/home/alice/.zshrc")
	for _, w := range []string{managed(zshID), `ZSH_THEME="agnoster"`, "plugins=(git sudo)", "source $ZSH/oh-my-zsh.sh"} {
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
	noDir(t, env, "/home/alice/.oh-my-zsh")
	if shellOf(t, env, "alice") != "/bin/bash" || env.Rec.Has(zshID) {
		t.Fatal("the shell and the record go back")
	}
}

func TestZshRevertWithoutOldZshrcRemovesIt(t *testing.T) {
	ctx := context.Background()
	env, _, _ := zshFwEnv(t)
	c := zshControl()
	must(t, c.Apply(ctx, env, fwValues("oh-my-zsh")))
	must(t, c.Revert(ctx, env))
	noFile(t, env, "/home/alice/.zshrc")
}

func TestOhMyZshRefusalsAndRollback(t *testing.T) {
	ctx := context.Background()
	env, run, _ := zshFwEnv(t)
	c := zshControl()
	fetch := "runuser -u alice -- env HOME=/home/alice git -C /home/alice/.oh-my-zsh fetch -q --depth 1 origin " + omzCommit

	bad := fwValues("oh-my-zsh")
	bad["theme"] = []string{"../evil"}
	if err := c.Apply(ctx, env, bad); err == nil {
		t.Fatal("a theme with a path must be refused")
	}
	bad = fwValues("oh-my-zsh")
	bad["plugins"] = []string{"git;rm"}
	if err := c.Apply(ctx, env, bad); err == nil {
		t.Fatal("a plugin with odd characters must be refused")
	}
	bad = fwValues("oh-my-zsh")
	bad["accounts"] = []string{"ghost"}
	if err := c.Apply(ctx, env, bad); err == nil {
		t.Fatal("an unknown account must be refused")
	}
	if err := c.Apply(ctx, env, fwValues("no-such-framework")); err == nil {
		t.Fatal("an unknown framework must be refused")
	}
	if run.did("fetch") || run.did("usermod") {
		t.Fatal("must refuse before changing or downloading anything")
	}

	// A theme the framework does not have: the directory is removed again.
	bad = fwValues("oh-my-zsh")
	bad["theme"] = []string{"nosuchtheme"}
	if err := c.Apply(ctx, env, bad); err == nil {
		t.Fatal("a missing theme must fail")
	}
	noDir(t, env, "/home/alice/.oh-my-zsh")
	noFile(t, env, "/home/alice/.zshrc")
	// The failed install shows as partial, so the next run repairs it.
	if state(t, c, env) != control.Partial {
		t.Fatal("a failed install is partial")
	}

	// A failing fetch also cleans up, and a good run afterwards repairs it.
	run.fail[fetch] = true
	if err := c.Apply(ctx, env, fwValues("oh-my-zsh")); err == nil {
		t.Fatal("a failed fetch must fail")
	}
	noDir(t, env, "/home/alice/.oh-my-zsh")
	delete(run.fail, fetch)
	must(t, c.Apply(ctx, env, fwValues("oh-my-zsh")))
	if state(t, c, env) != control.Applied {
		t.Fatal("the next run repairs it")
	}
}

func TestZshNeverTouchesAFrameworkDirectoryItDidNotMake(t *testing.T) {
	ctx := context.Background()
	for dir, name := range map[string]string{"/home/alice/.oh-my-zsh": "oh-my-zsh", "/home/alice/.zim": "zimfw"} {
		env, run, _ := zshFwEnv(t)
		writeFile(t, env, dir+"/keep", "mine")
		if err := zshControl().Apply(ctx, env, fwValues(name)); err == nil {
			t.Fatalf("%s: an existing directory must be refused", dir)
		}
		if read(t, env, dir+"/keep") != "mine" {
			t.Fatalf("%s must stay", dir)
		}
		if run.did("usermod") || run.did("fetch") {
			t.Fatalf("%s: refuse before any change", dir)
		}
	}
	env, _, _ := zshFwEnv(t)
	writeFile(t, env, "/home/alice/.zimrc", "mine")
	if err := zshControl().Apply(ctx, env, fwValues("zimfw")); err == nil {
		t.Fatal("an existing .zimrc must be refused")
	}
}

func TestZshRepairsAFrameworkThatWasDamaged(t *testing.T) {
	ctx := context.Background()
	env, _, _ := zshFwEnv(t)
	c := zshControl()
	must(t, c.Apply(ctx, env, fwValues("oh-my-zsh")))
	must(t, os.RemoveAll(env.Path("/home/alice/.oh-my-zsh")))
	if state(t, c, env) != control.Partial {
		t.Fatal("a missing directory is partial")
	}
	must(t, c.Apply(ctx, env, fwValues("oh-my-zsh")))
	if state(t, c, env) != control.Applied {
		t.Fatal("applying again repairs it")
	}
}

func TestZshOffersOneFrameworkPerAccount(t *testing.T) {
	ctx := context.Background()
	env, _, _ := zshFwEnv(t)
	c := zshControl()
	must(t, c.Apply(ctx, env, fwValues("oh-my-zsh")))
	if err := c.Apply(ctx, env, fwValues("zimfw")); err == nil {
		t.Fatal("a second framework in the same account must be refused")
	}
	noDir(t, env, "/home/alice/.zim")
	// Choosing none later leaves the first one alone.
	must(t, c.Apply(ctx, env, fwValues("none")))
	if state(t, c, env) != control.Applied {
		t.Fatal("none changes nothing")
	}
}

func TestZshInstallsZimWithPinnedFilesAndRevertsIt(t *testing.T) {
	ctx := context.Background()
	env, run, s := zshFwEnv(t)
	c := zshControl()
	writeFile(t, env, "/home/alice/.zshrc", "# my own\n")
	must(t, c.Apply(ctx, env, fwValues("zimfw")))
	if !s.installed["git"] || !s.installed["curl"] {
		t.Fatal("git and curl must be installed")
	}
	user := "runuser -u alice -- env HOME=/home/alice "
	if !run.did(user + "curl --proto =https --tlsv1.2 -fsSL -o /home/alice/.zim/zimfw.zsh " + zimURL) {
		t.Fatalf("download missing: %v", run.calls)
	}
	if !strings.Contains(zimURL, zimVersion) || strings.Contains(zimURL, "latest") {
		t.Fatalf("the download must name one version: %s", zimURL)
	}
	for _, m := range zimModules {
		if !run.did(user + "git -C /home/alice/.zim/modules/" + m.name + " fetch -q --depth 1 origin " + m.commit) {
			t.Fatalf("module %s not fetched at its commit", m.name)
		}
		if len(m.commit) != 40 {
			t.Fatalf("module %s is not pinned to a full commit", m.name)
		}
	}
	if zimModules[len(zimModules)-1].name != "completion" {
		t.Fatal("the completion module comes last")
	}
	if !run.did(user + "ZIM_HOME=/home/alice/.zim zsh /home/alice/.zim/zimfw.zsh build") {
		t.Fatalf("build missing: %v", run.calls)
	}
	rcs := read(t, env, "/home/alice/.zimrc")
	if !strings.Contains(rcs, "zmodule environment\n") || !strings.Contains(rcs, "zmodule completion\n") {
		t.Fatalf(".zimrc:\n%s", rcs)
	}
	rc := read(t, env, "/home/alice/.zshrc")
	for _, w := range []string{managed(zshID), "ZIM_HOME=${HOME}/.zim", "source ${ZIM_HOME}/init.zsh"} {
		if !strings.Contains(rc, w) {
			t.Fatalf("missing %q in\n%s", w, rc)
		}
	}
	for _, f := range []string{"/home/alice/.zimrc", "/home/alice/.zshrc"} {
		if !run.did("chown 1000:1000 " + f) {
			t.Fatalf("%s must go to its owner", f)
		}
	}
	if state(t, c, env) != control.Applied {
		t.Fatal("should be applied")
	}
	must(t, c.Revert(ctx, env))
	if read(t, env, "/home/alice/.zshrc") != "# my own\n" {
		t.Fatal("the old .zshrc must come back")
	}
	noDir(t, env, "/home/alice/.zim")
	noFile(t, env, "/home/alice/.zimrc")
	if env.Rec.Has(zshID) {
		t.Fatal("record must go")
	}
}

func TestZshRefusesAZimfwFileWithTheWrongChecksum(t *testing.T) {
	ctx := context.Background()
	env, run, _ := zshFwEnv(t)
	c := zshControl()
	zimChecksum = strings.Repeat("0", 64)
	err := c.Apply(ctx, env, fwValues("zimfw"))
	if err == nil || !strings.Contains(err.Error(), "checksum") {
		t.Fatalf("a changed file must be refused: %v", err)
	}
	noDir(t, env, "/home/alice/.zim")
	noFile(t, env, "/home/alice/.zimrc")
	noFile(t, env, "/home/alice/.zshrc")
	if run.did("zimfw.zsh build") || run.did("fetch") {
		t.Fatal("nothing runs from a file that failed the check")
	}
}

func TestZshCleansUpAFailedZimBuildAndRepairsIt(t *testing.T) {
	ctx := context.Background()
	env, run, _ := zshFwEnv(t)
	c := zshControl()
	build := "runuser -u alice -- env HOME=/home/alice ZIM_HOME=/home/alice/.zim zsh /home/alice/.zim/zimfw.zsh build"
	run.fail[build] = true
	if err := c.Apply(ctx, env, fwValues("zimfw")); err == nil {
		t.Fatal("a failed build must fail")
	}
	noDir(t, env, "/home/alice/.zim")
	noFile(t, env, "/home/alice/.zimrc")
	if state(t, c, env) != control.Partial {
		t.Fatal("a failed install is partial")
	}
	delete(run.fail, build)
	must(t, c.Apply(ctx, env, fwValues("zimfw")))
	if state(t, c, env) != control.Applied {
		t.Fatal("the next run repairs it")
	}
	must(t, os.Remove(env.Path("/home/alice/.zim/init.zsh")))
	if state(t, c, env) != control.Partial {
		t.Fatal("a missing init script is partial")
	}
}
