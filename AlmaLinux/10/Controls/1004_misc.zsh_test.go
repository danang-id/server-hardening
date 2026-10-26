// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Danang Galuh Tegar Prasetyo

package controls

import (
	"context"
	"strings"
	"testing"

	"github.com/danang-id/server-hardening/internal/control"
)

func zshControl() *zsh { return &zsh{control.Base{M: control.Meta{ID: zshID}}} }

// zshEnv has accounts, /etc/shells, and a usermod that edits /etc/passwd.
func zshEnv(t *testing.T) (*control.Env, *fakeRunner, *sysSim) {
	env, run, s := sysEnv(t)
	writeFile(t, env, "/etc/passwd", basePasswd+"daemon:x:1:1::/usr/sbin:/usr/sbin/nologin\n")
	writeFile(t, env, "/etc/group", baseGroup)
	writeFile(t, env, "/etc/shells", "/bin/sh\n/bin/bash\n/usr/bin/zsh\n")
	prev := run.hook
	run.hook = func(f *fakeRunner, cmd string) {
		prev(f, cmd)
		fields := strings.Fields(cmd)
		if len(fields) == 4 && fields[0] == "usermod" && fields[1] == "-s" {
			var out []string
			for l := range strings.SplitSeq(strings.TrimRight(read(t, env, "/etc/passwd"), "\n"), "\n") {
				p := strings.Split(l, ":")
				if p[0] == fields[3] && !f.fail[cmd] {
					p[6] = fields[2]
				}
				out = append(out, strings.Join(p, ":"))
			}
			writeFile(t, env, "/etc/passwd", strings.Join(out, "\n")+"\n")
		}
	}
	return env, run, s
}

func shellOf(t *testing.T, env *control.Env, u string) string {
	a, ok, err := findAccount(env, u)
	must(t, err)
	if !ok {
		t.Fatalf("no account %s", u)
	}
	return a.Shell
}

func TestZshOffersLoginAccountsOnly(t *testing.T) {
	env, _, _ := zshEnv(t)
	in, _ := zshControl().Inputs(context.Background(), env)
	var names []string
	for _, o := range in[0].Options {
		names = append(names, o.Value)
	}
	if strings.Join(names, ",") != "root,alice" {
		t.Fatalf("offered: %v", names)
	}
	for _, d := range in[0].DefaultMulti {
		if d == "root" {
			t.Fatal("root is not ticked at first")
		}
	}
}

func TestZshInstallChangeAndRevert(t *testing.T) {
	ctx := context.Background()
	env, _, s := zshEnv(t)
	c := zshControl()
	if state(t, c, env) != control.NotApplied {
		t.Fatal("should start not applied")
	}
	must(t, c.Apply(ctx, env, control.Values{"accounts": {"alice"}}))
	if !s.installed["zsh"] || shellOf(t, env, "alice") != zshPath {
		t.Fatalf("zsh %v, shell %s", s.installed["zsh"], shellOf(t, env, "alice"))
	}
	if shellOf(t, env, "root") != "/bin/bash" {
		t.Fatal("root was not chosen")
	}
	if state(t, c, env) != control.Applied {
		t.Fatal("should be applied")
	}
	// A second run adds root and keeps the first record of alice's shell.
	must(t, c.Apply(ctx, env, control.Values{"accounts": {"alice", "root"}}))
	must(t, c.Revert(ctx, env))
	if shellOf(t, env, "alice") != "/bin/bash" || shellOf(t, env, "root") != "/bin/bash" {
		t.Fatalf("shells: %s %s", shellOf(t, env, "alice"), shellOf(t, env, "root"))
	}
	if !s.installed["zsh"] || env.Rec.Has(zshID) {
		t.Fatal("package stays, record goes")
	}
}

func TestZshFailureRollsBackAndRefusals(t *testing.T) {
	env, run, _ := zshEnv(t)
	c := zshControl()
	run.fail["usermod -s /usr/bin/zsh root"] = true
	if err := c.Apply(context.Background(), env, control.Values{"accounts": {"alice", "root"}}); err == nil {
		t.Fatal("expected an error")
	}
	if shellOf(t, env, "alice") != "/bin/bash" {
		t.Fatal("alice must be put back")
	}
	if err := c.Apply(context.Background(), env, control.Values{"accounts": {"ghost"}}); err == nil {
		t.Fatal("an unknown account must be refused")
	}
	writeFile(t, env, "/etc/shells", "/bin/sh\n/bin/bash\n")
	if err := c.Apply(context.Background(), env, control.Values{"accounts": {"alice"}}); err == nil {
		t.Fatal("zsh missing from /etc/shells must be refused")
	}
}
