// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Danang Galuh Tegar Prasetyo

package controls

import (
	"context"
	"strings"
	"testing"

	"github.com/danang-id/server-hardening/internal/control"
)

func toolsControl() *basicTools { return &basicTools{control.Base{M: control.Meta{ID: toolsID}}} }

const epelRepoList = "repo id    repo name\nbaseos     AlmaLinux 10 - BaseOS\nepel       Extra Packages for Enterprise Linux 10\n"

func TestBasicToolsDefaultsWithEPEL(t *testing.T) {
	env, run, _ := sysEnv(t)
	run.out["dnf repolist --enabled -q"] = epelRepoList
	in, _ := toolsControl().Inputs(context.Background(), env)
	if got := strings.Join(in[0].DefaultMulti, ","); got != "curl,vim-enhanced,tmux,rsync,unzip,lsof,jq,bind-utils,htop" {
		t.Fatalf("ticked at first: %s", got)
	}
	if len(in[0].Options) != 12 {
		t.Fatalf("options: %d", len(in[0].Options))
	}
}

func TestBasicToolsLeavesOutEPELPackagesWithoutEPEL(t *testing.T) {
	ctx := context.Background()
	env, run, _ := sysEnv(t)
	run.out["dnf repolist --enabled -q"] = "repo id    repo name\nbaseos     AlmaLinux 10 - BaseOS\n"
	in, _ := toolsControl().Inputs(ctx, env)
	for _, o := range in[0].Options {
		if o.Value == "htop" || o.Value == "ncdu" {
			t.Fatalf("%s needs EPEL", o.Value)
		}
	}
	if len(in[0].Options) != 10 {
		t.Fatalf("options: %d", len(in[0].Options))
	}
	if err := toolsControl().Apply(ctx, env, control.Values{"packages": {"htop"}}); err == nil {
		t.Fatal("htop must be refused without EPEL")
	}
}

func TestBasicToolsInstallAndRevertNamesOnlyNewPackages(t *testing.T) {
	ctx := context.Background()
	env, run, s := sysEnv(t)
	run.out["dnf repolist --enabled -q"] = epelRepoList
	s.installed["curl"] = true // was there before
	c := toolsControl()
	if state(t, c, env) != control.NotApplied {
		t.Fatal("should start not applied")
	}
	must(t, c.Apply(ctx, env, control.Values{"packages": {"curl", "htop", "git"}}))
	if !s.installed["htop"] || !s.installed["git"] {
		t.Fatalf("installed: %v", s.installed)
	}
	if !run.did("install htop git") {
		t.Fatalf("only missing packages go to dnf: %v", run.calls)
	}
	if state(t, c, env) != control.Applied {
		t.Fatal("should be applied")
	}
	delete(s.installed, "htop")
	if state(t, c, env) != control.Partial {
		t.Fatal("a removed package is partial")
	}
	s.installed["htop"] = true

	var infos []string
	env.Log = &infoLog{infos: &infos}
	must(t, c.Revert(ctx, env))
	msg := strings.Join(infos, "\n")
	if !strings.Contains(msg, "dnf remove htop git") || strings.Contains(msg, "curl") {
		t.Fatalf("revert message: %q", msg)
	}
	if !s.installed["htop"] || !s.installed["curl"] {
		t.Fatal("packages stay installed")
	}
	if env.Rec.Has(toolsID) {
		t.Fatal("record should be gone")
	}
}

func TestBasicToolsRefusesUnknownPackage(t *testing.T) {
	env, run, _ := sysEnv(t)
	if err := toolsControl().Apply(context.Background(), env, control.Values{"packages": {"curl", "nmap-ncat"}}); err == nil {
		t.Fatal("a package outside the list must be refused")
	}
	if run.did(" install ") {
		t.Fatal("nothing may be installed after a refusal")
	}
}
