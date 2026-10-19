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

func TestBasicToolsDefaults(t *testing.T) {
	env, _, _ := sysEnv(t)
	in, _ := toolsControl().Inputs(context.Background(), env)
	if got := strings.Join(in[0].DefaultMulti, ","); got != "curl,vim,htop,tmux,rsync,unzip,lsof,jq,bind9-dnsutils" {
		t.Fatalf("ticked at first: %s", got)
	}
	if len(in[0].Options) != 13 {
		t.Fatalf("options: %d", len(in[0].Options))
	}
}

func TestBasicToolsInstallAndRevertNamesOnlyNewPackages(t *testing.T) {
	ctx := context.Background()
	env, run, s := sysEnv(t)
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
		t.Fatalf("only missing packages go to apt: %v", run.calls)
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
	if !strings.Contains(msg, "apt-get purge htop git") || strings.Contains(msg, "curl") {
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
	if err := toolsControl().Apply(context.Background(), env, control.Values{"packages": {"curl", "netcat-traditional"}}); err == nil {
		t.Fatal("a package outside the list must be refused")
	}
	if run.did(" install ") {
		t.Fatal("nothing may be installed after a refusal")
	}
}
