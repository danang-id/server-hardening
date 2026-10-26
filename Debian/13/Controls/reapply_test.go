// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Danang Galuh Tegar Prasetyo

package controls

import (
	"context"
	"os"
	"testing"

	"github.com/danang-id/server-hardening/internal/control"
)

// A control that reports Partial has work left, and the engine runs it again
// when the user picks it. These tests break an applied control, check that it
// reports Partial, apply it again, and check that it is whole and still reverts
// to what was there before the first run.

func reapply(t *testing.T, c control.Control, env *control.Env, in control.Values) {
	t.Helper()
	must(t, c.Apply(context.Background(), env, in))
	if st := state(t, c, env); st != control.Applied {
		t.Fatalf("applying again must finish the control: state %d", st)
	}
}

func TestUmaskReapplyAfterLoginDefsChanged(t *testing.T) {
	ctx := context.Background()
	env := umaskEnv(t)
	c := umaskControl()
	in := control.Values{"umask": {"027"}}
	must(t, c.Apply(ctx, env, in))
	writeFile(t, env, loginDefs, stockDefs)
	if state(t, c, env) != control.Partial {
		t.Fatal("a changed login.defs is partial")
	}
	reapply(t, c, env, in)
	must(t, c.Revert(ctx, env))
	if read(t, env, loginDefs) != stockDefs || read(t, env, pamSession) != stockSession {
		t.Fatal("revert must still restore what was there before the first run")
	}
}

func TestAuditdReapplyAfterConfigChanged(t *testing.T) {
	ctx := context.Background()
	env, _, _ := sysEnv(t)
	writeFile(t, env, auditdConf, stockAuditd)
	c := auditdControl()
	in := control.Values{"size": {"50"}, "files": {"7"}}
	must(t, c.Apply(ctx, env, in))
	writeFile(t, env, auditdConf, stockAuditd)
	if state(t, c, env) != control.Partial {
		t.Fatal("a changed configuration is partial")
	}
	reapply(t, c, env, in)
	must(t, c.Revert(ctx, env))
	if read(t, env, auditdConf) != stockAuditd {
		t.Fatalf("revert must restore the original: %q", read(t, env, auditdConf))
	}
}

func TestModulesReapplyAfterARuleIsLost(t *testing.T) {
	ctx := context.Background()
	env, _, _ := sysEnv(t)
	c := modulesControl()
	in := control.Values{"modules": {"sctp", "dccp"}}
	must(t, c.Apply(ctx, env, in))
	writeFile(t, env, modulesFile, managed(modulesID)+"\nblacklist dccp\n")
	if state(t, c, env) != control.Partial {
		t.Fatal("a file that lost a rule is partial")
	}
	reapply(t, c, env, in)
	must(t, c.Revert(ctx, env))
	noFile(t, env, modulesFile)
}

func TestImmutableReapplyAfterAFlagIsCleared(t *testing.T) {
	ctx := context.Background()
	env, _, flagged := immutableEnv(t)
	c := immutableControl()
	f1, f2 := "/etc/sysctl.d/99-server-hardening-kernel.conf", "/etc/sysctl.d/10-other.conf"
	in := control.Values{"files": {f1}, "extra": {f2}}
	must(t, c.Apply(ctx, env, in))
	flagged[f2] = false
	if state(t, c, env) != control.Partial {
		t.Fatal("a file that lost its flag is partial")
	}
	reapply(t, c, env, in)
	if !flagged[f1] || !flagged[f2] {
		t.Fatalf("both files must be locked again: %v", flagged)
	}
	must(t, c.Revert(ctx, env))
	if flagged[f1] || flagged[f2] {
		t.Fatalf("revert: %v", flagged)
	}
}

func TestBasicToolsReapplyAfterAPackageIsRemoved(t *testing.T) {
	ctx := context.Background()
	env, _, s := sysEnv(t)
	c := toolsControl()
	in := control.Values{"packages": {"htop", "git"}}
	must(t, c.Apply(ctx, env, in))
	delete(s.installed, "htop")
	if state(t, c, env) != control.Partial {
		t.Fatal("a removed package is partial")
	}
	reapply(t, c, env, in)
	if !s.installed["htop"] {
		t.Fatal("htop must be installed again")
	}
	must(t, c.Revert(ctx, env))
}

func TestNotifyReapplyAfterTheConfigIsGone(t *testing.T) {
	ctx := context.Background()
	env, _, _ := sysEnv(t)
	c := notifyControl()
	in := notifyValues("https://x.example/", "", "no")
	must(t, c.Apply(ctx, env, in))
	must(t, os.Remove(env.Path(notifyConf)))
	if state(t, c, env) != control.Partial {
		t.Fatal("a missing config is partial")
	}
	reapply(t, c, env, in)
	must(t, c.Revert(ctx, env))
}

func TestBannerReapplyAfterTheFileIsGone(t *testing.T) {
	ctx := context.Background()
	env, _, _ := sshEnv(t)
	c := bannerControl()
	in := control.Values{"text": {"Notice"}}
	must(t, c.Apply(ctx, env, in))
	must(t, os.Remove(env.Path(bannerFile)))
	if state(t, c, env) != control.Partial {
		t.Fatal("a setting without its file is partial")
	}
	reapply(t, c, env, in)
	must(t, c.Revert(ctx, env))
}

// Docker, or another program, switches a kernel setting back. Applying again
// must set it again, and revert must still bring back the value from before the
// first run, not the one that the control wrote.
func TestSysctlReapplyKeepsTheOriginalValues(t *testing.T) {
	ctx := context.Background()
	env, _, k := sysctlEnv(t, map[string]string{"net.ipv4.ip_forward": "1", "net.ipv6.conf.all.forwarding": "1"})
	c := forwardControl()
	must(t, c.Apply(ctx, env, nil))
	k.running["net.ipv4.ip_forward"] = "1"
	if state(t, c, env) != control.Partial {
		t.Fatal("a kernel that disagrees with the file is partial")
	}
	reapply(t, c, env, nil)
	if k.get("net.ipv4.ip_forward") != "0" {
		t.Fatalf("the setting must be applied again: %v", k.running)
	}
	must(t, c.Revert(ctx, env))
	if k.get("net.ipv4.ip_forward") != "1" || k.get("net.ipv6.conf.all.forwarding") != "1" {
		t.Fatalf("the values from before the first run must come back: %v", k.running)
	}
}
