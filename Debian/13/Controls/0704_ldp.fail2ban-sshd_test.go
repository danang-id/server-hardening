// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Danang Galuh Tegar Prasetyo

package controls

import (
	"context"
	"strings"
	"testing"

	"github.com/danang-id/server-hardening/internal/control"
)

func f2bControl() *fail2banSSHD { return &fail2banSSHD{control.Base{M: control.Meta{ID: f2bID}}} }

func f2bEnv(t *testing.T, engine string) (*control.Env, *fakeRunner, *sysSim) {
	env, run, s := sysEnv(t)
	must(t, env.Rec.Put(fwID, "engine", engine))
	run.out["ss -H -ltnp"] = "LISTEN 0 128 0.0.0.0:2299 0.0.0.0:* users:((\"sshd\",pid=1,fd=3))\n"
	t.Setenv("SSH_CONNECTION", "")
	return env, run, s
}

var f2bValues = control.Values{"maxretry": {"4"}, "findtime": {"15m"}, "bantime": {"2h"}, "ignore": {"198.51.100.7 10.0.0.0/8"}}

func TestFail2banJailPerEngine(t *testing.T) {
	for engine, action := range map[string]string{"nftables": "nftables", "ufw": "ufw", "firewalld": "firewallcmd-rich-rules"} {
		env, _, s := f2bEnv(t, engine)
		must(t, f2bControl().Apply(context.Background(), env, f2bValues))
		wantContains(t, read(t, env, f2bFile), managed(f2bID), "[sshd]", "enabled = true", "backend = systemd",
			"banaction = "+action, "port = 2299", "maxretry = 4", "findtime = 15m", "bantime = 2h",
			"ignoreip = 127.0.0.1/8 ::1 198.51.100.7 10.0.0.0/8")
		if !s.installed["fail2ban"] || !s.installed["python3-systemd"] || !s.enabled[f2bUnit] || !s.active[f2bUnit] {
			t.Fatalf("%s: package or service state: %v %v", engine, s.installed, s.enabled)
		}
	}
}

func TestFail2banCheckApplyRevert(t *testing.T) {
	ctx := context.Background()
	env, run, s := f2bEnv(t, "nftables")
	c := f2bControl()
	if state(t, c, env) != control.NotApplied {
		t.Fatal("should start not applied")
	}
	must(t, c.Apply(ctx, env, f2bValues))
	if !run.did("fail2ban-client -t") {
		t.Fatal("the configuration must be tested")
	}
	if state(t, c, env) != control.Applied {
		t.Fatal("should be applied")
	}
	run.fail["fail2ban-client status sshd"] = true
	if state(t, c, env) != control.Partial {
		t.Fatal("a jail that is not running is partial")
	}
	delete(run.fail, "fail2ban-client status sshd")

	run.calls = nil
	must(t, c.Revert(ctx, env))
	noFile(t, env, f2bFile)
	if !run.did("fail2ban-client unban --all") || !run.did("fail2ban-client reload") {
		t.Fatalf("bans must be lifted and the service reloaded: %v", run.calls)
	}
	if s.enabled[f2bUnit] || s.active[f2bUnit] {
		t.Fatal("the service was off before")
	}
	if env.Rec.Has(f2bID) {
		t.Fatal("record should be gone")
	}
}

func TestFail2banRejectsInvalidConfigurationAndRestores(t *testing.T) {
	env, run, _ := f2bEnv(t, "nftables")
	run.fail["fail2ban-client -t"] = true
	run.out["fail2ban-client -t"] = "ERROR unknown action"
	err := f2bControl().Apply(context.Background(), env, f2bValues)
	if err == nil || !strings.Contains(err.Error(), "unknown action") {
		t.Fatalf("want the tool's message, got %v", err)
	}
	noFile(t, env, f2bFile)
}

func TestFail2banJailThatNeverStartsIsUndone(t *testing.T) {
	env, run, _ := f2bEnv(t, "nftables")
	run.fail["fail2ban-client status sshd"] = true
	if err := f2bControl().Apply(context.Background(), env, f2bValues); err == nil {
		t.Fatal("expected an error")
	}
	noFile(t, env, f2bFile)
}

func TestFail2banNeedsFirewallControl(t *testing.T) {
	env, _, _ := sysEnv(t)
	if err := f2bControl().Apply(context.Background(), env, f2bValues); err == nil {
		t.Fatal("without network.firewall there is no ban method")
	}
}

func TestFail2banRejectsBadValues(t *testing.T) {
	env, _, _ := f2bEnv(t, "nftables")
	c := f2bControl()
	for name, v := range map[string]control.Values{
		"retry":  {"maxretry": {"0"}, "findtime": {"10m"}, "bantime": {"1h"}},
		"time":   {"maxretry": {"5"}, "findtime": {"soon"}, "bantime": {"1h"}},
		"ignore": {"maxretry": {"5"}, "findtime": {"10m"}, "bantime": {"1h"}, "ignore": {"not-an-ip"}},
		"inject": {"maxretry": {"5"}, "findtime": {"10m"}, "bantime": {"1h\nenabled = false"}},
	} {
		if err := c.Apply(context.Background(), env, v); err == nil {
			t.Fatalf("%s must be refused", name)
		}
	}
	noFile(t, env, f2bFile)
}

func TestFail2banDefaultIgnoreIsSessionAddress(t *testing.T) {
	ctx := context.Background()
	env, run, _ := f2bEnv(t, "nftables")
	t.Setenv("SSH_CONNECTION", "198.51.100.7 51234 203.0.113.5 2299")
	in, _ := f2bControl().Inputs(ctx, env)
	if in[3].Key != "ignore" || in[3].Default != "198.51.100.7" {
		t.Fatalf("default: %+v", in[3])
	}

	// Under sudo the variable is gone: use the established SSH connection.
	t.Setenv("SSH_CONNECTION", "")
	run.out["ss -H -tn state established"] = "0 0 203.0.113.5:2299 198.51.100.9:50000\n0 0 203.0.113.5:443 192.0.2.1:40000\n"
	in, _ = f2bControl().Inputs(ctx, env)
	if in[3].Default != "198.51.100.9" {
		t.Fatalf("default from connections: %q", in[3].Default)
	}

	// Two people connected: do not guess.
	run.out["ss -H -tn state established"] = "0 0 203.0.113.5:2299 198.51.100.9:50000\n0 0 203.0.113.5:2299 192.0.2.8:50001\n"
	in, _ = f2bControl().Inputs(ctx, env)
	if in[3].Default != "" {
		t.Fatalf("two clients must give no default: %q", in[3].Default)
	}
}
