// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Danang Galuh Tegar Prasetyo

package controls

import (
	"context"
	"strings"
	"testing"

	"github.com/danang-id/server-hardening/internal/control"
)

func portsControl() *openPorts { return &openPorts{control.Base{M: control.Meta{ID: portsID}}} }

func rulesIn(text string) control.Values { return control.Values{"rules": {text}} }

func TestParsePortRule(t *testing.T) {
	good := map[string]portRule{
		"443":                           {"443", "tcp", ""},
		"443/tcp":                       {"443", "tcp", ""},
		"51820/udp from 203.0.113.0/24": {"51820", "udp", "203.0.113.0/24"},
		"8000-8010/tcp":                 {"8000-8010", "tcp", ""},
		"5432 from 2001:db8::/32":       {"5432", "tcp", "2001:db8::/32"},
		"22/tcp from 198.51.100.7":      {"22", "tcp", "198.51.100.7"},
	}
	for in, want := range good {
		got, err := parsePortRule(in)
		if err != nil || got != want {
			t.Errorf("%q: %+v %v", in, got, err)
		}
	}
	for _, bad := range []string{"", "0", "65536", "abc", "80/icmp", "8010-8000", "80 from", "80 from nowhere", "80 to 1.2.3.4", "80/tcp from 1.2.3.4 extra", "-5"} {
		if _, err := parsePortRule(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	rs, err := parsePortRules("# web\n443/tcp\n\n443\n80\n")
	if err != nil || len(rs) != 2 {
		t.Fatalf("duplicates and comments: %v %v", rs, err)
	}
}

func applyFW(t *testing.T, env *control.Env, engine string) {
	t.Helper()
	must(t, fwControl().Apply(context.Background(), env, engineIn(engine)))
}

func TestOpenPortsNftables(t *testing.T) {
	ctx := context.Background()
	env, _, _, fw := fwEnv(t)
	applyFW(t, env, "nftables")
	c := portsControl()
	must(t, c.Apply(ctx, env, rulesIn("443/tcp\n51820/udp from 203.0.113.0/24\n5432 from 2001:db8::/32")))
	got := read(t, env, nftFile)
	wantContains(t, got, "tcp dport 443 accept", "ip saddr 203.0.113.0/24 udp dport 51820 accept",
		"ip6 saddr 2001:db8::/32 tcp dport 5432 accept", "tcp dport { 22 } accept")
	if !strings.Contains(fw.nftLoadedText, "tcp dport 443 accept") {
		t.Fatal("the rules must be loaded")
	}
	if state(t, c, env) != control.Applied {
		t.Fatal("should be applied")
	}

	// A second run with fewer rules closes the others.
	must(t, c.Apply(ctx, env, rulesIn("443/tcp")))
	got = read(t, env, nftFile)
	if strings.Contains(got, "51820") || !strings.Contains(got, "dport 443") {
		t.Fatalf("rules:\n%s", got)
	}

	must(t, c.Revert(ctx, env))
	if strings.Contains(read(t, env, nftFile), "443") || !strings.Contains(read(t, env, nftFile), "dport { 22 }") {
		t.Fatalf("only SSH stays:\n%s", read(t, env, nftFile))
	}
	if env.Rec.Has(portsID) {
		t.Fatal("record should be gone")
	}
}

func TestOpenPortsNothingBeyondSSH(t *testing.T) {
	env, _, _, _ := fwEnv(t)
	applyFW(t, env, "nftables")
	must(t, portsControl().Apply(context.Background(), env, control.Values{}))
	if strings.Contains(read(t, env, nftFile), "443") {
		t.Fatal("no extra rule")
	}
	if st := state(t, portsControl(), env); st != control.Applied {
		t.Fatalf("state %v", st)
	}
}

func TestOpenPortsNftablesRefusedKeepsOldRules(t *testing.T) {
	ctx := context.Background()
	env, _, _, fw := fwEnv(t)
	applyFW(t, env, "nftables")
	c := portsControl()
	must(t, c.Apply(ctx, env, rulesIn("443")))
	fw.nftBad = true
	if err := c.Apply(ctx, env, rulesIn("443\n8080")); err == nil {
		t.Fatal("expected an error")
	}
	if strings.Contains(read(t, env, nftFile), "8080") {
		t.Fatal("the refused rule must not be in the file")
	}
	if v, _, _ := env.Rec.Get(portsID, "rules"); v != "443/tcp" {
		t.Fatalf("recorded rules %q", v)
	}
}

func TestOpenPortsUFW(t *testing.T) {
	ctx := context.Background()
	env, run, _, fw := fwEnv(t)
	applyFW(t, env, "ufw")
	c := portsControl()
	must(t, c.Apply(ctx, env, rulesIn("443/tcp\n51820/udp from 203.0.113.0/24\n8000-8010/tcp")))
	if !run.did("ufw allow 443/tcp") || !run.did("ufw allow from 203.0.113.0/24 to any port 51820 proto udp") ||
		!run.did("ufw allow 8000:8010/tcp") {
		t.Fatalf("calls: %v", run.calls)
	}
	if state(t, c, env) != control.Applied {
		t.Fatalf("state %v", state(t, c, env))
	}
	must(t, c.Apply(ctx, env, rulesIn("443/tcp")))
	if !run.did("ufw delete allow 8000:8010/tcp") {
		t.Fatalf("a rule that is not wanted any more must go: %v", run.calls)
	}
	must(t, c.Revert(ctx, env))
	if got := strings.Join(fw.ufwRules, "|"); strings.Contains(got, "443") || !strings.Contains(got, "22/tcp") {
		t.Fatalf("ufw rules after the revert: %s", got)
	}
}

func TestOpenPortsFirewalld(t *testing.T) {
	ctx := context.Background()
	env, _, _, fw := fwEnv(t)
	firewalldPoll.tries, firewalldPoll.every = 2, 0
	applyFW(t, env, "firewalld")
	c := portsControl()
	must(t, c.Apply(ctx, env, rulesIn("443/tcp\n51820/udp from 203.0.113.0/24")))
	if got := strings.Join(fw.fwdPorts, " "); !strings.Contains(got, "443/tcp") {
		t.Fatalf("ports %v", fw.fwdPorts)
	}
	if len(fw.fwdRich) != 1 || !strings.Contains(fw.fwdRich[0], `source address="203.0.113.0/24" port port="51820" protocol="udp" accept`) {
		t.Fatalf("rich rules %v", fw.fwdRich)
	}
	must(t, c.Revert(ctx, env))
	if len(fw.fwdRich) != 0 || strings.Contains(strings.Join(fw.fwdPorts, " "), "443") {
		t.Fatalf("rules left: %v %v", fw.fwdPorts, fw.fwdRich)
	}
}

func TestOpenPortsNeedsFirewall(t *testing.T) {
	env, _, _, _ := fwEnv(t)
	err := portsControl().Apply(context.Background(), env, rulesIn("443"))
	if err == nil || !strings.Contains(err.Error(), fwID) {
		t.Fatalf("error: %v", err)
	}
}

func TestOpenPortsBadRuleChangesNothing(t *testing.T) {
	env, run, _, _ := fwEnv(t)
	applyFW(t, env, "ufw")
	run.calls = nil
	if err := portsControl().Apply(context.Background(), env, rulesIn("443\nnonsense")); err == nil {
		t.Fatal("bad rule accepted")
	}
	if run.did("ufw allow") {
		t.Fatalf("nothing may be opened: %v", run.calls)
	}
}

func TestOpenPortsInputsListWhatListens(t *testing.T) {
	ctx := context.Background()
	env, _, ssh, _ := fwEnv(t)
	ssh.lntup = []string{
		`tcp LISTEN 0 511 0.0.0.0:443 0.0.0.0:* users:(("nginx",pid=2,fd=6))`,
		`tcp LISTEN 0 511 [::]:443 [::]:* users:(("nginx",pid=2,fd=7))`,
		`tcp LISTEN 0 244 127.0.0.1:5432 0.0.0.0:* users:(("postgres",pid=3,fd=5))`,
		`tcp LISTEN 0 4096 127.0.0.53%lo:53 0.0.0.0:*`,
		`udp UNCONN 0 0 0.0.0.0:51820 0.0.0.0:*`,
		`tcp LISTEN 0 128 [::1]:631 [::]:*`,
	}
	ins, _ := portsControl().Inputs(ctx, env)
	if len(ins) != 2 || ins[0].Key != "listening" || ins[0].Kind != control.MultiChoice {
		t.Fatalf("inputs: %+v", ins)
	}
	var vals []string
	for _, o := range ins[0].Options {
		vals = append(vals, o.Value+"="+o.Label)
	}
	got := strings.Join(vals, "|")
	if got != "443/tcp=443/tcp (nginx)|51820/udp=51820/udp" {
		t.Fatalf("options: %s", got)
	}
	if len(ins[0].DefaultMulti) != 0 {
		t.Fatal("nothing is open by default")
	}
	if ins[1].Key != "rules" || ins[1].Validate("nonsense") == nil || ins[1].Validate("443") != nil {
		t.Fatal("the free text must be validated")
	}
}

func TestOpenPortsChosenFromList(t *testing.T) {
	env, _, _, _ := fwEnv(t)
	applyFW(t, env, "nftables")
	in := control.Values{"listening": {"443/tcp", "51820/udp"}, "rules": {"8080"}}
	must(t, portsControl().Apply(context.Background(), env, in))
	wantContains(t, read(t, env, nftFile), "tcp dport 443 accept", "udp dport 51820 accept", "tcp dport 8080 accept")
}

func TestOpenPortsRevertAfterFirewallRevert(t *testing.T) {
	ctx := context.Background()
	env, _, _, _ := fwEnv(t)
	applyFW(t, env, "nftables")
	must(t, portsControl().Apply(ctx, env, rulesIn("443")))
	must(t, fwControl().Revert(ctx, env))
	must(t, portsControl().Revert(ctx, env)) // must not fail: the firewall is gone
	if env.Rec.Has(portsID) {
		t.Fatal("record should be gone")
	}
}

func TestOpenPortsRequiresFirewall(t *testing.T) {
	c, _ := System.Get(portsID)
	if got := strings.Join(c.Meta().Requires, ","); got != fwID {
		t.Fatalf("requires %q", got)
	}
}
