// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Danang Galuh Tegar Prasetyo

package controls

import (
	"context"
	"strings"
	"testing"

	"github.com/danang-id/server-hardening/internal/control"
)

func logControl() *firewallLogDenied {
	return &firewallLogDenied{control.Base{M: control.Meta{ID: fwLogID}}}
}

func TestLogDeniedNftables(t *testing.T) {
	ctx := context.Background()
	env, _, _, fw := fwEnv(t)
	applyFW(t, env, "nftables")
	must(t, portsControl().Apply(ctx, env, rulesIn("443")))
	c := logControl()
	ins, _ := c.Inputs(ctx, env)
	if ins[0].Key != "rate" || ins[0].Default != "5/minute" || ins[0].Validate("lots") == nil || ins[0].Validate("10/second") != nil {
		t.Fatalf("input: %+v", ins[0])
	}
	must(t, c.Apply(ctx, env, control.Values{"rate": {"10/minute"}}))
	got := read(t, env, nftFile)
	wantContains(t, got, `limit rate 10/minute log prefix "server-hardening drop: "`)
	// The logging rule is the last rule of the chain, after every accept rule, so it only sees packets that are dropped.
	if strings.Index(got, "log prefix") < strings.Index(got, "dport 443 accept") || strings.Index(got, "log prefix") < strings.Index(got, "dport { 22 }") {
		t.Fatalf("the log rule must come last:\n%s", got)
	}
	if !strings.Contains(fw.nftLoadedText, "log prefix") || state(t, c, env) != control.Applied {
		t.Fatal("should be applied")
	}
	must(t, c.Revert(ctx, env))
	if strings.Contains(read(t, env, nftFile), "log prefix") || !strings.Contains(read(t, env, nftFile), "dport 443") {
		t.Fatalf("the log rule goes, the others stay:\n%s", read(t, env, nftFile))
	}
}

func TestLogDeniedNftablesBadRate(t *testing.T) {
	env, _, _, _ := fwEnv(t)
	applyFW(t, env, "nftables")
	if err := logControl().Apply(context.Background(), env, control.Values{"rate": {"loud"}}); err == nil {
		t.Fatal("bad rate accepted")
	}
	if env.Rec.Has(fwLogID) {
		t.Fatal("no record after a refusal")
	}
}

func TestLogDeniedNftablesRefusedRules(t *testing.T) {
	env, _, _, fw := fwEnv(t)
	applyFW(t, env, "nftables")
	fw.nftBad = true
	if err := logControl().Apply(context.Background(), env, control.Values{"rate": {"5/minute"}}); err == nil {
		t.Fatal("expected an error")
	}
	if env.Rec.Has(fwLogID) || strings.Contains(read(t, env, nftFile), "log prefix") {
		t.Fatal("nothing may change")
	}
}

func TestLogDeniedFirewalld(t *testing.T) {
	ctx := context.Background()
	env, _, _, fw := fwEnv(t)
	applyFW(t, env, "firewalld")
	c := logControl()
	ins, _ := c.Inputs(ctx, env)
	if ins[0].Key != "mode" || ins[0].Default != "unicast" {
		t.Fatalf("input: %+v", ins[0])
	}
	must(t, c.Apply(ctx, env, control.Values{"mode": {"unicast"}}))
	if fw.fwdLog != "unicast" || state(t, c, env) != control.Applied {
		t.Fatalf("log-denied %q", fw.fwdLog)
	}
	must(t, c.Revert(ctx, env))
	if fw.fwdLog != "off" {
		t.Fatalf("log-denied %q after the revert", fw.fwdLog)
	}
}

func TestLogDeniedNeedsFirewall(t *testing.T) {
	env, _, _, _ := fwEnv(t)
	c := logControl()
	ins, err := c.Inputs(context.Background(), env)
	if err != nil || ins != nil {
		t.Fatalf("no inputs without a firewall: %v %v", ins, err)
	}
	if err := c.Apply(context.Background(), env, control.Values{"rate": {"5/minute"}}); err == nil || !strings.Contains(err.Error(), fwID) {
		t.Fatalf("error: %v", err)
	}
}

func TestLogDeniedMeta(t *testing.T) {
	c, _ := System.Get(fwLogID)
	m := c.Meta()
	if m.Default || strings.Join(m.Requires, ",") != fwID {
		t.Fatalf("meta: %+v", m)
	}
}
