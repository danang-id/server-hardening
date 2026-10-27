// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Danang Galuh Tegar Prasetyo

package controls

import (
	"context"
	"strings"
	"testing"

	"github.com/danang-id/server-hardening/internal/control"
)

func cryptoControl() *cryptoPolicy {
	return &cryptoPolicy{control.Base{M: control.Meta{ID: cryptoPolicyID}}}
}

// cryptoEnv simulates update-crypto-policies, which keeps one policy name.
func cryptoEnv(t *testing.T, policy string) (*control.Env, *fakeRunner, *sysSim, *string) {
	env, run, s := sysEnv(t)
	cur := policy
	prev := run.hook
	run.hook = func(f *fakeRunner, cmd string) {
		prev(f, cmd)
		switch {
		case cmd == "update-crypto-policies --show":
			f.out[cmd] = cur + "\n"
		case strings.HasPrefix(cmd, "update-crypto-policies --set ") && !f.fail[cmd]:
			cur = strings.TrimPrefix(cmd, "update-crypto-policies --set ")
		}
	}
	s.active["sshd"] = true
	return env, run, s, &cur
}

func TestCryptoPolicyApplyAndRevert(t *testing.T) {
	ctx := context.Background()
	env, run, s, cur := cryptoEnv(t, "DEFAULT")
	c := cryptoControl()
	if state(t, c, env) != control.NotApplied {
		t.Fatal("should start not applied")
	}
	must(t, c.Apply(ctx, env, control.Values{"policy": {"DEFAULT:NO-SHA1"}}))
	if *cur != "DEFAULT:NO-SHA1" {
		t.Fatalf("policy: %s", *cur)
	}
	if !s.installed["crypto-policies-scripts"] {
		t.Fatal("the tool must be installed")
	}
	if !run.did("sshd -t") || !run.did("systemctl reload sshd") {
		t.Fatalf("sshd must check and reload: %v", run.calls)
	}
	if state(t, c, env) != control.Applied {
		t.Fatal("should be applied")
	}

	// Somebody switches the policy by hand: no longer applied.
	*cur = "LEGACY"
	if state(t, c, env) != control.Partial {
		t.Fatal("a policy changed by hand is partial")
	}
	*cur = "DEFAULT:NO-SHA1"
	run.fail["update-crypto-policies --check"] = true
	if state(t, c, env) != control.Partial {
		t.Fatal("generated files that do not match the policy are partial")
	}
	run.fail["update-crypto-policies --check"] = false

	must(t, c.Revert(ctx, env))
	if *cur != "DEFAULT" {
		t.Fatalf("the old policy must come back: %s", *cur)
	}
	if env.Rec.Has(cryptoPolicyID) {
		t.Fatal("record should be gone")
	}
}

func TestCryptoPolicyKeepsFirstPolicyOnRerun(t *testing.T) {
	ctx := context.Background()
	env, _, _, cur := cryptoEnv(t, "DEFAULT")
	c := cryptoControl()
	must(t, c.Apply(ctx, env, control.Values{"policy": {"DEFAULT:NO-SHA1"}}))
	must(t, c.Apply(ctx, env, control.Values{"policy": {"FUTURE"}}))
	must(t, c.Revert(ctx, env))
	if *cur != "DEFAULT" {
		t.Fatalf("revert must go back to the policy from before the first run: %s", *cur)
	}
}

func TestCryptoPolicyRefusesFIPS(t *testing.T) {
	env, run, _, cur := cryptoEnv(t, "FIPS")
	err := cryptoControl().Apply(context.Background(), env, control.Values{"policy": {"FUTURE"}})
	if err == nil || !strings.Contains(err.Error(), "FIPS") {
		t.Fatalf("expected a FIPS refusal: %v", err)
	}
	if *cur != "FIPS" || run.did("--set") {
		t.Fatal("nothing may change in FIPS mode")
	}
	if env.Rec.Has(cryptoPolicyID) {
		t.Fatal("no record for a refused change")
	}
}

func TestCryptoPolicyRejectsBadNames(t *testing.T) {
	env, run, _, _ := cryptoEnv(t, "DEFAULT")
	for _, p := range []string{"", "default", "FUTURE; reboot", "DEFAULT:", "A B"} {
		if err := cryptoControl().Apply(context.Background(), env, control.Values{"policy": {p}}); err == nil {
			t.Fatalf("%q must be refused", p)
		}
	}
	if run.did("--set") {
		t.Fatal("nothing may be set")
	}
}

func TestCryptoPolicyUndoneWhenSSHDRefuses(t *testing.T) {
	env, run, _, cur := cryptoEnv(t, "DEFAULT")
	run.fail["sshd -t"] = true
	err := cryptoControl().Apply(context.Background(), env, control.Values{"policy": {"FUTURE"}})
	if err == nil {
		t.Fatal("expected an error")
	}
	if *cur != "DEFAULT" {
		t.Fatalf("the old policy must be back: %s", *cur)
	}
	if env.Rec.Has(cryptoPolicyID) {
		t.Fatal("a failed first run leaves no record")
	}
}

func TestCryptoPolicyFailedSetLeavesNoSetting(t *testing.T) {
	env, run, _, cur := cryptoEnv(t, "DEFAULT")
	run.fail["update-crypto-policies --set FUTURE"] = true
	if err := cryptoControl().Apply(context.Background(), env, control.Values{"policy": {"FUTURE"}}); err == nil {
		t.Fatal("expected an error")
	}
	if *cur != "DEFAULT" {
		t.Fatalf("policy: %s", *cur)
	}
}

// Under FUTURE dnf refused a mirror whose certificate has a 2048-bit RSA key,
// and every later dnf step of the run failed. The control now puts the old
// policy back when dnf stops working.
func TestCryptoPolicyUndoneWhenDnfCannotReachItsMirror(t *testing.T) {
	env, run, _, cur := cryptoEnv(t, "DEFAULT")
	prev := run.hook
	run.hook = func(f *fakeRunner, cmd string) {
		prev(f, cmd)
		if cmd == "dnf -y makecache --refresh" {
			f.fail[cmd] = *cur == "FUTURE"
		}
	}
	c := cryptoControl()
	err := c.Apply(context.Background(), env, control.Values{"policy": {"FUTURE"}})
	if err == nil || !strings.Contains(err.Error(), "dnf can no longer read its repositories") {
		t.Fatalf("want a message about dnf, got %v", err)
	}
	if *cur != "DEFAULT" {
		t.Fatalf("the old policy must be back: %s", *cur)
	}
	if env.Rec.Has(cryptoPolicyID) {
		t.Fatal("a refused change must leave no record")
	}
	if run.did("systemctl reload sshd") {
		t.Fatal("sshd must not be reloaded for a policy that was undone")
	}
	// A milder policy keeps working.
	must(t, c.Apply(context.Background(), env, control.Values{"policy": {"DEFAULT:NO-SHA1"}}))
	if *cur != "DEFAULT:NO-SHA1" {
		t.Fatalf("policy: %s", *cur)
	}
}

// If dnf did not work before the change either, the policy is not to blame and
// the change stays.
func TestCryptoPolicyKeptWhenDnfWasAlreadyBroken(t *testing.T) {
	env, run, _, cur := cryptoEnv(t, "DEFAULT")
	run.fail["dnf -y makecache --refresh"] = true
	must(t, cryptoControl().Apply(context.Background(), env, control.Values{"policy": {"FUTURE"}}))
	if *cur != "FUTURE" {
		t.Fatalf("policy: %s", *cur)
	}
}
