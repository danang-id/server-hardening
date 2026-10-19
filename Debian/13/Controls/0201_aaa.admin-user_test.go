// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Danang Galuh Tegar Prasetyo

package controls

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/danang-id/server-hardening/internal/control"
)

func adminControl() *adminUser { return &adminUser{control.Base{M: control.Meta{ID: adminUserID}}} }

func TestAdminUserCreatesAccountWithPassword(t *testing.T) {
	ctx := context.Background()
	env, run := accountsEnv(t)
	run.out["dpkg-query -W -f=${Status} sudo"] = "install ok installed"
	// alice is in no group, so the only admin is the new one.
	c := adminControl()
	if state(t, c, env) != control.NotApplied {
		t.Fatal("no admin yet")
	}
	pw := "Zq9!x7Lm2#pW"
	must(t, c.Apply(ctx, env, control.Values{"username": {"dan"}, "password": {pw}}))

	if !run.did("useradd --create-home --shell /bin/bash --groups sudo dan") {
		t.Fatalf("calls: %v", run.calls)
	}
	if got := run.stdin["chpasswd"]; got != "dan:"+pw+"\n" {
		t.Fatalf("chpasswd stdin = %q", got)
	}
	for _, c := range run.calls {
		if strings.Contains(c, pw) {
			t.Fatalf("the password is in a command line: %s", c)
		}
	}
	if u, _, _ := env.Rec.Get(adminUserID, "user"); u != "dan" {
		t.Fatalf("recorded user = %q", u)
	}
	if state(t, c, env) != control.Applied {
		t.Fatal("should be applied")
	}
	if h, _, _ := shadowHash(env, "dan"); !usablePassword(h) {
		t.Fatalf("password not set: %q", h)
	}
}

func TestAdminUserHomeIsPrivate(t *testing.T) {
	env, _ := accountsEnv(t)
	c := adminControl()
	must(t, c.Apply(context.Background(), env, control.Values{"username": {"dan"}}))
	if fi, err := os.Stat(env.Path("/home/dan")); err != nil || fi.Mode().Perm() != 0o700 {
		t.Fatalf("home directory: %v %v", fi, err)
	}
	// An account that already exists keeps the mode its home directory has.
	must(t, os.MkdirAll(env.Path("/home/alice"), 0o755))
	must(t, os.Chmod(env.Path("/home/alice"), 0o755))
	must(t, c.Apply(context.Background(), env, control.Values{"username": {"alice"}}))
	if fi, _ := os.Stat(env.Path("/home/alice")); fi.Mode().Perm() != 0o755 {
		t.Fatalf("an existing home directory must not be touched: %v", fi.Mode().Perm())
	}
}

func TestAdminUserEmptyPasswordLocksNewAccount(t *testing.T) {
	env, run := accountsEnv(t)
	c := adminControl()
	must(t, c.Apply(context.Background(), env, control.Values{"username": {"dan"}}))
	if _, ok := run.stdin["chpasswd"]; ok {
		t.Fatal("no password was given, chpasswd must not run")
	}
	if h, _, _ := shadowHash(env, "dan"); usablePassword(h) {
		t.Fatalf("account should be locked, hash %q", h)
	}
}

func TestAdminUserExistingAccount(t *testing.T) {
	ctx := context.Background()
	env, run := accountsEnv(t)
	c := adminControl()

	// Exists, not in the sudo group: only added to the group, password untouched.
	must(t, c.Apply(ctx, env, control.Values{"username": {"alice"}}))
	if run.did("useradd") {
		t.Fatal("must not create an existing account")
	}
	if !run.did("usermod -aG sudo alice") {
		t.Fatalf("calls: %v", run.calls)
	}
	if _, ok := run.stdin["chpasswd"]; ok {
		t.Fatal("empty password on an existing account must leave it alone")
	}
	if h, _, _ := shadowHash(env, "alice"); h != "!" {
		t.Fatalf("password changed: %q", h)
	}

	// Already in the group: nothing to do but record it.
	run.calls = nil
	must(t, c.Apply(ctx, env, control.Values{"username": {"alice"}}))
	if run.did("usermod") || run.did("useradd") {
		t.Fatalf("calls: %v", run.calls)
	}
}

func TestAdminUserRefusesBadNames(t *testing.T) {
	ctx := context.Background()
	env, run := accountsEnv(t)
	c := adminControl()
	for _, n := range []string{"", "root", "Dan", "1dan", "da n", "dan:x", strings.Repeat("a", 33), "dan;rm"} {
		if err := c.Apply(ctx, env, control.Values{"username": {n}}); err == nil {
			t.Errorf("name %q should be refused", n)
		}
	}
	if err := c.Apply(ctx, env, control.Values{"username": {"www-data"}}); err == nil || !strings.Contains(err.Error(), "system account") {
		t.Errorf("system account should be refused, got %v", err)
	}
	if err := c.Apply(ctx, env, control.Values{"username": {"dan"}, "password": {"a\nb"}}); err == nil {
		t.Error("a password with a line break should be refused")
	}
	if run.did("useradd") || run.did("usermod") || run.did("apt-get") {
		t.Fatalf("a refused request must change nothing: %v", run.calls)
	}
}

func TestAdminUserPasswordFailureIsReported(t *testing.T) {
	env, run := accountsEnv(t)
	run.fail["chpasswd"] = true
	err := adminControl().Apply(context.Background(), env, control.Values{"username": {"dan"}, "password": {"x"}})
	if err == nil {
		t.Fatal("a failing chpasswd must fail the control")
	}
	if strings.Contains(err.Error(), "x\n") {
		t.Fatal("error must not echo the password")
	}
}

func TestAdminUserInputsSuggestTheInvokingUser(t *testing.T) {
	env, _ := accountsEnv(t)
	c := adminControl()
	for sudoUser, want := range map[string]string{"alice": "alice", "root": "", "": "", "Bad Name": ""} {
		t.Setenv("SUDO_USER", sudoUser)
		in, err := c.Inputs(context.Background(), env)
		must(t, err)
		if in[0].Default != want {
			t.Errorf("SUDO_USER=%q: default %q, want %q", sudoUser, in[0].Default, want)
		}
	}
	in, _ := c.Inputs(context.Background(), env)
	if in[1].Kind != control.Secret || !in[1].Confirm || !in[1].Optional {
		t.Fatalf("password input must be a hidden, confirmed, optional secret: %+v", in[1])
	}
}

func TestAdminUserCheckCountsOnlyNormalSudoMembers(t *testing.T) {
	env, _ := accountsEnv(t)
	c := adminControl()
	writeFile(t, env, "/etc/group", "root:x:0:\nsudo:x:27:daemon,ghost\n")
	if state(t, c, env) != control.NotApplied {
		t.Fatal("system accounts and unknown names are not administrators")
	}
	writeFile(t, env, "/etc/group", "root:x:0:\nsudo:x:27:alice\n")
	if state(t, c, env) != control.Applied {
		t.Fatal("alice is an administrator")
	}
}

func TestAdminUserCannotBeReverted(t *testing.T) {
	c := adminControl()
	env, _ := accountsEnv(t)
	if err := c.Revert(context.Background(), env); !errors.Is(err, control.ErrNoRevert) {
		t.Fatalf("revert = %v", err)
	}
}
