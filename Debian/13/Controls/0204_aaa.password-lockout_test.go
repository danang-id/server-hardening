// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Danang Galuh Tegar Prasetyo

package controls

import (
	"context"
	"strings"
	"testing"

	"github.com/danang-id/server-hardening/internal/control"
)

func lockControl() *passwordLockout {
	return &passwordLockout{control.Base{M: control.Meta{ID: lockID}}}
}

const debianFaillockConf = "# Debian's file\n# deny = 3\n# unlock_time = 600\ndir = /var/lib/faillock\ndeny = 3\n"

func TestPasswordLockoutRoundTrip(t *testing.T) {
	ctx := context.Background()
	env, run := accountsEnv(t)
	writeFile(t, env, lockConf, debianFaillockConf)
	c := lockControl()
	if state(t, c, env) != control.NotApplied {
		t.Fatal("should start not applied")
	}

	must(t, c.Apply(ctx, env, control.Values{"attempts": {"4"}, "minutes": {"20"}}))
	got := read(t, env, lockConf)
	for _, want := range []string{lockMarker, "deny = 4", "fail_interval = 1200", "unlock_time = 1200", "dir = /var/lib/faillock", "# deny = 3"} {
		if !strings.Contains(got, want) {
			t.Errorf("faillock.conf lacks %q:\n%s", want, got)
		}
	}
	if strings.Contains(got, "deny = 3\n") && !strings.Contains(got, "# deny = 3") {
		t.Fatalf("old active setting must be replaced:\n%s", got)
	}
	if strings.Count(got, "\ndeny = ") != 1 {
		t.Fatalf("exactly one active deny line:\n%s", got)
	}
	if strings.Contains(got, "\neven_deny_root") {
		t.Fatalf("root must not be locked:\n%s", got)
	}
	if !strings.Contains(read(t, env, lockProfileDir+lockProfileMain), "pam_faillock.so authfail") ||
		!strings.Contains(read(t, env, lockProfileDir+lockProfilePre), "pam_faillock.so preauth") {
		t.Fatal("PAM profiles missing")
	}
	if !run.did("pam-auth-update --package --enable") {
		t.Fatalf("calls: %v", run.calls)
	}
	if state(t, c, env) != control.Applied {
		t.Fatal("should be applied")
	}

	must(t, c.Revert(ctx, env))
	if read(t, env, lockConf) != debianFaillockConf {
		t.Fatalf("faillock.conf not restored:\n%s", read(t, env, lockConf))
	}
	for _, n := range []string{lockProfilePre, lockProfileMain} {
		if read(t, env, lockProfileDir+n) != "<missing>" {
			t.Fatalf("profile %s should be gone", n)
		}
	}
	if !run.did("pam-auth-update --package --remove") {
		t.Fatal("the module must come out of the stack")
	}
	if read(t, env, lockPAM) != basePAMAuth {
		t.Fatalf("common-auth after revert:\n%s", read(t, env, lockPAM))
	}
	if env.Rec.Has(lockID) {
		t.Fatal("record should be gone")
	}
}

func TestPasswordLockoutRemovesAFileThatDidNotExist(t *testing.T) {
	ctx := context.Background()
	env, _ := accountsEnv(t)
	c := lockControl()
	must(t, c.Apply(ctx, env, control.Values{"attempts": {"5"}, "minutes": {"15"}}))
	if !strings.Contains(read(t, env, lockConf), "deny = 5") {
		t.Fatal("conf not written")
	}
	must(t, c.Revert(ctx, env))
	if read(t, env, lockConf) != "<missing>" {
		t.Fatal("a file that did not exist before must be removed again")
	}
}

func TestPasswordLockoutRefusesWhenAddedByHand(t *testing.T) {
	env, run := accountsEnv(t)
	appendLine(t, env, lockPAM, "auth\trequired\tpam_faillock.so preauth")
	err := lockControl().Apply(context.Background(), env, control.Values{"attempts": {"5"}, "minutes": {"15"}})
	if err == nil || !strings.Contains(err.Error(), "already in") {
		t.Fatalf("err = %v", err)
	}
	if run.did("pam-auth-update") || read(t, env, lockConf) != "<missing>" {
		t.Fatal("nothing may change")
	}
}

func TestPasswordLockoutReapply(t *testing.T) {
	ctx := context.Background()
	env, _ := accountsEnv(t)
	c := lockControl()
	must(t, c.Apply(ctx, env, control.Values{"attempts": {"5"}, "minutes": {"15"}}))
	must(t, c.Apply(ctx, env, control.Values{"attempts": {"3"}, "minutes": {"30"}}))
	got := read(t, env, lockConf)
	if !strings.Contains(got, "deny = 3") || strings.Contains(got, "deny = 5") || strings.Count(got, lockMarker) != 1 {
		t.Fatalf("second run should replace the values:\n%s", got)
	}
	must(t, c.Revert(ctx, env))
	if read(t, env, lockConf) != "<missing>" {
		t.Fatal("revert must go back to the very first state")
	}
}

func TestPasswordLockoutRollsBackWhenPAMUpdateFails(t *testing.T) {
	env, run := accountsEnv(t)
	writeFile(t, env, lockConf, debianFaillockConf)
	run.fail["pam-auth-update --package --enable "+lockProfilePre+" "+lockProfileMain] = true
	err := lockControl().Apply(context.Background(), env, control.Values{"attempts": {"5"}, "minutes": {"15"}})
	if err == nil {
		t.Fatal("must fail")
	}
	if read(t, env, lockConf) != debianFaillockConf {
		t.Fatal("faillock.conf must be put back")
	}
	for _, n := range []string{lockProfilePre, lockProfileMain} {
		if read(t, env, lockProfileDir+n) != "<missing>" {
			t.Fatalf("profile %s must be removed again", n)
		}
	}
}

func TestPasswordLockoutRejectsBadInput(t *testing.T) {
	env, run := accountsEnv(t)
	c := lockControl()
	for _, v := range []control.Values{
		{"attempts": {"0"}, "minutes": {"15"}},
		{"attempts": {"100"}, "minutes": {"15"}},
		{"attempts": {"x"}, "minutes": {"15"}},
		{"attempts": {"5"}, "minutes": {"0"}},
		{"attempts": {"5"}, "minutes": {"1441"}},
		{"attempts": {""}, "minutes": {""}},
	} {
		if err := c.Apply(context.Background(), env, v); err == nil {
			t.Errorf("%v should be refused", v)
		}
	}
	if run.did("pam-auth-update") || read(t, env, lockConf) != "<missing>" {
		t.Fatal("a refused request must change nothing")
	}
}

func TestPasswordLockoutCheckStates(t *testing.T) {
	env, _ := accountsEnv(t)
	c := lockControl()
	writeFile(t, env, lockConf, lockConfContent("", 5, 15))
	if state(t, c, env) != control.Partial {
		t.Fatal("rules without the module in the stack are partial")
	}
	appendLine(t, env, lockPAM, "auth\trequired\tpam_faillock.so preauth")
	if state(t, c, env) != control.Applied {
		t.Fatal("rules and module: applied")
	}
	writeFile(t, env, lockConf, "deny = 5\n")
	if state(t, c, env) != control.NotApplied {
		t.Fatal("somebody else's rules are not this control")
	}
}

func TestPasswordLockoutIsALockoutControl(t *testing.T) {
	c, ok := System.Get(lockID)
	if !ok || !c.Meta().Has(control.TagLockout) {
		t.Fatal("must be registered with the lockout tag")
	}
}

func TestPasswordLockoutConfContentIsStable(t *testing.T) {
	a := lockConfContent("", 5, 15)
	b := lockConfContent(a, 5, 15)
	if a != b {
		t.Fatalf("applying twice must give the same file:\n%s\n---\n%s", a, b)
	}
}
