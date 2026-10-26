// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Danang Galuh Tegar Prasetyo

package controls

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/danang-id/server-hardening/internal/control"
)

func sudoControl() *sudoPolicy { return &sudoPolicy{control.Base{M: control.Meta{ID: sudoID}}} }

// sudoEnv has one administrator, alice, with a password.
func sudoEnv(t *testing.T) (*control.Env, *fakeRunner) {
	env, run := accountsEnv(t)
	writeFile(t, env, "/etc/group", "root:x:0:\nwheel:x:10:alice\nalice:x:1000:\n")
	writeFile(t, env, "/etc/shadow", "root:*:20000:0:99999:7:::\nalice:$y$alicehash:20000:0:99999:7:::\n")
	return env, run
}

func TestSudoPolicyOwnPassword(t *testing.T) {
	ctx := context.Background()
	env, run := sudoEnv(t)
	c := sudoControl()
	if state(t, c, env) != control.NotApplied {
		t.Fatal("should start not applied")
	}
	must(t, c.Apply(ctx, env, control.Values{"policy": {policyOwn}}))

	got := read(t, env, sudoFile)
	for _, want := range []string{sudoMarker, "Defaults use_pty", "Defaults timestamp_timeout=5",
		"%wheel ALL=(ALL:ALL) PASSWD: ALL"} {
		if !strings.Contains(got, want) {
			t.Errorf("policy lacks %q:\n%s", want, got)
		}
	}
	if strings.Contains(got, "NOPASSWD") || strings.Contains(got, "rootpw") {
		t.Fatalf("wrong policy written:\n%s", got)
	}
	if !run.did("visudo -cf " + env.Path(sudoTemp)) {
		t.Fatalf("the file must be checked before it is activated: %v", run.calls)
	}
	if _, err := os.Stat(env.Path(sudoTemp)); err == nil {
		t.Fatal("the temporary file must be gone")
	}
	if fi, err := os.Stat(env.Path(sudoFile)); err != nil || fi.Mode().Perm() != 0o440 {
		t.Fatalf("mode of the policy file: %v %v", fi, err)
	}
	if strings.Contains(got, "logfile") {
		t.Fatal("sudo logs to the journal, no separate log file")
	}
	if state(t, c, env) != control.Applied {
		t.Fatal("should be applied")
	}
	run.fail["visudo -c"] = true
	if state(t, c, env) != control.Partial {
		t.Fatal("a configuration that fails visudo is partial")
	}
	delete(run.fail, "visudo -c")

	must(t, c.Revert(ctx, env))
	if read(t, env, sudoFile) != "<missing>" {
		t.Fatal("policy should be gone")
	}
	if env.Rec.Has(sudoID) {
		t.Fatal("record should be gone")
	}
}

func TestSudoPolicyNoPassword(t *testing.T) {
	env, run := sudoEnv(t)
	// The administrator has no password at all. That is fine for this policy.
	writeFile(t, env, "/etc/shadow", baseShadow)
	must(t, sudoControl().Apply(context.Background(), env, control.Values{"policy": {policyNone}}))
	got := read(t, env, sudoFile)
	if !strings.Contains(got, "%wheel ALL=(ALL:ALL) NOPASSWD: ALL") || strings.Contains(got, "rootpw") {
		t.Fatalf("policy:\n%s", got)
	}
	if _, ok := run.stdin["chpasswd"]; ok {
		t.Fatal("no password work for this policy")
	}
}

func TestSudoPolicyOwnPasswordNeedsAnAdminWithAPassword(t *testing.T) {
	env, run := sudoEnv(t)
	writeFile(t, env, "/etc/shadow", baseShadow) // alice is locked
	err := sudoControl().Apply(context.Background(), env, control.Values{"policy": {policyOwn}})
	if err == nil || !strings.Contains(err.Error(), "no administrator account has a password") {
		t.Fatalf("err = %v", err)
	}
	if read(t, env, sudoFile) != "<missing>" || run.did("dnf") {
		t.Fatal("nothing may change when the policy cannot work")
	}
}

func TestSudoPolicyRootPasswordSetAndRestored(t *testing.T) {
	ctx := context.Background()
	env, run := sudoEnv(t)
	c := sudoControl()
	pw := "Qw8$e4Rt7!yU"

	must(t, c.Apply(ctx, env, control.Values{"policy": {policyRoot}, "root-password": {pw}}))
	got := read(t, env, sudoFile)
	if !strings.Contains(got, "Defaults:%wheel rootpw") || !strings.Contains(got, "PASSWD: ALL") {
		t.Fatalf("policy:\n%s", got)
	}
	if run.stdin["chpasswd"] != "root:"+pw+"\n" {
		t.Fatalf("stdin = %q", run.stdin["chpasswd"])
	}
	for _, call := range run.calls {
		if strings.Contains(call, pw) {
			t.Fatalf("the password is in a command line: %s", call)
		}
	}
	if h, _, _ := shadowHash(env, "root"); !usablePassword(h) {
		t.Fatalf("root's password was not set: %q", h)
	}
	// Running again must not record the new password field as the old one.
	must(t, c.Apply(ctx, env, control.Values{"policy": {policyRoot}, "root-password": {pw}}))

	must(t, c.Revert(ctx, env))
	if run.stdin["chpasswd -e"] != "root:*\n" {
		t.Fatalf("root's old password field was not restored: %q", run.stdin["chpasswd -e"])
	}
	if h, _, _ := shadowHash(env, "root"); h != "*" {
		t.Fatalf("root's password field after revert: %q", h)
	}
}

func TestSudoPolicyRootPasswordKeepsAnExistingPassword(t *testing.T) {
	ctx := context.Background()
	env, run := sudoEnv(t)
	writeFile(t, env, "/etc/shadow", "root:$y$roothash:20000:0:99999:7:::\nalice:$y$alicehash:20000:0:99999:7:::\n")
	c := sudoControl()
	must(t, c.Apply(ctx, env, control.Values{"policy": {policyRoot}}))
	if _, ok := run.stdin["chpasswd"]; ok {
		t.Fatal("an empty root password input must keep the current one")
	}
	must(t, c.Revert(ctx, env))
	if _, ok := run.stdin["chpasswd -e"]; ok {
		t.Fatal("root's password was not changed, so nothing to restore")
	}
}

func TestSudoPolicyRootPasswordNeedsRootToHaveOne(t *testing.T) {
	env, run := sudoEnv(t) // root is locked ("*")
	err := sudoControl().Apply(context.Background(), env, control.Values{"policy": {policyRoot}})
	if err == nil || !strings.Contains(err.Error(), "root has no usable password") {
		t.Fatalf("err = %v", err)
	}
	if read(t, env, sudoFile) != "<missing>" || run.did("dnf") {
		t.Fatal("nothing may change")
	}
}

func TestSudoPolicyIgnoresRootPasswordForOtherPolicies(t *testing.T) {
	env, run := sudoEnv(t)
	must(t, sudoControl().Apply(context.Background(), env, control.Values{"policy": {policyOwn}, "root-password": {"whatever"}}))
	if _, ok := run.stdin["chpasswd"]; ok {
		t.Fatal("root's password must only change with the root password policy")
	}
}

func TestSudoPolicySyntaxFailureChangesNothing(t *testing.T) {
	env, run := sudoEnv(t)
	run.fail["visudo -cf "+env.Path(sudoTemp)] = true
	err := sudoControl().Apply(context.Background(), env, control.Values{"policy": {policyRoot}, "root-password": {"Qw8$e4Rt7!yU"}})
	if err == nil {
		t.Fatal("a failed syntax check must fail the control")
	}
	if read(t, env, sudoFile) != "<missing>" {
		t.Fatal("the policy must not be activated")
	}
	if _, e := os.Stat(env.Path(sudoTemp)); e == nil {
		t.Fatal("the temporary file must be removed")
	}
	if _, ok := run.stdin["chpasswd"]; ok {
		t.Fatal("root's password must not change when the policy was refused")
	}
}

func TestSudoPolicyRevertPutsPolicyBackIfSudoWouldBreak(t *testing.T) {
	ctx := context.Background()
	env, run := sudoEnv(t)
	c := sudoControl()
	must(t, c.Apply(ctx, env, control.Values{"policy": {policyOwn}}))
	before := read(t, env, sudoFile)

	run.fail["visudo -c"] = true
	if err := c.Revert(ctx, env); err == nil {
		t.Fatal("revert must fail when sudo rejects its configuration")
	}
	if read(t, env, sudoFile) != before {
		t.Fatal("the policy must be put back")
	}
	if !env.Rec.Has(sudoID) {
		t.Fatal("the record must stay so the revert can be tried again")
	}
}

func TestSudoPolicyRestoresAnEarlierFile(t *testing.T) {
	ctx := context.Background()
	env, _ := sudoEnv(t)
	writeFile(t, env, sudoFile, "# my own\nDefaults env_reset\n")
	c := sudoControl()
	must(t, c.Apply(ctx, env, control.Values{"policy": {policyOwn}}))
	must(t, c.Revert(ctx, env))
	if got := read(t, env, sudoFile); got != "# my own\nDefaults env_reset\n" {
		t.Fatalf("earlier file not restored: %q", got)
	}
}

func TestSudoPolicyRejectsUnknownPolicy(t *testing.T) {
	env, run := sudoEnv(t)
	if err := sudoControl().Apply(context.Background(), env, control.Values{"policy": {"anything"}}); err == nil {
		t.Fatal("unknown policy must be refused")
	}
	if run.did("dnf") {
		t.Fatal("nothing may change")
	}
}

func TestSudoPolicyRequiresAdminUser(t *testing.T) {
	c, ok := System.Get(sudoID)
	if !ok {
		t.Fatal("not registered")
	}
	if got := c.Meta().Requires; len(got) != 1 || got[0] != adminUserID {
		t.Fatalf("requires = %v", got)
	}
}
