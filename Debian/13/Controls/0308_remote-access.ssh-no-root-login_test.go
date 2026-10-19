// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Danang Galuh Tegar Prasetyo

package controls

import (
	"context"
	"strings"
	"testing"

	"github.com/danang-id/server-hardening/internal/control"
)

func noRootControl() *sshNoRootLogin {
	return &sshNoRootLogin{control.Base{M: control.Meta{ID: noRootID}}}
}

func TestNoRootLogin(t *testing.T) {
	ctx := context.Background()
	env, _, sim := sshEnv(t)
	withKey(t, env)
	c := noRootControl()
	must(t, c.Apply(ctx, env, nil))
	if sim.effective()["permitrootlogin"][0] != "no" {
		t.Fatal("root login must be off")
	}
	if state(t, c, env) != control.Applied {
		t.Fatal("should be applied")
	}
	must(t, c.Revert(ctx, env))
	if sim.effective()["permitrootlogin"][0] != "without-password" {
		t.Fatal("the default is back")
	}
}

func TestNoRootLoginRefusals(t *testing.T) {
	ctx := context.Background()
	t.Run("no key", func(t *testing.T) {
		env, run, _ := sshEnv(t)
		err := noRootControl().Apply(ctx, env, nil)
		if err == nil || !strings.Contains(err.Error(), "alice has no SSH key") {
			t.Fatalf("error: %v", err)
		}
		noFile(t, env, sshdFile("no-root-login"))
		if run.did("reload") {
			t.Fatal("nothing may change")
		}
	})
	t.Run("no sudo", func(t *testing.T) {
		env, _, _ := sshEnv(t)
		withKey(t, env)
		must(t, removeIfExists(env, "/usr/bin/sudo"))
		err := noRootControl().Apply(ctx, env, nil)
		if err == nil || !strings.Contains(err.Error(), "sudo is not installed") {
			t.Fatalf("error: %v", err)
		}
	})
	t.Run("sudo policy needs a password the admin lacks", func(t *testing.T) {
		env, _, _ := sshEnv(t)
		withKey(t, env)
		writeFile(t, env, "/etc/shadow", baseShadow) // alice has "!"
		must(t, env.Rec.Put(sudoID, "policy", policyOwn))
		err := noRootControl().Apply(ctx, env, nil)
		if err == nil || !strings.Contains(err.Error(), "no password") {
			t.Fatalf("error: %v", err)
		}
	})
	t.Run("no administrator", func(t *testing.T) {
		env, _, _ := sshEnv(t)
		writeFile(t, env, "/etc/group", baseGroup)
		err := noRootControl().Apply(ctx, env, nil)
		if err == nil || !strings.Contains(err.Error(), "no administrator account") {
			t.Fatalf("error: %v", err)
		}
	})
}

func TestNoRootLoginPicksTheReadyAdmin(t *testing.T) {
	env, _, _ := sshEnv(t)
	// bob has a key and sudo, alice has neither a key nor a password.
	writeFile(t, env, "/etc/passwd", basePasswd+"bob:x:1002:1002::/home/bob:/bin/bash\n")
	writeFile(t, env, "/etc/group", "root:x:0:\nsudo:x:27:alice,bob\nalice:x:1000:\n")
	writeFile(t, env, "/home/bob/.ssh/authorized_keys", ed25519Key(4, "bob")+"\n")
	must(t, noRootControl().Apply(context.Background(), env, nil))
}

func TestAdminCanSudoPolicies(t *testing.T) {
	env, _, _ := sshEnv(t)
	if err := adminCanSudo(env, "alice"); err != nil {
		t.Fatal(err)
	}
	if err := adminCanSudo(env, "nobody"); err == nil {
		t.Error("a user outside the sudo group cannot use sudo")
	}
	must(t, env.Rec.Put(sudoID, "policy", policyRoot))
	if err := adminCanSudo(env, "alice"); err == nil {
		t.Error("the root policy needs a password for root, which is locked here")
	}
	writeFile(t, env, "/etc/shadow", "root:$y$roothash:20000:0:99999:7:::\nalice:!:20000:0:99999:7:::\n")
	if err := adminCanSudo(env, "alice"); err != nil {
		t.Errorf("root has a password now: %v", err)
	}
	must(t, env.Rec.Put(sudoID, "policy", policyNone))
	if err := adminCanSudo(env, "alice"); err != nil {
		t.Errorf("no password needed: %v", err)
	}
}
