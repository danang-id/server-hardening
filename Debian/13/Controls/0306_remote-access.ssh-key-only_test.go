// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Danang Galuh Tegar Prasetyo

package controls

import (
	"context"
	"strings"
	"testing"

	"github.com/danang-id/server-hardening/internal/control"
)

func keyOnlyControl() *sshKeyOnly { return &sshKeyOnly{control.Base{M: control.Meta{ID: keyOnlyID}}} }

func TestKeyOnlyRefusesWithoutKey(t *testing.T) {
	env, run, _ := sshEnv(t)
	err := keyOnlyControl().Apply(context.Background(), env, nil)
	if err == nil || !strings.Contains(err.Error(), "lock you out") {
		t.Fatalf("error: %v", err)
	}
	noFile(t, env, sshdFile("key-only"))
	if run.did("reload") {
		t.Fatal("nothing may change")
	}
}

func TestKeyOnly(t *testing.T) {
	ctx := context.Background()
	env, _, sim := sshEnv(t)
	withKey(t, env)
	c := keyOnlyControl()
	must(t, c.Apply(ctx, env, nil))
	eff := sim.effective()
	if eff["passwordauthentication"][0] != "no" || eff["kbdinteractiveauthentication"][0] != "no" || eff["pubkeyauthentication"][0] != "yes" {
		t.Fatalf("effective: %v", eff)
	}
	if state(t, c, env) != control.Applied {
		t.Fatal("should be applied")
	}
	must(t, c.Revert(ctx, env))
	if sim.effective()["passwordauthentication"][0] != "yes" {
		t.Fatal("passwords work again")
	}
}

// A provider file such as 50-cloud-init.conf enables passwords. The drop-in is
// read first, so it wins.
func TestKeyOnlyBeatsProviderFile(t *testing.T) {
	env, _, sim := sshEnv(t)
	withKey(t, env)
	writeFile(t, env, "/etc/ssh/sshd_config.d/50-cloud-init.conf", "PasswordAuthentication yes\n")
	must(t, keyOnlyControl().Apply(context.Background(), env, nil))
	if sim.effective()["passwordauthentication"][0] != "no" {
		t.Fatal("the drop-in must win over the provider file")
	}
}

// If the main file still wins, the change is undone and the error says so.
func TestKeyOnlyUndoneWhenOverridden(t *testing.T) {
	env, _, sim := sshEnv(t)
	withKey(t, env)
	sim.mainWins = true
	writeFile(t, env, "/etc/ssh/sshd_config", "PasswordAuthentication yes\n")
	err := keyOnlyControl().Apply(context.Background(), env, nil)
	if err == nil || !strings.Contains(err.Error(), "overrides") {
		t.Fatalf("error: %v", err)
	}
	noFile(t, env, sshdFile("key-only"))
}

func TestKeyOnlyRequirements(t *testing.T) {
	c, ok := System.Get(keyOnlyID)
	if !ok {
		t.Fatal("not registered")
	}
	m := c.Meta()
	if !strings.Contains(strings.Join(m.Requires, ","), authKeyID) || !m.Has(control.TagLockout) {
		t.Fatalf("requires the key and is a lockout: %+v", m)
	}
}
