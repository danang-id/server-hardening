// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Danang Galuh Tegar Prasetyo

package controls

import (
	"context"
	"strings"
	"testing"

	"github.com/danang-id/server-hardening/internal/control"
)

func allowControl() *sshAllowUsers {
	return &sshAllowUsers{control.Base{M: control.Meta{ID: allowUsersID}}}
}

func TestAllowUsersEmptyMeansAdmin(t *testing.T) {
	ctx := context.Background()
	env, _, sim := sshEnv(t)
	c := allowControl()
	must(t, c.Apply(ctx, env, control.Values{"users": {""}}))
	wantContains(t, dropIn(t, env, "allow-users"), "AllowUsers alice")
	if got := sim.effective()["allowusers"]; len(got) != 1 || got[0] != "alice" {
		t.Fatalf("effective: %v", got)
	}
	if state(t, c, env) != control.Applied {
		t.Fatal("should be applied")
	}
	must(t, c.Revert(ctx, env))
	noFile(t, env, sshdFile("allow-users"))
}

func TestAllowUsersList(t *testing.T) {
	env, _, sim := sshEnv(t)
	writeFile(t, env, "/etc/passwd", basePasswd+"deploy:x:1002:1002::/home/deploy:/bin/bash\n")
	must(t, allowControl().Apply(context.Background(), env, control.Values{"users": {"alice, deploy alice"}}))
	wantContains(t, dropIn(t, env, "allow-users"), "AllowUsers alice deploy\n")
	if got := sim.effective()["allowusers"]; len(got) != 2 {
		t.Fatalf("effective: %v", got)
	}
}

func TestAllowUsersRefusals(t *testing.T) {
	ctx := context.Background()
	env, run, _ := sshEnv(t)
	writeFile(t, env, "/etc/passwd", basePasswd+"deploy:x:1002:1002::/home/deploy:/bin/bash\n")
	c := allowControl()
	for name, tc := range map[string]struct{ users, want string }{
		"unknown account": {"alice ghost", "does not exist"},
		"no admin":        {"deploy", "leaves out the administrator"},
		"pattern":         {"alice *", "plain account name"},
		"group pattern":   {"alice @staff", "plain account name"},
		"negation":        {"alice !bob", "plain account name"},
	} {
		err := c.Apply(ctx, env, control.Values{"users": {tc.users}})
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: error %v", name, err)
		}
	}
	noFile(t, env, sshdFile("allow-users"))
	if run.did("reload") {
		t.Fatal("nothing may change")
	}
}

func TestAllowUsersKeepsTheCurrentLogin(t *testing.T) {
	env, _, _ := sshEnv(t)
	writeFile(t, env, "/etc/passwd", basePasswd+"bob:x:1002:1002::/home/bob:/bin/bash\n")
	writeFile(t, env, "/etc/group", "root:x:0:\nwheel:x:10:alice,bob\nalice:x:1000:\n")
	t.Setenv("SUDO_USER", "bob")
	// Two admins; the list names only alice, but bob started the tool.
	err := allowControl().Apply(context.Background(), env, control.Values{"users": {"alice"}})
	if err == nil || !strings.Contains(err.Error(), "bob") {
		t.Fatalf("error: %v", err)
	}
}

func TestAllowUsersNoAdmin(t *testing.T) {
	env, _, _ := sshEnv(t)
	writeFile(t, env, "/etc/group", baseGroup)
	err := allowControl().Apply(context.Background(), env, control.Values{"users": {""}})
	if err == nil || !strings.Contains(err.Error(), "no user to allow") {
		t.Fatalf("error: %v", err)
	}
}

func TestAllowUsersDefaultInput(t *testing.T) {
	env, _, _ := sshEnv(t)
	ins, _ := allowControl().Inputs(context.Background(), env)
	if ins[0].Default != "alice" || !ins[0].Optional {
		t.Fatalf("input: %+v", ins[0])
	}
}
