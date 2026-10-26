// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Danang Galuh Tegar Prasetyo

package controls

import (
	"context"
	"testing"

	"github.com/danang-id/server-hardening/internal/control"
)

func limitsControl() *sshLoginLimits {
	return &sshLoginLimits{control.Base{M: control.Meta{ID: limitsID}}}
}

func TestLoginLimits(t *testing.T) {
	ctx := context.Background()
	env, _, sim := sshEnv(t)
	c := limitsControl()
	in := control.Values{"tries": {"3"}, "grace": {"30"}, "startups": {"10:30:60"}, "alive": {"300"}}
	must(t, c.Apply(ctx, env, in))
	wantContains(t, dropIn(t, env, "login-limits"), "MaxAuthTries 3", "LoginGraceTime 30",
		"MaxStartups 10:30:60", "ClientAliveInterval 300", "ClientAliveCountMax 2")
	eff := sim.effective()
	if eff["maxauthtries"][0] != "3" || eff["clientalivecountmax"][0] != "2" {
		t.Fatalf("effective: %v", eff)
	}
	if state(t, c, env) != control.Applied {
		t.Fatal("should be applied")
	}
	// A second run with other numbers replaces the first.
	in["tries"] = []string{"4"}
	must(t, c.Apply(ctx, env, in))
	if sim.effective()["maxauthtries"][0] != "4" {
		t.Fatal("the new value must win")
	}
	must(t, c.Revert(ctx, env))
	noFile(t, env, sshdFile("login-limits"))
	if sim.effective()["maxauthtries"][0] != "6" {
		t.Fatal("the default is back")
	}
}

func TestLoginLimitsValidation(t *testing.T) {
	env, _, _ := sshEnv(t)
	c := limitsControl()
	good := func() control.Values {
		return control.Values{"tries": {"3"}, "grace": {"30"}, "startups": {"10:30:60"}, "alive": {"300"}}
	}
	for key, bad := range map[string]string{
		"tries": "0", "grace": "2", "alive": "5", "startups": "60:30:10",
	} {
		in := good()
		in[key] = []string{bad}
		if err := c.Apply(context.Background(), env, in); err == nil {
			t.Errorf("%s=%q accepted", key, bad)
		}
	}
	for _, bad := range []string{"10", "10:30", "a:b:c", "10:0:60", "10:101:60", "0:30:60"} {
		if validMaxStartups(bad) == nil {
			t.Errorf("MaxStartups %q accepted", bad)
		}
	}
	if validMaxStartups("10:30:60") != nil || validMaxStartups("1:1:1") != nil {
		t.Error("valid MaxStartups refused")
	}
	noFile(t, env, sshdFile("login-limits"))
}
