// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Danang Galuh Tegar Prasetyo

package controls

import (
	"context"
	"testing"

	"github.com/danang-id/server-hardening/internal/control"
)

func forwardingControl() *sshDisableForwarding {
	return &sshDisableForwarding{control.Base{M: control.Meta{ID: forwardingID}}}
}

func TestForwarding(t *testing.T) {
	ctx := context.Background()
	for _, mode := range []string{"no", "local", "remote", "yes"} {
		env, _, sim := sshEnv(t)
		c := forwardingControl()
		must(t, c.Apply(ctx, env, control.Values{"tcp": {mode}}))
		eff := sim.effective()
		if eff["x11forwarding"][0] != "no" || eff["allowagentforwarding"][0] != "no" || eff["allowtcpforwarding"][0] != mode {
			t.Errorf("%s: effective %v", mode, eff)
		}
		if state(t, c, env) != control.Applied {
			t.Errorf("%s: should be applied", mode)
		}
		must(t, c.Revert(ctx, env))
		if sim.effective()["allowtcpforwarding"][0] != "yes" {
			t.Errorf("%s: default is back", mode)
		}
	}
}

func TestForwardingRejectsUnknownMode(t *testing.T) {
	env, _, _ := sshEnv(t)
	if err := forwardingControl().Apply(context.Background(), env, control.Values{"tcp": {"all"}}); err == nil {
		t.Fatal("unknown mode accepted")
	}
	noFile(t, env, sshdFile("forwarding"))
}

func TestForwardingDefaultsToNo(t *testing.T) {
	env, _, _ := sshEnv(t)
	ins, _ := forwardingControl().Inputs(context.Background(), env)
	if ins[0].Default != "no" || len(ins[0].Options) != 4 {
		t.Fatalf("input: %+v", ins[0])
	}
}
