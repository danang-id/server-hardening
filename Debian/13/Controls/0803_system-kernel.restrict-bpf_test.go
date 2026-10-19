// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Danang Galuh Tegar Prasetyo

package controls

import (
	"context"
	"testing"

	"github.com/danang-id/server-hardening/internal/control"
)

func bpfControl() *restrictBPF { return &restrictBPF{control.Base{M: control.Meta{ID: bpfID}}} }

func TestBPFMode2(t *testing.T) {
	ctx := context.Background()
	env, _, k := sysctlEnv(t, map[string]string{"kernel.unprivileged_bpf_disabled": "0", "net.core.bpf_jit_harden": "0"})
	c := bpfControl()
	must(t, c.Apply(ctx, env, control.Values{"mode": {"2"}}))
	if k.get("kernel.unprivileged_bpf_disabled") != "2" || k.get("net.core.bpf_jit_harden") != "2" {
		t.Fatalf("running: %v", k.running)
	}
	if state(t, c, env) != control.Applied {
		t.Fatal("should be applied")
	}
	must(t, c.Revert(ctx, env))
	if k.get("kernel.unprivileged_bpf_disabled") != "0" || k.get("net.core.bpf_jit_harden") != "0" {
		t.Fatalf("revert: %v", k.running)
	}
}

func TestBPFWithoutJIT(t *testing.T) {
	env, _, _ := sysctlEnv(t, map[string]string{"kernel.unprivileged_bpf_disabled": "0"})
	must(t, bpfControl().Apply(context.Background(), env, control.Values{"mode": {"1"}}))
	if got := read(t, env, sysctlFile("bpf")); contains(lines(got), "net.core.bpf_jit_harden = 2") {
		t.Fatal("no compiler, no hardening setting")
	}
	if err := bpfControl().Apply(context.Background(), env, control.Values{"mode": {"0"}}); err == nil {
		t.Fatal("mode 0 would switch eBPF on")
	}
}
