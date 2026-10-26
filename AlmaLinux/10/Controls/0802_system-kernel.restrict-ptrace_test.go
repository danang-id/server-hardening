// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Danang Galuh Tegar Prasetyo

package controls

import (
	"context"
	"strings"
	"testing"

	"github.com/danang-id/server-hardening/internal/control"
)

func ptraceControl() *restrictPtrace {
	return &restrictPtrace{control.Base{M: control.Meta{ID: ptraceID}}}
}

func TestPtraceScope(t *testing.T) {
	ctx := context.Background()
	env, _, k := sysctlEnv(t, map[string]string{"kernel.yama.ptrace_scope": "0"})
	c := ptraceControl()
	must(t, c.Apply(ctx, env, control.Values{"scope": {"2"}}))
	wantContains(t, read(t, env, sysctlFile("ptrace")), "kernel.yama.ptrace_scope = 2")
	if k.get("kernel.yama.ptrace_scope") != "2" || state(t, c, env) != control.Applied {
		t.Fatal("scope 2 should be set")
	}
	must(t, c.Revert(ctx, env))
	if k.get("kernel.yama.ptrace_scope") != "0" {
		t.Fatal("the previous scope must come back")
	}
}

func TestPtraceScope3CannotBeLowered(t *testing.T) {
	ctx := context.Background()
	env, _, k := sysctlEnv(t, map[string]string{"kernel.yama.ptrace_scope": "1"})
	c := ptraceControl()
	must(t, c.Apply(ctx, env, control.Values{"scope": {"3"}}))
	k.locked["kernel.yama.ptrace_scope"] = true
	must(t, c.Revert(ctx, env))
	noFile(t, env, sysctlFile("ptrace"))
	if k.get("kernel.yama.ptrace_scope") != "3" {
		t.Fatal("the simulated kernel keeps 3")
	}
}

func TestPtraceNeedsYamaAndAValidScope(t *testing.T) {
	env, _, _ := sysctlEnv(t, map[string]string{})
	err := ptraceControl().Apply(context.Background(), env, control.Values{"scope": {"1"}})
	if err == nil || !strings.Contains(err.Error(), "Yama") {
		t.Fatalf("want a Yama message, got %v", err)
	}
	env, _, _ = sysctlEnv(t, map[string]string{"kernel.yama.ptrace_scope": "0"})
	if err := ptraceControl().Apply(context.Background(), env, control.Values{"scope": {"4"}}); err == nil {
		t.Fatal("scope 4 does not exist")
	}
}
