// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Danang Galuh Tegar Prasetyo

package controls

import (
	"context"
	"testing"

	"github.com/danang-id/server-hardening/internal/control"
)

func kernelControl() *sysctlKernel {
	return &sysctlKernel{control.Base{M: control.Meta{ID: kernelSysctlID}}}
}

func kernelParams() map[string]string {
	m := map[string]string{}
	for _, s := range kernelSettings("0") {
		m[s.Key] = "0"
	}
	m["kernel.sysrq"] = "438"
	return m
}

func TestKernelSettings(t *testing.T) {
	ctx := context.Background()
	env, _, k := sysctlEnv(t, kernelParams())
	c := kernelControl()
	if state(t, c, env) != control.NotApplied {
		t.Fatal("should start not applied")
	}
	must(t, c.Apply(ctx, env, control.Values{"sysrq": {"safe"}}))
	wantContains(t, read(t, env, sysctlFile("kernel")), sysctlMarker(kernelSysctlID),
		"kernel.kptr_restrict = 2", "kernel.dmesg_restrict = 1", "kernel.perf_event_paranoid = 3",
		"fs.protected_hardlinks = 1", "fs.protected_fifos = 2", "fs.protected_regular = 2",
		"fs.suid_dumpable = 0", "kernel.randomize_va_space = 2", "kernel.sysrq = 176")
	if k.get("kernel.kptr_restrict") != "2" || k.get("kernel.sysrq") != "176" {
		t.Fatalf("running: %v", k.running)
	}
	if state(t, c, env) != control.Applied {
		t.Fatal("should be applied")
	}
	must(t, c.Revert(ctx, env))
	noFile(t, env, sysctlFile("kernel"))
	if k.get("kernel.sysrq") != "438" || k.get("kernel.kptr_restrict") != "0" {
		t.Fatalf("the recorded values must come back: %v", k.running)
	}
}

func TestKernelSysrqOff(t *testing.T) {
	env, _, k := sysctlEnv(t, kernelParams())
	must(t, kernelControl().Apply(context.Background(), env, control.Values{"sysrq": {"off"}}))
	if k.get("kernel.sysrq") != "0" {
		t.Fatalf("sysrq: %s", k.get("kernel.sysrq"))
	}
}

func TestKernelRejectsBadSysrqAndSkipsMissingParameters(t *testing.T) {
	params := kernelParams()
	delete(params, "kernel.perf_event_paranoid")
	env, _, _ := sysctlEnv(t, params)
	if err := kernelControl().Apply(context.Background(), env, control.Values{"sysrq": {"1"}}); err == nil {
		t.Fatal("a bit mask is not an answer")
	}
	must(t, kernelControl().Apply(context.Background(), env, control.Values{"sysrq": {"off"}}))
	if got := read(t, env, sysctlFile("kernel")); contains(lines(got), "kernel.perf_event_paranoid = 3") {
		t.Fatal("a parameter the kernel lacks must not be written")
	}
}
