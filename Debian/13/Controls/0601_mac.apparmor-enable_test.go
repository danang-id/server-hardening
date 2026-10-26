// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Danang Galuh Tegar Prasetyo

package controls

import (
	"context"
	"strings"
	"testing"

	"github.com/danang-id/server-hardening/internal/control"
)

func apparmorControl() *apparmorEnable {
	return &apparmorEnable{control.Base{M: control.Meta{ID: apparmorID}}}
}

func TestAppArmorAlreadyActiveInKernel(t *testing.T) {
	ctx := context.Background()
	env, run, s := sysEnv(t)
	c := apparmorControl()
	if state(t, c, env) != control.NotApplied {
		t.Fatal("should start not applied")
	}
	must(t, c.Apply(ctx, env, nil))
	for _, p := range []string{"apparmor", "apparmor-utils", "apparmor-profiles"} {
		if !s.installed[p] {
			t.Fatalf("%s should be installed", p)
		}
	}
	if !s.enabled[apparmorUnit] || !s.active[apparmorUnit] {
		t.Fatal("service should be enabled and running")
	}
	if run.did("update-grub") {
		t.Fatal("the kernel already runs AppArmor: the boot loader stays alone")
	}
	if state(t, c, env) != control.Applied {
		t.Fatal("should be applied")
	}
}

// Debian runs AppArmor in the kernel by default, so a new server often has it
// on. Without apparmor-utils, aa-enforce is missing and the next control
// fails, so that is not "applied".
func TestAppArmorRunningWithoutToolsIsPartial(t *testing.T) {
	env, _, s := sysEnv(t)
	s.installed["apparmor"] = true
	s.enabled[apparmorUnit], s.active[apparmorUnit] = true, true
	c := apparmorControl()
	if state(t, c, env) != control.Partial {
		t.Fatal("running without apparmor-utils and apparmor-profiles is partial")
	}
	must(t, c.Apply(context.Background(), env, nil))
	if state(t, c, env) != control.Applied {
		t.Fatal("applied once the tools are there")
	}
}

func TestAppArmorNeedsKernelParameters(t *testing.T) {
	ctx := context.Background()
	env, run, s := sysEnv(t)
	writeFile(t, env, "/etc/default/grub", "GRUB_CMDLINE_LINUX_DEFAULT=\"quiet\"\n")
	run.fail["aa-status --enabled"] = true
	c := apparmorControl()
	must(t, c.Apply(ctx, env, nil))
	wantContains(t, read(t, env, apparmorGrub), managed(apparmorID), "apparmor=1 security=apparmor", "$GRUB_CMDLINE_LINUX_DEFAULT")
	if !run.did("update-grub") {
		t.Fatal("update-grub should run")
	}
	if state(t, c, env) != control.Pending {
		t.Fatal("waiting for a reboot is pending")
	}

	// After the reboot the kernel runs AppArmor.
	delete(run.fail, "aa-status --enabled")
	if state(t, c, env) != control.Applied {
		t.Fatal("applied after the reboot")
	}

	s.enabled[apparmorUnit], s.active[apparmorUnit] = true, true
	run.calls = nil
	must(t, c.Revert(ctx, env))
	noFile(t, env, apparmorGrub)
	if !run.did("update-grub") {
		t.Fatal("update-grub should run on revert")
	}
	if s.enabled[apparmorUnit] || s.active[apparmorUnit] {
		t.Fatal("the service was off before")
	}
	if env.Rec.Has(apparmorID) {
		t.Fatal("record should be gone")
	}
}

func TestAppArmorWithoutGrubTellsWhatToDo(t *testing.T) {
	env, run, _ := sysEnv(t)
	run.fail["aa-status --enabled"] = true
	var warned []string
	env.Log = &memLog{warns: &warned}
	must(t, apparmorControl().Apply(context.Background(), env, nil))
	if run.did("update-grub") {
		t.Fatal("no GRUB, no update-grub")
	}
	if !strings.Contains(strings.Join(warned, "\n"), "apparmor=1 security=apparmor") {
		t.Fatalf("expected the command line in a warning: %v", warned)
	}
}

func TestAppArmorUpdateGrubFailureRollsBack(t *testing.T) {
	env, run, _ := sysEnv(t)
	writeFile(t, env, "/etc/default/grub", "GRUB_CMDLINE_LINUX_DEFAULT=\"quiet\"\n")
	run.fail["aa-status --enabled"] = true
	run.fail["update-grub"] = true
	if err := apparmorControl().Apply(context.Background(), env, nil); err == nil {
		t.Fatal("expected an error")
	}
	noFile(t, env, apparmorGrub)
}
