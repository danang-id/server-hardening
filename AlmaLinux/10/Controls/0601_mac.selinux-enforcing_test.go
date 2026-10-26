// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Danang Galuh Tegar Prasetyo

package controls

import (
	"context"
	"strings"
	"testing"

	"github.com/danang-id/server-hardening/internal/control"
)

func selinuxControl() *selinuxEnforcing {
	return &selinuxEnforcing{control.Base{M: control.Meta{ID: selinuxID}}}
}

const permissiveConfig = "# This file controls the state of SELinux on the system.\nSELINUX=permissive\nSELINUXTYPE=targeted\n"

// selinuxEnv has SELinux in the given mode, the way setenforce changes it.
func selinuxEnv(t *testing.T, mode, config string) (*control.Env, *fakeRunner) {
	t.Helper()
	env, run := testEnv(t)
	writeFile(t, env, selinuxConfig, config)
	run.out["getenforce"] = mode + "\n"
	run.hook = func(f *fakeRunner, cmd string) {
		switch cmd {
		case "setenforce 1":
			f.out["getenforce"] = "Enforcing\n"
		case "setenforce 0":
			f.out["getenforce"] = "Permissive\n"
		}
	}
	return env, run
}

func TestSELinuxEnforcingRoundTrip(t *testing.T) {
	ctx := context.Background()
	env, run := selinuxEnv(t, "Permissive", permissiveConfig)
	c := selinuxControl()
	if state(t, c, env) != control.NotApplied {
		t.Fatal("permissive is not applied")
	}
	must(t, c.Apply(ctx, env, nil))
	got := read(t, env, selinuxConfig)
	wantContains(t, got, "SELINUX=enforcing\n", "SELINUXTYPE=targeted\n", "# This file controls")
	if strings.Contains(got, "SELINUX=permissive") || strings.Contains(got, "SELINUX = ") {
		t.Fatalf("one line, no spaces around the equal sign:\n%s", got)
	}
	if !run.did("setenforce 1") {
		t.Fatalf("enforcing now, not only at the next boot: %v", run.calls)
	}
	if state(t, c, env) != control.Applied {
		t.Fatal("should be applied")
	}

	must(t, c.Revert(ctx, env))
	if read(t, env, selinuxConfig) != permissiveConfig {
		t.Fatalf("config not restored:\n%s", read(t, env, selinuxConfig))
	}
	if !run.did("setenforce 0") {
		t.Fatal("it was permissive before and must go back")
	}
	if env.Rec.Has(selinuxID) {
		t.Fatal("record should be gone")
	}
}

func TestSELinuxEnforcingAlreadyOnlyInTheConfig(t *testing.T) {
	ctx := context.Background()
	// Enforcing in the kernel, permissive in the file: the next boot would undo it.
	env, run := selinuxEnv(t, "Enforcing", permissiveConfig)
	c := selinuxControl()
	if state(t, c, env) != control.Partial {
		t.Fatal("a mode that does not survive the reboot is partial")
	}
	must(t, c.Apply(ctx, env, nil))
	if run.did("setenforce") {
		t.Fatal("the kernel is enforcing already")
	}
	if state(t, c, env) != control.Applied {
		t.Fatal("should be applied")
	}
	must(t, c.Revert(ctx, env))
	if run.did("setenforce 0") {
		t.Fatal("it was enforcing before, it stays")
	}
}

func TestSELinuxEnforcingRefusesWhenDisabled(t *testing.T) {
	env, run := selinuxEnv(t, "Disabled", "SELINUX=disabled\n")
	err := selinuxControl().Apply(context.Background(), env, nil)
	if err == nil || !strings.Contains(err.Error(), "relabel") {
		t.Fatalf("error: %v", err)
	}
	if read(t, env, selinuxConfig) != "SELINUX=disabled\n" || run.did("setenforce") {
		t.Fatal("nothing may change")
	}
	if state(t, selinuxControl(), env) != control.NotApplied {
		t.Fatal("disabled is not applied")
	}
}

func TestSELinuxEnforcingRollsBackWhenSetenforceFails(t *testing.T) {
	env, run := selinuxEnv(t, "Permissive", permissiveConfig)
	run.fail["setenforce 1"] = true
	if err := selinuxControl().Apply(context.Background(), env, nil); err == nil {
		t.Fatal("expected an error")
	}
	if read(t, env, selinuxConfig) != permissiveConfig {
		t.Fatal("the config must be put back")
	}
}

func TestWithSELinuxMode(t *testing.T) {
	for in, want := range map[string]string{
		"":                        "SELINUX=enforcing\n",
		"SELINUXTYPE=targeted":    "SELINUXTYPE=targeted\nSELINUX=enforcing\n",
		"SELINUX=disabled\n":      "SELINUX=enforcing\n",
		"SELINUX = permissive\n":  "SELINUX=enforcing\n",
		"SELINUX=a\nSELINUX=b\n":  "SELINUX=enforcing\n#SELINUX=enforcing\n",
		"#SELINUX=x\nSELINUX=y\n": "#SELINUX=x\nSELINUX=enforcing\n",
	} {
		if got := withSELinuxMode(in, "enforcing"); got != want {
			t.Errorf("withSELinuxMode(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestSELinuxEnforcingMeta(t *testing.T) {
	c, ok := System.Get(selinuxID)
	if !ok || !c.Meta().Has(control.TagCompat) || !c.Meta().Default {
		t.Fatalf("meta: %+v", c)
	}
}

func TestSELinuxRevertWithoutRecord(t *testing.T) {
	env, run := selinuxEnv(t, "Enforcing", "SELINUX=enforcing\n")
	must(t, selinuxControl().Revert(context.Background(), env))
	if run.did("setenforce") || read(t, env, selinuxConfig) != "SELINUX=enforcing\n" {
		t.Fatal("no record means no change")
	}
}
