// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Danang Galuh Tegar Prasetyo

package controls

import (
	"context"
	"strings"
	"testing"

	"github.com/danang-id/server-hardening/internal/control"
)

func autoControl() *autoUpdates { return &autoUpdates{control.Base{M: control.Meta{ID: autoID}}} }

const stockAutomatic = "[commands]\n#  What kind of upgrade to perform:\nupgrade_type = default\ndownload_updates = yes\napply_updates = no\nrandom_sleep = 0\n\n[emitters]\nemit_via = stdio\n\n[base]\ndebuglevel = 1\n"

func TestAutoUpdatesRoundTrip(t *testing.T) {
	ctx := context.Background()
	env, run := testEnv(t)
	must(t, writeTestFile(env, autoConf, stockAutomatic))
	run.fail["systemctl is-enabled --quiet dnf-automatic-install.timer"] = true
	run.fail["systemctl is-active --quiet dnf-automatic-install.timer"] = true
	run.fail["rpm -q --quiet dnf-automatic"] = true // not installed yet
	c := autoControl()
	if state(t, c, env) != control.NotApplied {
		t.Fatal("applied before apply")
	}

	must(t, c.Apply(ctx, env, control.Values{"time": {"04:30"}, "reboot": {"yes"}}))
	conf := read(t, env, autoConf)
	for _, want := range []string{
		"# Managed by github.com/danang-id/server-hardening (baseline.auto-security-updates)\n",
		"upgrade_type = security\n", "apply_updates = yes\n", "reboot = when-needed\n",
		"random_sleep = 0\nreboot = when-needed\n\n[emitters]", "[base]\ndebuglevel = 1\n",
	} {
		if !strings.Contains(conf, want) {
			t.Errorf("automatic.conf lacks %q:\n%s", want, conf)
		}
	}
	if got := read(t, env, autoDropIn); !strings.Contains(got, "OnCalendar=\nOnCalendar=*-*-* 04:30\n") {
		t.Fatalf("timer drop-in: %q", got)
	}
	for _, want := range []string{"dnf -y install dnf-automatic", "systemctl daemon-reload", "systemctl enable --now dnf-automatic-install.timer"} {
		if !run.did(want) {
			t.Errorf("missing command %q in %v", want, run.calls)
		}
	}
	delete(run.fail, "systemctl is-enabled --quiet dnf-automatic-install.timer")
	if state(t, c, env) != control.Applied {
		t.Fatal("not applied after apply")
	}
	// Somebody turns updates off again: only part of the control is left.
	must(t, writeTestFile(env, autoConf, strings.Replace(conf, "apply_updates = yes", "apply_updates = no", 1)))
	if state(t, c, env) != control.Partial {
		t.Fatal("a changed setting must be reported as partial")
	}
	must(t, writeTestFile(env, autoConf, conf))

	must(t, c.Revert(ctx, env))
	if got := read(t, env, autoConf); got != stockAutomatic {
		t.Fatalf("automatic.conf not restored:\n%s", got)
	}
	if got := read(t, env, autoDropIn); got != "<missing>" {
		t.Fatalf("drop-in should be gone: %q", got)
	}
	if !run.did("systemctl disable --now dnf-automatic-install.timer") {
		t.Fatalf("the timer must be switched off again as it was: %v", run.calls)
	}
	if state(t, c, env) != control.NotApplied {
		t.Fatal("still applied after revert")
	}
}

func TestAutoUpdatesNoRebootByDefault(t *testing.T) {
	env, _ := testEnv(t)
	must(t, writeTestFile(env, autoConf, stockAutomatic))
	must(t, autoControl().Apply(context.Background(), env, control.Values{"time": {"03:00"}, "reboot": {"no"}}))
	if conf := read(t, env, autoConf); !strings.Contains(conf, "reboot = never\n") {
		t.Fatalf("automatic.conf:\n%s", conf)
	}
}

func TestAutoUpdatesRejectsBadTime(t *testing.T) {
	env, run := testEnv(t)
	for _, bad := range []string{"", "25:00", "3pm", "03:60"} {
		if err := autoControl().Apply(context.Background(), env, control.Values{"time": {bad}, "reboot": {"no"}}); err == nil {
			t.Errorf("%q should be rejected", bad)
		}
	}
	if run.did("install") {
		t.Fatal("a package was installed for invalid input")
	}
}
