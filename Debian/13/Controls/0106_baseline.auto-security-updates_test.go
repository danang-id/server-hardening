// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Danang Galuh Tegar Prasetyo

package controls

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/danang-id/server-hardening/internal/control"
)

func autoControl() *autoUpdates { return &autoUpdates{control.Base{M: control.Meta{ID: autoID}}} }

func TestAutoUpdatesWithReboot(t *testing.T) {
	ctx := context.Background()
	env, run := testEnv(t)
	c := autoControl()

	must(t, c.Apply(ctx, env, control.Values{"reboot": {"yes"}, "reboot-time": {"04:30"}}))
	got := read(t, env, autoFile)
	for _, want := range []string{
		`APT::Periodic::Update-Package-Lists "1";`,
		`APT::Periodic::Unattended-Upgrade "1";`,
		`#clear Unattended-Upgrade::Origins-Pattern;`,
		`label=Debian-Security`,
		`Unattended-Upgrade::Automatic-Reboot "true";`,
		`Unattended-Upgrade::Automatic-Reboot-Time "04:30";`,
	} {
		if !strings.Contains(got, want) {
			t.Errorf("config lacks %q:\n%s", want, got)
		}
	}
	if !run.did("install unattended-upgrades") || !run.did("systemctl enable --now apt-daily.timer apt-daily-upgrade.timer") {
		t.Fatalf("calls: %v", run.calls)
	}
	if state(t, c, env) != control.Applied {
		t.Fatal("not applied")
	}
	run.fail["systemctl is-enabled --quiet apt-daily-upgrade.timer"] = true
	if state(t, c, env) != control.Partial {
		t.Fatal("a disabled timer should be partial")
	}
	delete(run.fail, "systemctl is-enabled --quiet apt-daily-upgrade.timer")

	must(t, c.Revert(ctx, env))
	if got := read(t, env, autoFile); got != "<missing>" {
		t.Fatalf("config should be gone: %q", got)
	}
	if run.did("disable --now apt-daily") {
		t.Fatal("timers that were enabled before must stay enabled")
	}
}

func TestAutoUpdatesWithoutRebootAndTimersRestored(t *testing.T) {
	ctx := context.Background()
	env, run := testEnv(t)
	run.fail["systemctl is-enabled --quiet apt-daily.timer"] = true // not enabled before
	c := autoControl()

	must(t, c.Apply(ctx, env, control.Values{"reboot": {"no"}, "reboot-time": {"03:00"}}))
	if got := read(t, env, autoFile); strings.Contains(got, "Automatic-Reboot") {
		t.Fatalf("no reboot was chosen:\n%s", got)
	}
	delete(run.fail, "systemctl is-enabled --quiet apt-daily.timer")
	must(t, c.Revert(ctx, env))
	if !run.did("systemctl disable --now apt-daily.timer") {
		t.Fatal("a timer that was off before must be switched off again")
	}
	if run.did("disable --now apt-daily-upgrade.timer") {
		t.Fatal("a timer that was on before must stay on")
	}
}

func TestAutoUpdatesRejectsBadRebootTime(t *testing.T) {
	env, _ := testEnv(t)
	if err := autoControl().Apply(context.Background(), env, control.Values{"reboot": {"yes"}, "reboot-time": {"25:99"}}); err == nil {
		t.Fatal("bad time accepted")
	}
}

func TestAutoUpdatesInstallsAndRemovesTheNotifyHook(t *testing.T) {
	ctx := context.Background()
	env, run := testEnv(t)
	c := autoControl()
	must(t, c.Apply(ctx, env, control.Values{"reboot": {"no"}, "reboot-time": {"03:00"}}))
	wantContains(t, read(t, env, autoDropIn), "[Service]", "ExecStopPost=-"+autoHook)
	wantContains(t, read(t, env, autoHook), managed(autoID), notifyPath)
	fi, err := os.Stat(env.Path(autoHook))
	must(t, err)
	if fi.Mode().Perm() != 0o755 {
		t.Fatalf("hook mode %o", fi.Mode().Perm())
	}
	if !run.did("systemctl daemon-reload") {
		t.Fatal("systemd must reread its units")
	}
	noFileAt(t, env, autoHook)
	if state(t, c, env) != control.Partial {
		t.Fatal("a missing hook is partial")
	}
	must(t, os.WriteFile(env.Path(autoHook), []byte(autoHookScript), 0o755))
	must(t, c.Revert(ctx, env))
	noFile(t, env, autoDropIn)
	noFile(t, env, autoHook)
}

func TestAutoUpdatesHookScript(t *testing.T) {
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("no sh")
	}
	dir := t.TempDir()
	hook := filepath.Join(dir, "hook")
	calls := filepath.Join(dir, "calls")
	flag, seen := filepath.Join(dir, "reboot-required"), filepath.Join(dir, "seen")
	must(t, os.WriteFile(hook, []byte(autoHookScript), 0o755))
	notify := filepath.Join(dir, "notify")
	must(t, os.WriteFile(notify, []byte("#!/bin/sh\necho \"$*\" >> "+calls+"\n"), 0o755))
	run := func(env ...string) string {
		_ = os.Remove(calls)
		cmd := exec.Command("sh", hook)
		cmd.Env = append([]string{"PATH=/usr/bin:/bin", "HOOK_NOTIFY=" + notify, "HOOK_FLAG=" + flag, "HOOK_SEEN=" + seen}, env...)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("hook failed: %v: %s", err, out)
		}
		b, _ := os.ReadFile(calls)
		return string(b)
	}
	if got := run("SERVICE_RESULT=success"); got != "" {
		t.Fatalf("a quiet success says nothing: %q", got)
	}
	got := run("SERVICE_RESULT=exit-code", "EXIT_STATUS=100")
	wantContains(t, got, "baseline.auto-security-updates.failed warning", "exit-code", "100")

	must(t, os.WriteFile(flag, nil, 0o644))
	must(t, os.WriteFile(flag+".pkgs", []byte("linux-image-6.12\nlibc6\nlibc6\n"), 0o644))
	got = run("SERVICE_RESULT=success")
	wantContains(t, got, "baseline.auto-security-updates.reboot-required info", "libc6 linux-image-6.12")
	if got := run("SERVICE_RESULT=success"); got != "" {
		t.Fatalf("the reminder comes once per boot: %q", got)
	}
	// Without the helper the hook does nothing and does not fail.
	must(t, os.Remove(notify))
	_ = os.Remove(seen)
	if got := run("SERVICE_RESULT=exit-code"); got != "" {
		t.Fatal("no helper, no call")
	}
}
