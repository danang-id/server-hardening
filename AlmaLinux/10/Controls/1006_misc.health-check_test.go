// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Danang Galuh Tegar Prasetyo

package controls

import (
	"context"
	"strings"
	"testing"

	"github.com/danang-id/server-hardening/internal/control"
)

func healthControl() *healthCheck { return &healthCheck{control.Base{M: control.Meta{ID: healthID}}} }

const (
	okMeminfo = "MemTotal:  2048000 kB\nMemFree: 100000 kB\nMemAvailable: 1500000 kB\n"
	dfOK      = "Filesystem 1024-blocks Used Available Capacity Mounted on\n/dev/sda1 10000000 1000000 9000000 10% /\n"
)

// healthyEnv answers every command the check runs with a healthy result.
func healthyEnv(t *testing.T) (*control.Env, *fakeRunner, *sysSim) {
	env, run, s := sysEnv(t)
	writeFile(t, env, "/proc/meminfo", okMeminfo)
	run.out["timedatectl show -p NTPSynchronized --value"] = "yes\n"
	for _, d := range []string{"/", "/var"} {
		run.out["df -Pk "+d] = dfOK
	}
	run.fail["df -Pk /boot"] = true
	return env, run, s
}

func TestHealthPassesOnAHealthyServer(t *testing.T) {
	ctx := context.Background()
	env, _, _ := healthyEnv(t)
	c := healthControl()
	if state(t, c, env) != control.NotApplied {
		t.Fatal("should start not applied")
	}
	must(t, c.Apply(ctx, env, nil))
	if state(t, c, env) != control.Applied {
		t.Fatal("should be applied")
	}
	if err := c.Revert(ctx, env); err != control.ErrNoRevert {
		t.Fatalf("revert: %v", err)
	}
}

func TestHealthReportsEachProblem(t *testing.T) {
	ctx := context.Background()
	env, run, s := healthyEnv(t)
	c := healthControl()
	s.active["sshd"] = true
	run.fail["sshd -t"] = true
	run.out["sshd -t"] = "/etc/ssh/sshd_config line 3: Bad configuration option: Foo\n"
	run.out["systemctl --failed --no-legend --plain"] = "fail2ban.service loaded failed failed Fail2Ban\n"
	run.out["rpm --verifydb"] = "error: rpmdb: BDB0113 Thread/process failed\n"
	run.fail["rpm --verifydb"] = true
	run.out["dnf -q repoquery --unsatisfied"] = "foo-1.0-1.el10.x86_64\n"
	run.out["df -Pk /"] = "Filesystem 1024-blocks Used Available Capacity Mounted on\n/dev/sda1 10000000 9800000 200000 98% /\n"
	writeFile(t, env, "/proc/meminfo", "MemTotal: 2048000 kB\nMemAvailable: 30000 kB\n")
	run.out["timedatectl show -p NTPSynchronized --value"] = "no\n"

	var warns []string
	env.Log = &memLog{warns: &warns}
	err := c.Apply(ctx, env, nil)
	if err == nil {
		t.Fatal("expected a failure")
	}
	for _, w := range []string{"sshd -t", "fail2ban.service", "rpm --verifydb", "unsatisfied dependencies", "/ has only 195 MiB", "29 MiB of memory"} {
		if !strings.Contains(err.Error(), w) {
			t.Errorf("error lacks %q:\n%v", w, err)
		}
	}
	if !strings.Contains(strings.Join(warns, "\n"), "clock is not synchronised") {
		t.Errorf("clock warning missing: %v", warns)
	}
	if strings.Contains(err.Error(), "clock") {
		t.Error("an unsynchronised clock is a warning, not a failure")
	}
	if state(t, c, env) != control.Partial {
		t.Fatal("a failed run is partial")
	}
}

func TestHealthSSHPortMustListen(t *testing.T) {
	ctx := context.Background()
	env, run, s := healthyEnv(t)
	s.active["sshd"] = true
	run.out["sshd -T"] = "port 2222\n"
	run.out["ss -H -ltnp"] = `LISTEN 0 128 0.0.0.0:22 0.0.0.0:* users:(("sshd",pid=1,fd=3))` + "\n"
	err := healthControl().Apply(ctx, env, nil)
	if err == nil || !strings.Contains(err.Error(), "port 2222") {
		t.Fatalf("got %v", err)
	}
	run.out["ss -H -ltnp"] = `LISTEN 0 128 0.0.0.0:2222 0.0.0.0:* users:(("sshd",pid=1,fd=3))` + "\n"
	must(t, healthControl().Apply(ctx, env, nil))
}

func TestHealthFirewallDownAndExposedPorts(t *testing.T) {
	ctx := context.Background()
	env, run, _ := healthyEnv(t)
	must(t, env.Rec.Put(fwID, "engine", "firewalld"))
	must(t, env.Rec.Put(fwID, "ssh-ports", "22"))
	must(t, env.Rec.Put(portsID, "rules", "443/tcp\n8000-8010/tcp"))
	run.out["firewall-cmd --state"] = "not running\n"
	run.fail["firewall-cmd --state"] = true
	fs := healthFirewall(ctx, env)
	if len(fs) != 1 || fs[0].level != levelFail || !strings.Contains(fs[0].text, "firewalld firewall is not active") {
		t.Fatalf("got %+v", fs)
	}

	run.out["firewall-cmd --state"] = "running\n"
	run.fail["firewall-cmd --state"] = false
	run.out["ss -H -ltnp"] = strings.Join([]string{
		`LISTEN 0 128 0.0.0.0:22 0.0.0.0:* users:(("sshd",pid=1,fd=3))`,
		`LISTEN 0 128 *:443 *:*`,
		`LISTEN 0 128 0.0.0.0:8005 0.0.0.0:*`,
		`LISTEN 0 128 127.0.0.1:5432 0.0.0.0:*`,
		`LISTEN 0 128 0.0.0.0:3306 0.0.0.0:*`,
	}, "\n") + "\n"
	var texts []string
	for _, f := range healthFirewall(ctx, env) {
		if f.level != levelWarn {
			t.Errorf("only warnings expected: %+v", f)
		}
		texts = append(texts, f.text)
	}
	all := strings.Join(texts, "\n")
	if !strings.Contains(all, "port 3306") {
		t.Errorf("3306 must be reported: %v", texts)
	}
	for _, p := range []string{"port 22 ", "port 443", "port 8005", "port 5432"} {
		if strings.Contains(all, p) {
			t.Errorf("%q must not be reported: %v", p, texts)
		}
	}
}

func TestHealthRecheckAppliedControlsAndNotify(t *testing.T) {
	ctx := context.Background()
	env, run, _ := healthyEnv(t)
	// timezone is recorded as applied, but the zone has changed since.
	must(t, env.Rec.Put("baseline.timezone", "previous", "Asia/Jakarta"))
	writeFile(t, env, "/etc/timezone", "Europe/Paris\n")
	writeFile(t, env, notifyPath, "#!/bin/sh\n")
	err := healthControl().Apply(ctx, env, nil)
	if err == nil || !strings.Contains(err.Error(), "baseline.timezone") {
		t.Fatalf("got %v", err)
	}
	found := false
	for _, c := range run.calls {
		if strings.HasPrefix(c, notifyPath+" misc.health-check.failed critical ") {
			found = true
		}
	}
	if !found {
		t.Fatalf("notify not called: %v", run.calls)
	}
}

func TestHealthNoNotifyWithoutHelper(t *testing.T) {
	env, run, _ := healthyEnv(t)
	run.out["systemctl --failed --no-legend --plain"] = "x.service loaded failed failed X\n"
	_ = healthControl().Apply(context.Background(), env, nil)
	if run.did("misc.health-check.failed") {
		t.Fatal("no helper, no call")
	}
}

func TestHealthNotesAPendingReboot(t *testing.T) {
	ctx := context.Background()
	env, run, _ := healthyEnv(t)
	var infos []string
	env.Log = &infoLog{infos: &infos}
	run.fail["dnf -q needs-restarting -r"] = true
	run.out["dnf -q needs-restarting -r"] = "Core libraries or services have been updated since boot-up:\n  * kernel\n\nReboot is required to fully utilize these updates.\n"
	must(t, healthControl().Apply(ctx, env, nil))
	if !strings.Contains(strings.Join(infos, "\n"), "a reboot is pending") {
		t.Fatalf("infos: %v", infos)
	}

	infos = nil
	// The plugin is missing: the command fails with some other text.
	run.out["dnf -q needs-restarting -r"] = "No such command: needs-restarting.\n"
	must(t, healthControl().Apply(ctx, env, nil))
	if strings.Contains(strings.Join(infos, "\n"), "reboot is pending") {
		t.Fatalf("no reboot message without the real answer: %v", infos)
	}
}
