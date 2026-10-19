// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Danang Galuh Tegar Prasetyo

package controls

import (
	"context"
	"strings"
	"testing"

	"github.com/danang-id/server-hardening/internal/control"
)

func TestSFTP(t *testing.T) {
	ctx := context.Background()
	env, run, sim := sshEnv(t)
	c := &sftp{control.Base{M: control.Meta{ID: sftpID}}}
	if state(t, c, env) != control.NotApplied {
		t.Fatal("should start not applied")
	}
	must(t, c.Apply(ctx, env, nil))
	wantContains(t, dropIn(t, env, "sftp"), sshdMarker(sftpID), "Subsystem sftp internal-sftp")
	if got := sim.effective()["subsystem"]; len(got) != 1 || got[0] != "sftp internal-sftp" {
		t.Fatalf("effective: %v", got)
	}
	// The configuration is checked before sshd reloads it.
	t0, t1 := -1, -1
	for i, c := range run.calls {
		if c == "sshd -t" && t0 < 0 {
			t0 = i
		}
		if c == "systemctl reload ssh" {
			t1 = i
		}
	}
	if t0 < 0 || t1 < t0 {
		t.Fatalf("sshd -t must come before the reload: %v", run.calls)
	}
	if state(t, c, env) != control.Applied {
		t.Fatal("should be applied")
	}
	must(t, c.Revert(ctx, env))
	noFile(t, env, sshdFile("sftp"))
	if env.Rec.Has(sftpID) {
		t.Fatal("record should be gone")
	}
	if got := sim.effective()["subsystem"]; !strings.Contains(got[0], "sftp-server") {
		t.Fatalf("the system default is back: %v", got)
	}
}

func TestSFTPInstallsOpenSSH(t *testing.T) {
	env, run, _ := sshEnv(t)
	run.out["dpkg-query -W -f=${Status} openssh-server"] = ""
	c := &sftp{control.Base{M: control.Meta{ID: sftpID}}}
	must(t, c.Apply(context.Background(), env, nil))
	if !run.did("apt-get -y -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold install openssh-server") {
		t.Fatalf("openssh-server must be installed: %v", run.calls)
	}
}

func TestSSHDRollsBackWhenSSHDRefuses(t *testing.T) {
	env, run, _ := sshEnv(t)
	writeFile(t, env, sshdFile("sftp"), "# earlier content\n")
	c := &sftp{control.Base{M: control.Meta{ID: sftpID}}}
	run.hook = chain(run.hook, func(f *fakeRunner, cmd string) {
		if cmd == "sshd -t" {
			f.fail[cmd] = true
		}
	})
	err := c.Apply(context.Background(), env, nil)
	if err == nil || !strings.Contains(err.Error(), "refused") {
		t.Fatalf("error: %v", err)
	}
	if got := dropIn(t, env, "sftp"); got != "# earlier content\n" {
		t.Fatalf("the earlier file must be back:\n%s", got)
	}
}

func TestSSHDRollsBackWhenAnotherSettingWins(t *testing.T) {
	env, _, sim := sshEnv(t)
	sim.mainWins = true
	writeFile(t, env, "/etc/ssh/sshd_config", "Subsystem sftp /usr/lib/openssh/sftp-server\n")
	c := &sftp{control.Base{M: control.Meta{ID: sftpID}}}
	err := c.Apply(context.Background(), env, nil)
	if err == nil || !strings.Contains(err.Error(), "overrides") {
		t.Fatalf("error: %v", err)
	}
	noFile(t, env, sshdFile("sftp"))
}

func TestSSHDRevertWithoutRecordTouchesNothing(t *testing.T) {
	env, run, _ := sshEnv(t)
	writeFile(t, env, sshdFile("sftp"), "Subsystem sftp internal-sftp\n")
	c := &sftp{control.Base{M: control.Meta{ID: sftpID}}}
	must(t, c.Revert(context.Background(), env))
	if read(t, env, sshdFile("sftp")) == "<missing>" || run.did("reload") {
		t.Fatal("a file this tool did not write must stay")
	}
}

// chain runs two hooks in order.
func chain(a, b func(*fakeRunner, string)) func(*fakeRunner, string) {
	return func(f *fakeRunner, cmd string) {
		if a != nil {
			a(f, cmd)
		}
		b(f, cmd)
	}
}
