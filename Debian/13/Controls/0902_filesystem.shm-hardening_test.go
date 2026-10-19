// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Danang Galuh Tegar Prasetyo

package controls

import (
	"context"
	"strings"
	"testing"

	"github.com/danang-id/server-hardening/internal/control"
)

func shmControl() *shmHardening { return &shmHardening{control.Base{M: control.Meta{ID: shmID}}} }

const stockFstab = "# /etc/fstab\nUUID=1 / ext4 errors=remount-ro 0 1\n"

func TestShmHardeningFstabAndRemount(t *testing.T) {
	ctx := context.Background()
	env, run, _, m := mountEnv(t)
	writeFile(t, env, "/etc/fstab", stockFstab)
	c := shmControl()
	if state(t, c, env) != control.NotApplied {
		t.Fatal("should start not applied")
	}
	must(t, c.Apply(ctx, env, control.Values{"noexec": {"yes"}}))
	got := read(t, env, "/etc/fstab")
	wantContains(t, got, stockFstab, managed(shmID), "tmpfs /dev/shm tmpfs defaults,nosuid,nodev,noexec 0 0")
	if !strings.Contains(m.opts["/dev/shm"], "noexec") || !run.did("mount -o remount,nosuid,nodev,noexec /dev/shm") {
		t.Fatalf("options %s, calls %v", m.opts["/dev/shm"], run.calls)
	}
	if state(t, c, env) != control.Applied {
		t.Fatal("should be applied")
	}

	// Applying again with a different answer replaces the line, it does not add one.
	must(t, c.Apply(ctx, env, control.Values{"noexec": {"no"}}))
	got = read(t, env, "/etc/fstab")
	if strings.Count(got, "/dev/shm") != 1 || strings.Contains(got, "noexec") || strings.Count(got, managed(shmID)) != 1 {
		t.Fatalf("fstab: %s", got)
	}
	if strings.Contains(m.opts["/dev/shm"], "noexec") {
		t.Fatalf("noexec must be off: %s", m.opts["/dev/shm"])
	}

	must(t, c.Revert(ctx, env))
	if read(t, env, "/etc/fstab") != stockFstab {
		t.Fatalf("fstab must be restored: %q", read(t, env, "/etc/fstab"))
	}
	if strings.Contains(m.opts["/dev/shm"], "noexec") || !strings.Contains(m.opts["/dev/shm"], "nosuid") {
		t.Fatalf("the original flags must come back: %s", m.opts["/dev/shm"])
	}
	if env.Rec.Has(shmID) {
		t.Fatal("record should be gone")
	}
}

func TestShmReplacesExistingLine(t *testing.T) {
	env, _, _, _ := mountEnv(t)
	writeFile(t, env, "/etc/fstab", stockFstab+"tmpfs /dev/shm tmpfs defaults 0 0\n")
	must(t, shmControl().Apply(context.Background(), env, control.Values{"noexec": {"yes"}}))
	got := read(t, env, "/etc/fstab")
	if strings.Count(got, "/dev/shm") != 1 || strings.Contains(got, "defaults 0 0") {
		t.Fatalf("the old line must be replaced: %s", got)
	}
}

func TestShmRemountFailureRestoresFstab(t *testing.T) {
	env, run, _, _ := mountEnv(t)
	writeFile(t, env, "/etc/fstab", stockFstab)
	run.fail["mount -o remount,nosuid,nodev,noexec /dev/shm"] = true
	if err := shmControl().Apply(context.Background(), env, control.Values{"noexec": {"yes"}}); err == nil {
		t.Fatal("expected an error")
	}
	if read(t, env, "/etc/fstab") != stockFstab {
		t.Fatalf("fstab must be as before: %q", read(t, env, "/etc/fstab"))
	}
}
