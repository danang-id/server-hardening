// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Danang Galuh Tegar Prasetyo

package controls

import (
	"context"
	"strings"
	"testing"

	"github.com/danang-id/server-hardening/internal/control"
)

func tmpControl() *tmpHardening { return &tmpHardening{control.Base{M: control.Meta{ID: tmpID}}} }

func TestTmpHardeningOnTmpfs(t *testing.T) {
	ctx := context.Background()
	env, run, _, m := mountEnv(t)
	c := tmpControl()
	if state(t, c, env) != control.NotApplied {
		t.Fatal("should start not applied")
	}
	must(t, c.Apply(ctx, env, control.Values{"size": {"25%"}, "noexec": {"yes"}}))
	wantContains(t, read(t, env, tmpDropIn), managed(tmpID), "[Mount]",
		"Options=mode=1777,strictatime,nosuid,nodev,noexec,size=25%,nr_inodes=1m")
	if !run.did("systemctl daemon-reload") || !run.did("systemctl reload tmp.mount") {
		t.Fatalf("calls: %v", run.calls)
	}
	if !strings.Contains(m.opts["/tmp"], "noexec") || !strings.Contains(m.opts["/tmp"], "nosuid") {
		t.Fatalf("options: %s", m.opts["/tmp"])
	}
	if state(t, c, env) != control.Applied {
		t.Fatal("should be applied")
	}

	must(t, c.Revert(ctx, env))
	noFile(t, env, tmpDropIn)
	if strings.Contains(m.opts["/tmp"], "noexec") {
		t.Fatalf("noexec must be gone after the revert: %s", m.opts["/tmp"])
	}
	if env.Rec.Has(tmpID) {
		t.Fatal("record should be gone")
	}
}

func TestTmpWithoutNoexec(t *testing.T) {
	env, _, _, m := mountEnv(t)
	c := tmpControl()
	must(t, c.Apply(context.Background(), env, control.Values{"size": {"50%"}, "noexec": {"no"}}))
	if strings.Contains(read(t, env, tmpDropIn), "noexec") || strings.Contains(m.opts["/tmp"], "noexec") {
		t.Fatal("noexec was not asked for")
	}
	if state(t, c, env) != control.Applied {
		t.Fatal("should be applied")
	}
}

func TestTmpReloadFailureFallsBackToRemount(t *testing.T) {
	env, run, _, m := mountEnv(t)
	run.fail["systemctl reload tmp.mount"] = true
	must(t, tmpControl().Apply(context.Background(), env, control.Values{"size": {"50%"}, "noexec": {"yes"}}))
	if !strings.Contains(m.opts["/tmp"], "noexec") {
		t.Fatalf("the fallback remount must set noexec: %s", m.opts["/tmp"])
	}
}

func TestTmpNotTmpfsEnablesTheMount(t *testing.T) {
	env, _, s, m := mountEnv(t)
	m.fstype["/tmp"] = "ext4"
	var warned []string
	env.Log = &memLog{warns: &warned}
	c := tmpControl()
	must(t, c.Apply(context.Background(), env, control.Values{"size": {"50%"}, "noexec": {"yes"}}))
	if !s.enabled[tmpUnit] || !s.active[tmpUnit] {
		t.Fatal("tmp.mount should be enabled and started")
	}
	if !strings.Contains(strings.Join(warned, "\n"), "hidden") {
		t.Fatalf("the person must be told that files are hidden: %v", warned)
	}
	must(t, c.Revert(context.Background(), env))
	if s.enabled[tmpUnit] || s.active[tmpUnit] {
		t.Fatal("the mount this control turned on must be turned off again")
	}
}

// /tmp is a plain directory on the root file system (AlmaLinux). findmnt /tmp
// fails there, so the control must ask for the file system that holds it.
func TestTmpThatIsNoMountPointGetsTheMount(t *testing.T) {
	env, _, s, m := mountEnv(t)
	delete(m.opts, "/tmp")
	delete(m.fstype, "/tmp")
	m.opts["/"] = "rw,relatime,seclabel"
	m.fstype["/"] = "xfs"
	var warned []string
	env.Log = &memLog{warns: &warned}
	c := tmpControl()
	must(t, c.Apply(context.Background(), env, control.Values{"size": {"50%"}, "noexec": {"yes"}}))
	wantContains(t, read(t, env, tmpDropIn), "noexec")
	if !s.enabled[tmpUnit] || !s.active[tmpUnit] {
		t.Fatal("tmp.mount should be enabled and started")
	}
	if !strings.Contains(strings.Join(warned, "\n"), "xfs") {
		t.Fatalf("the person must be told that /tmp is on xfs: %v", warned)
	}
	must(t, c.Revert(context.Background(), env))
	if s.enabled[tmpUnit] || s.active[tmpUnit] {
		t.Fatal("the mount this control turned on must be turned off again")
	}
}

func TestTmpRefusesWhenFstabHasAnEntry(t *testing.T) {
	env, _, _, _ := mountEnv(t)
	writeFile(t, env, "/etc/fstab", "UUID=1 / ext4 defaults 0 1\ntmpfs /tmp tmpfs defaults 0 0\n")
	err := tmpControl().Apply(context.Background(), env, control.Values{"size": {"50%"}, "noexec": {"yes"}})
	if err == nil || !strings.Contains(err.Error(), "/etc/fstab") {
		t.Fatalf("want a message about fstab, got %v", err)
	}
	noFile(t, env, tmpDropIn)
}

func TestTmpRejectsBadSize(t *testing.T) {
	env, _, _, _ := mountEnv(t)
	for _, s := range []string{"huge", "0", "50%\nOptions=exec", "5 0%"} {
		if err := tmpControl().Apply(context.Background(), env, control.Values{"size": {s}, "noexec": {"yes"}}); err == nil {
			t.Fatalf("%q must be refused", s)
		}
	}
}
