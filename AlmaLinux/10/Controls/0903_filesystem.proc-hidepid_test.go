// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Danang Galuh Tegar Prasetyo

package controls

import (
	"context"
	"strings"
	"testing"

	"github.com/danang-id/server-hardening/internal/control"
)

func hidepidControl() *procHidepid {
	return &procHidepid{control.Base{M: control.Meta{ID: hidepidID}}}
}

// hidepidEnv has accounts, and makes group tools work on /etc/group.
func hidepidEnv(t *testing.T) (*control.Env, *fakeRunner, *mountSim) {
	env, run, _, m := mountEnv(t)
	writeFile(t, env, "/etc/fstab", stockFstab)
	writeFile(t, env, "/etc/passwd", basePasswd)
	writeFile(t, env, "/etc/group", baseGroup)
	prev := run.hook
	run.hook = func(f *fakeRunner, cmd string) {
		prev(f, cmd)
		fields := strings.Fields(cmd)
		g := read(t, env, "/etc/group")
		switch {
		case fields[0] == "getent" && len(fields) == 3:
			delete(f.fail, cmd)
			f.fail[cmd] = true
			for l := range strings.SplitSeq(g, "\n") {
				if strings.HasPrefix(l, fields[2]+":") {
					f.out[cmd] = l + "\n"
					delete(f.fail, cmd)
				}
			}
		case fields[0] == "groupadd":
			writeFile(t, env, "/etc/group", g+fields[2]+":x:998:\n")
		case fields[0] == "groupdel":
			writeFile(t, env, "/etc/group", strings.ReplaceAll(g, fields[1]+":x:998:\n", ""))
		case fields[0] == "usermod":
			writeFile(t, env, "/etc/group", strings.ReplaceAll(g, fields[2]+":x:998:", fields[2]+":x:998:"+fields[3]))
		case fields[0] == "mount" && strings.HasPrefix(fields[2], "remount,hidepid="):
			opts := strings.Split(fields[2], ",")[1:]
			m.opts["/proc"] = "rw,nosuid,nodev,noexec,relatime," + strings.Join(opts, ",")
		}
	}
	return env, run, m
}

func TestHidepidCreatesGroupAndMounts(t *testing.T) {
	ctx := context.Background()
	env, run, m := hidepidEnv(t)
	c := hidepidControl()
	if state(t, c, env) != control.NotApplied {
		t.Fatal("should start not applied")
	}
	in, _ := c.Inputs(ctx, env)
	if in[2].Default != "" {
		// alice is in no sudo group yet in this fixture
		t.Fatalf("members default: %q", in[2].Default)
	}
	must(t, c.Apply(ctx, env, control.Values{"level": {"invisible"}, "group": {"procadmin"}, "members": {"alice"}}))
	wantContains(t, read(t, env, "/etc/fstab"), stockFstab, managed(hidepidID), "proc /proc proc defaults,hidepid=invisible,gid=998 0 0")
	if !run.did("groupadd --system procadmin") || !run.did("usermod -aG procadmin alice") {
		t.Fatalf("calls: %v", run.calls)
	}
	if !strings.Contains(m.opts["/proc"], "hidepid=invisible,gid=998") {
		t.Fatalf("options: %s", m.opts["/proc"])
	}
	if state(t, c, env) != control.Applied {
		t.Fatal("should be applied")
	}
	m.opts["/proc"] = "rw,nosuid,nodev,noexec,relatime,hidepid=2,gid=998"
	if state(t, c, env) != control.Applied {
		t.Fatal("the number 2 is the same as invisible")
	}
	m.opts["/proc"] = "rw,nosuid,nodev,noexec,relatime"
	if state(t, c, env) != control.Partial {
		t.Fatal("a mount without hidepid is partial")
	}
	m.opts["/proc"] = "rw,nosuid,nodev,noexec,relatime,hidepid=invisible,gid=998"

	must(t, c.Revert(ctx, env))
	if read(t, env, "/etc/fstab") != stockFstab {
		t.Fatalf("fstab: %q", read(t, env, "/etc/fstab"))
	}
	if !strings.Contains(m.opts["/proc"], "hidepid=off,gid=0") {
		t.Fatalf("options after revert: %s", m.opts["/proc"])
	}
	if !run.did("groupdel procadmin") {
		t.Fatal("the group this control created must be removed")
	}
	if env.Rec.Has(hidepidID) {
		t.Fatal("record should be gone")
	}
}

func TestHidepidExistingGroupKeepsGroupOnRevert(t *testing.T) {
	ctx := context.Background()
	env, run, _ := hidepidEnv(t)
	writeFile(t, env, "/etc/group", baseGroup+"monitor:x:998:\n")
	c := hidepidControl()
	must(t, c.Apply(ctx, env, control.Values{"level": {"noaccess"}, "group": {"monitor"}, "members": {"alice"}}))
	if run.did("groupadd") {
		t.Fatal("the group exists already")
	}
	wantContains(t, read(t, env, "/etc/fstab"), "hidepid=noaccess,gid=998")
	must(t, c.Revert(ctx, env))
	if run.did("groupdel") {
		t.Fatal("a group this control did not create must stay")
	}
	if !run.did("gpasswd -d alice monitor") {
		t.Fatalf("the member this control added must be removed: %v", run.calls)
	}
}

func TestHidepidRefusesUnknownMemberAndBadInput(t *testing.T) {
	env, run, _ := hidepidEnv(t)
	c := hidepidControl()
	for _, v := range []control.Values{
		{"level": {"invisible"}, "group": {"procadmin"}, "members": {"nobody-here"}},
		{"level": {"off"}, "group": {"procadmin"}},
		{"level": {"invisible"}, "group": {"Bad Name"}},
	} {
		if err := c.Apply(context.Background(), env, v); err == nil {
			t.Fatalf("%v must be refused", v)
		}
	}
	if run.did("groupadd") || read(t, env, "/etc/fstab") != stockFstab {
		t.Fatal("nothing may change after a refusal")
	}
}

func TestHidepidRemountFailureUndoes(t *testing.T) {
	env, run, _ := hidepidEnv(t)
	run.fail["mount -o remount,hidepid=invisible,gid=998 /proc"] = true
	if err := hidepidControl().Apply(context.Background(), env, control.Values{"level": {"invisible"}, "group": {"procadmin"}}); err == nil {
		t.Fatal("expected an error")
	}
	if read(t, env, "/etc/fstab") != stockFstab {
		t.Fatal("fstab must be restored")
	}
	if !run.did("groupdel procadmin") || env.Rec.Has(hidepidID) {
		t.Fatalf("the new group and the record must go: %v", run.calls)
	}
}
