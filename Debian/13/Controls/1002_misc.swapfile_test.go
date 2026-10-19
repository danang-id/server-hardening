// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Danang Galuh Tegar Prasetyo

package controls

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/danang-id/server-hardening/internal/control"
)

func swapControl() *swapfile { return &swapfile{control.Base{M: control.Meta{ID: swapID}}} }

// swapEnv simulates swapon, swapoff, df and file creation tools.
func swapEnv(t *testing.T, freeBytes string) (*control.Env, *fakeRunner, map[string]bool) {
	env, run, _ := sysEnv(t)
	active := map[string]bool{}
	writeFile(t, env, "/etc/fstab", stockFstab)
	run.out["df --output=avail -B1 /"] = "Avail\n" + freeBytes + "\n"
	run.out["findmnt -n -o FSTYPE -T /"] = "ext4\n"
	prev := run.hook
	run.hook = func(f *fakeRunner, cmd string) {
		prev(f, cmd)
		fields := strings.Fields(cmd)
		switch {
		case cmd == "swapon --show=NAME --noheadings":
			var b strings.Builder
			for p, on := range active {
				if on {
					b.WriteString(p)
					b.WriteString("\n")
				}
			}
			f.out[cmd] = b.String()
		case fields[0] == "swapon" && len(fields) == 2:
			active[fields[1]] = !f.fail[cmd]
		case fields[0] == "swapoff":
			if !f.fail[cmd] {
				active[fields[1]] = false
			}
		}
	}
	return env, run, active
}

func TestSwapfileCreateAndRevert(t *testing.T) {
	ctx := context.Background()
	env, run, active := swapEnv(t, "20000000000")
	c := swapControl()
	if state(t, c, env) != control.NotApplied {
		t.Fatal("should start not applied")
	}
	must(t, c.Apply(ctx, env, control.Values{"size": {"2G"}, "path": {"/swapfile"}}))
	fi, err := os.Stat(env.Path("/swapfile"))
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("the file must exist with mode 0600: %v %v", fi, err)
	}
	for _, want := range []string{"fallocate -l 2147483648 /swapfile", "mkswap /swapfile", "swapon /swapfile"} {
		if !run.did(want) {
			t.Fatalf("missing %q in %v", want, run.calls)
		}
	}
	wantContains(t, read(t, env, "/etc/fstab"), stockFstab, "/swapfile none swap sw 0 0")
	if !active["/swapfile"] || state(t, c, env) != control.Applied {
		t.Fatal("swap should be active")
	}
	must(t, os.Chmod(env.Path("/swapfile"), 0o644))
	if state(t, c, env) != control.Partial {
		t.Fatal("a readable swap file is partial")
	}

	must(t, c.Revert(ctx, env))
	if active["/swapfile"] || read(t, env, "/etc/fstab") != stockFstab {
		t.Fatal("swap off and fstab restored")
	}
	noFile(t, env, "/swapfile")
	if env.Rec.Has(swapID) {
		t.Fatal("record should be gone")
	}
}

func TestSwapfileSkipsWhenSwapExists(t *testing.T) {
	env, run, active := swapEnv(t, "20000000000")
	active["/dev/vda2"] = true
	c := swapControl()
	if state(t, c, env) != control.Applied {
		t.Fatal("a server with swap meets the purpose")
	}
	must(t, c.Apply(context.Background(), env, control.Values{"size": {"2G"}, "path": {"/swapfile"}}))
	if run.did("mkswap") || env.Rec.Has(swapID) {
		t.Fatal("nothing may be created")
	}
	noFile(t, env, "/swapfile")
}

func TestSwapfileRefusals(t *testing.T) {
	ctx := context.Background()
	env, run, _ := swapEnv(t, "2500000000") // 2.3 GiB: not enough for 2G plus margin
	c := swapControl()
	if err := c.Apply(ctx, env, control.Values{"size": {"2G"}, "path": {"/swapfile"}}); err == nil || !strings.Contains(err.Error(), "margin") {
		t.Fatalf("not enough room: %v", err)
	}
	run.out["findmnt -n -o FSTYPE -T /"] = "btrfs\n"
	run.out["df --output=avail -B1 /"] = "Avail\n90000000000\n"
	if err := c.Apply(ctx, env, control.Values{"size": {"2G"}, "path": {"/swapfile"}}); err == nil || !strings.Contains(err.Error(), "btrfs") {
		t.Fatalf("btrfs: %v", err)
	}
	for _, v := range []control.Values{
		{"size": {"lots"}, "path": {"/swapfile"}},
		{"size": {"2G"}, "path": {"swapfile"}},
		{"size": {"2G"}, "path": {"/a b"}},
		{"size": {"2G"}, "path": {"/../etc/x"}},
	} {
		if err := c.Apply(ctx, env, v); err == nil {
			t.Fatalf("%v must be refused", v)
		}
	}
	noFile(t, env, "/swapfile")
	if env.Rec.Has(swapID) {
		t.Fatal("no record after refusals")
	}
	writeFile(t, env, "/swapfile", "mine")
	run.out["findmnt -n -o FSTYPE -T /"] = "ext4\n"
	if err := c.Apply(ctx, env, control.Values{"size": {"2G"}, "path": {"/swapfile"}}); err == nil {
		t.Fatal("an existing file must never be overwritten")
	}
	if read(t, env, "/swapfile") != "mine" {
		t.Fatal("the existing file must stay")
	}
}

func TestSwapfileFallbackAndFailureCleanup(t *testing.T) {
	env, run, _ := swapEnv(t, "20000000000")
	run.fail["fallocate -l 1073741824 /swapfile"] = true
	run.fail["mkswap /swapfile"] = true
	err := swapControl().Apply(context.Background(), env, control.Values{"size": {"1G"}, "path": {"/swapfile"}})
	if err == nil {
		t.Fatal("expected an error")
	}
	if !run.did("dd if=/dev/zero of=/swapfile bs=1M count=1024") {
		t.Fatalf("dd is the fallback when fallocate fails: %v", run.calls)
	}
	noFile(t, env, "/swapfile")
	if read(t, env, "/etc/fstab") != stockFstab || env.Rec.Has(swapID) {
		t.Fatal("everything must be undone")
	}
}

func TestSwapfileRevertStopsWhenSwapoffFails(t *testing.T) {
	env, run, _ := swapEnv(t, "20000000000")
	c := swapControl()
	must(t, c.Apply(context.Background(), env, control.Values{"size": {"1G"}, "path": {"/swapfile"}}))
	run.fail["swapoff /swapfile"] = true
	err := c.Revert(context.Background(), env)
	if err == nil || !strings.Contains(err.Error(), "free memory") {
		t.Fatalf("want a message about memory, got %v", err)
	}
	if read(t, env, "/swapfile") == "<missing>" || !env.Rec.Has(swapID) {
		t.Fatal("a failed revert must leave file and record alone")
	}
}
