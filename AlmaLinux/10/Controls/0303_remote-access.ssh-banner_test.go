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

func bannerControl() *sshBanner { return &sshBanner{control.Base{M: control.Meta{ID: bannerID}}} }

func TestBanner(t *testing.T) {
	ctx := context.Background()
	env, run, sim := sshEnv(t)
	c := bannerControl()
	must(t, c.Apply(ctx, env, control.Values{"text": {"  Keep out.\nReally.  \n"}}))
	if got := read(t, env, bannerFile); got != "Keep out.\nReally.\n" {
		t.Fatalf("banner file: %q", got)
	}
	wantContains(t, dropIn(t, env, "banner"), "Banner "+bannerFile)
	if sim.effective()["banner"][0] != bannerFile {
		t.Fatal("banner not in force")
	}
	if state(t, c, env) != control.Applied {
		t.Fatal("should be applied")
	}
	run.calls = nil
	must(t, c.Revert(ctx, env))
	noFile(t, env, bannerFile)
	noFile(t, env, sshdFile("banner"))
	if env.Rec.Has(bannerID) {
		t.Fatal("record should be gone")
	}
	// The setting must leave before the file does: the reload is the last step
	// that touches sshd, and the file is gone after it.
	if !run.did("systemctl reload sshd") {
		t.Fatalf("sshd must reload: %v", run.calls)
	}
}

func TestBannerPartialWhenFileGone(t *testing.T) {
	ctx := context.Background()
	env, _, _ := sshEnv(t)
	c := bannerControl()
	must(t, c.Apply(ctx, env, control.Values{"text": {"Notice"}}))
	must(t, os.Remove(env.Path(bannerFile)))
	if state(t, c, env) != control.Partial {
		t.Fatal("setting without its file is partial")
	}
}

func TestBannerKeepsExistingFile(t *testing.T) {
	ctx := context.Background()
	env, _, _ := sshEnv(t)
	writeFile(t, env, bannerFile, "old banner\n")
	c := bannerControl()
	must(t, c.Apply(ctx, env, control.Values{"text": {"new banner"}}))
	must(t, c.Revert(ctx, env))
	if read(t, env, bannerFile) != "old banner\n" {
		t.Fatal("the earlier banner must come back")
	}
}

func TestBannerValidation(t *testing.T) {
	env, _, _ := sshEnv(t)
	c := bannerControl()
	if err := c.Apply(context.Background(), env, control.Values{"text": {"  \n"}}); err == nil {
		t.Error("empty banner accepted")
	}
	ins, _ := c.Inputs(context.Background(), env)
	if err := ins[0].Validate(strings.Repeat("x", 5000)); err == nil {
		t.Error("long banner accepted")
	}
	if ins[0].Default == "" || ins[0].Kind != control.TextArea {
		t.Error("a default notice in a text area is expected")
	}
}

func TestBannerFailureRestoresFile(t *testing.T) {
	env, run, _ := sshEnv(t)
	run.hook = chain(run.hook, func(f *fakeRunner, cmd string) {
		if cmd == "sshd -t" {
			f.fail[cmd] = true
		}
	})
	if err := bannerControl().Apply(context.Background(), env, control.Values{"text": {"Notice"}}); err == nil {
		t.Fatal("expected an error")
	}
	noFile(t, env, bannerFile)
}
