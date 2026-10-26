// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Danang Galuh Tegar Prasetyo

package controls

import (
	"context"
	"strings"
	"testing"

	"github.com/danang-id/server-hardening/internal/control"
)

func mirrorControl() *dnfMirror { return &dnfMirror{control.Base{M: control.Meta{ID: mirrorID}}} }

const appstreamRepo = "[appstream]\nname=AlmaLinux $releasever - AppStream\nmirrorlist=https://mirrors.almalinux.org/mirrorlist/$releasever/appstream\nenabled=1\ngpgcheck=1\n\n[appstream-debuginfo]\nname=debug\nmirrorlist=https://mirrors.almalinux.org/mirrorlist/$releasever/appstream-debuginfo\nenabled=0\n"

func TestDnfMirrorRoundTrip(t *testing.T) {
	ctx := context.Background()
	env, run := testEnv(t)
	put := func(p, s string) { must(t, writeTestFile(env, p, s)) }
	put("/etc/yum.repos.d/almalinux-appstream.repo", appstreamRepo)
	put("/etc/yum.repos.d/epel.repo", "[epel]\nmetalink=https://example/epel\n")
	baseBefore := read(t, env, "/etc/yum.repos.d/almalinux-baseos.repo")
	c := mirrorControl()

	must(t, c.Apply(ctx, env, control.Values{"mirror": {"https://mirror.example/almalinux/"}}))
	base := read(t, env, "/etc/yum.repos.d/almalinux-baseos.repo")
	for _, want := range []string{
		"# Managed by github.com/danang-id/server-hardening (baseline.dnf-mirror)\n",
		"[baseos]\nbaseurl=https://mirror.example/almalinux/$releasever/BaseOS/$basearch/os/\n",
		"# retired by server-hardening: mirrorlist=https://mirrors.almalinux.org/mirrorlist/$releasever/baseos\n",
		"gpgcheck=1\n",
	} {
		if !strings.Contains(base, want) {
			t.Errorf("baseos repo lacks %q:\n%s", want, base)
		}
	}
	app := read(t, env, "/etc/yum.repos.d/almalinux-appstream.repo")
	if !strings.Contains(app, "[appstream]\nbaseurl=https://mirror.example/almalinux/$releasever/AppStream/$basearch/os/\n") ||
		!strings.Contains(app, "[appstream-debuginfo]\nname=debug\nmirrorlist=https://mirrors.almalinux.org/mirrorlist/$releasever/appstream-debuginfo\n") {
		t.Errorf("appstream repo:\n%s", app)
	}
	if got := read(t, env, "/etc/yum.repos.d/epel.repo"); got != "[epel]\nmetalink=https://example/epel\n" {
		t.Errorf("other repositories must not change: %q", got)
	}
	if !run.did("dnf -y clean all") || !run.did("dnf -y makecache") {
		t.Fatalf("calls: %v", run.calls)
	}
	if state(t, c, env) != control.Applied {
		t.Fatal("not applied")
	}

	// Applying again with another mirror starts from the original files.
	must(t, c.Apply(ctx, env, control.Values{"mirror": {"https://other.example/alma"}}))
	if got := read(t, env, "/etc/yum.repos.d/almalinux-baseos.repo"); strings.Contains(got, "mirror.example") ||
		!strings.Contains(got, "baseurl=https://other.example/alma/$releasever/BaseOS/") || strings.Count(got, "Managed by") != 1 {
		t.Fatalf("second apply:\n%s", got)
	}

	must(t, c.Revert(ctx, env))
	if got := read(t, env, "/etc/yum.repos.d/almalinux-baseos.repo"); got != baseBefore {
		t.Fatalf("baseos repo not restored:\n%s", got)
	}
	if state(t, c, env) != control.NotApplied {
		t.Fatal("still applied")
	}
}

func TestDnfMirrorPutsFilesBackWhenTheMirrorFails(t *testing.T) {
	env, run := testEnv(t)
	run.fail["dnf -y makecache"] = true
	before := read(t, env, "/etc/yum.repos.d/almalinux-baseos.repo")
	if err := mirrorControl().Apply(context.Background(), env, control.Values{"mirror": {"https://dead.example/alma"}}); err == nil {
		t.Fatal("a mirror that cannot be read must fail")
	}
	if got := read(t, env, "/etc/yum.repos.d/almalinux-baseos.repo"); got != before {
		t.Fatalf("file not put back:\n%s", got)
	}
}

func TestDnfMirrorRejectsBadInput(t *testing.T) {
	env, run := testEnv(t)
	for _, bad := range []string{"http://insecure.example/alma", "https://a b.example", "https://x.example/$basearch", ""} {
		if err := mirrorControl().Apply(context.Background(), env, control.Values{"mirror": {bad}}); err == nil {
			t.Errorf("%q should be rejected", bad)
		}
	}
	if run.did("dnf") {
		t.Fatal("dnf ran for an invalid mirror")
	}
}
