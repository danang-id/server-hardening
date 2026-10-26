// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Danang Galuh Tegar Prasetyo

package controls

import (
	"context"
	"testing"

	"github.com/danang-id/server-hardening/internal/control"
)

func debsumsControl() *debsumsBaseline {
	return &debsumsBaseline{control.Base{M: control.Meta{ID: debsumsID}}}
}

func TestDebsumsInstallsAndRecordsBaseline(t *testing.T) {
	ctx := context.Background()
	env, run, s := sysEnv(t)
	run.out["debsums -c"] = "/usr/bin/ls\n/usr/sbin/sshd\n"
	run.fail["debsums -c"] = true // debsums exits with an error when files differ
	c := debsumsControl()
	if state(t, c, env) != control.NotApplied {
		t.Fatal("should start not applied")
	}
	must(t, c.Apply(ctx, env, nil))
	if !s.installed["debsums"] {
		t.Fatal("debsums should be installed")
	}
	got, _, _ := env.Rec.Get(debsumsID, "changed")
	if got != "/usr/bin/ls\n/usr/sbin/sshd" {
		t.Fatalf("baseline: %q", got)
	}
	if state(t, c, env) != control.Partial {
		t.Fatal("changed files make it partial")
	}
	if err := c.Revert(ctx, env); err != control.ErrNoRevert {
		t.Fatalf("want ErrNoRevert, got %v", err)
	}
}

func TestDebsumsCleanSystem(t *testing.T) {
	env, _, _ := sysEnv(t)
	c := debsumsControl()
	must(t, c.Apply(context.Background(), env, nil))
	if state(t, c, env) != control.Applied {
		t.Fatal("no changed file is applied")
	}
}

// A minimal image leaves out translated man pages. debsums reports every one of
// them and exits with status 2, which is no finding.
func TestDebsumsIgnoresDocumentationLeftOut(t *testing.T) {
	env, run, _ := sysEnv(t)
	run.out["debsums -c"] = "debsums: missing file /usr/share/man/de/man8/adduser.8.gz (from adduser package)\n" +
		"debsums: missing file /usr/share/doc/apt/changelog.gz (from apt package)\n" +
		"debsums: missing file /usr/share/locale/fr/LC_MESSAGES/apt.mo (from apt package)\n"
	run.fail["debsums -c"] = true
	c := debsumsControl()
	must(t, c.Apply(context.Background(), env, nil))
	if state(t, c, env) != control.Applied {
		t.Fatal("documentation left out is not a difference")
	}
}

// A program that a package lists but that is gone is a finding, next to a file
// that changed.
func TestDebsumsReportsMissingProgramsAndChangedFiles(t *testing.T) {
	env, run, _ := sysEnv(t)
	run.out["debsums -c"] = "debsums: missing file /usr/share/man/de/man8/adduser.8.gz (from adduser package)\n" +
		"debsums: missing file /usr/bin/ls (from coreutils package)\n" +
		"/etc/ssh/sshd_config\n"
	run.fail["debsums -c"] = true
	c := debsumsControl()
	must(t, c.Apply(context.Background(), env, nil))
	got, _, _ := env.Rec.Get(debsumsID, "changed")
	if got != "/etc/ssh/sshd_config\n/usr/bin/ls" {
		t.Fatalf("baseline: %q", got)
	}
	if state(t, c, env) != control.Partial {
		t.Fatal("findings make it partial")
	}
}

func TestDebsumsFailureWithoutOutputIsAnError(t *testing.T) {
	env, run, _ := sysEnv(t)
	run.fail["debsums -c"] = true
	if err := debsumsControl().Apply(context.Background(), env, nil); err == nil {
		t.Fatal("a failing debsums with no output is an error")
	}
	if env.Rec.Has(debsumsID) {
		t.Fatal("nothing may be recorded after a failure")
	}
}
