// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Danang Galuh Tegar Prasetyo

package controls

import (
	"context"
	"testing"

	"github.com/danang-id/server-hardening/internal/control"
)

func rpmVerifyControl() *rpmVerifyBaseline {
	return &rpmVerifyBaseline{control.Base{M: control.Meta{ID: rpmVerifyID}}}
}

const rpmVa = "rpm -Va --nomtime"

func TestRPMVerifyRecordsBaseline(t *testing.T) {
	ctx := context.Background()
	env, run, _ := sysEnv(t)
	run.out[rpmVa] = "S.5....T.    /usr/bin/ls\n..5......    /usr/sbin/sshd\n"
	run.fail[rpmVa] = true // rpm exits with an error when files differ
	c := rpmVerifyControl()
	if state(t, c, env) != control.NotApplied {
		t.Fatal("should start not applied")
	}
	must(t, c.Apply(ctx, env, nil))
	got, _, _ := env.Rec.Get(rpmVerifyID, "changed")
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

func TestRPMVerifyCleanSystem(t *testing.T) {
	env, _, _ := sysEnv(t)
	c := rpmVerifyControl()
	must(t, c.Apply(context.Background(), env, nil))
	if state(t, c, env) != control.Applied {
		t.Fatal("no changed file is applied")
	}
}

// People change configuration files, authselect changes links and modes, and
// a minimal image leaves out documentation. None of this is a finding.
func TestRPMVerifyIgnoresExpectedDifferences(t *testing.T) {
	env, run, _ := sysEnv(t)
	run.out[rpmVa] = "S.5....T.  c /etc/ssh/sshd_config\n" +
		".M.......  g /var/log/lastlog\n" +
		"....L....    /etc/pam.d/system-auth\n" +
		".M.......    /usr/bin/ping\n" +
		"missing     d /usr/share/doc/foo/README\n" +
		"missing        /usr/share/man/de/man8/adduser.8.gz\n" +
		"missing     c /etc/foo.conf\n"
	run.fail[rpmVa] = true
	c := rpmVerifyControl()
	must(t, c.Apply(context.Background(), env, nil))
	if state(t, c, env) != control.Applied {
		got, _, _ := env.Rec.Get(rpmVerifyID, "changed")
		t.Fatalf("expected differences are no finding, got %q", got)
	}
}

// A program that a package lists but that is gone is a finding, next to a file
// that changed.
func TestRPMVerifyReportsMissingProgramsAndChangedFiles(t *testing.T) {
	env, run, _ := sysEnv(t)
	run.out[rpmVa] = "missing        /usr/share/man/de/man8/adduser.8.gz\n" +
		"missing        /usr/bin/ls\n" +
		"S.5....T.      /etc/ssh/ssh_config.d/05-redhat.conf\n"
	run.fail[rpmVa] = true
	c := rpmVerifyControl()
	must(t, c.Apply(context.Background(), env, nil))
	got, _, _ := env.Rec.Get(rpmVerifyID, "changed")
	if got != "/etc/ssh/ssh_config.d/05-redhat.conf\n/usr/bin/ls" {
		t.Fatalf("baseline: %q", got)
	}
	if state(t, c, env) != control.Partial {
		t.Fatal("findings make it partial")
	}
}

func TestRPMVerifyOnlyNewFilesAreNew(t *testing.T) {
	ctx := context.Background()
	env, run, _ := sysEnv(t)
	run.out[rpmVa] = "..5......    /usr/bin/ls\n"
	run.fail[rpmVa] = true
	var warned []string
	env.Log = &memLog{&warned}
	c := rpmVerifyControl()
	must(t, c.Apply(ctx, env, nil))
	warned = nil
	run.out[rpmVa] = "..5......    /usr/bin/ls\n..5......    /usr/bin/cp\n"
	must(t, c.Apply(ctx, env, nil))
	if len(warned) != 2 || warned[1] != "  /usr/bin/cp" {
		t.Fatalf("only the new file is shown: %q", warned)
	}
}

func TestRPMVerifyFailureWithoutOutputIsAnError(t *testing.T) {
	env, run, _ := sysEnv(t)
	run.fail[rpmVa] = true
	if err := rpmVerifyControl().Apply(context.Background(), env, nil); err == nil {
		t.Fatal("a failing rpm with no output is an error")
	}
	if env.Rec.Has(rpmVerifyID) {
		t.Fatal("nothing may be recorded after a failure")
	}
}
