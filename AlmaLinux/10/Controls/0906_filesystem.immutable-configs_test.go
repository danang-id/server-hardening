// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Danang Galuh Tegar Prasetyo

package controls

import (
	"context"
	"strings"
	"testing"

	"github.com/danang-id/server-hardening/internal/control"
)

func immutableControl() *immutableConfigs {
	return &immutableConfigs{control.Base{M: control.Meta{ID: immutableID}}}
}

// attrSim makes chattr and lsattr work on a set of flagged paths.
func attrSim(run *fakeRunner, flagged map[string]bool) {
	prev := run.hook
	run.hook = func(f *fakeRunner, cmd string) {
		if prev != nil {
			prev(f, cmd)
		}
		fields := strings.Fields(cmd)
		switch {
		case len(fields) == 3 && fields[0] == "chattr" && fields[1] == "+i":
			flagged[fields[2]] = !f.fail[cmd]
		case len(fields) == 3 && fields[0] == "chattr" && fields[1] == "-i":
			flagged[fields[2]] = false
		case len(fields) == 3 && fields[0] == "lsattr":
			if flagged[fields[2]] {
				f.out[cmd] = "----i---------e------- " + fields[2] + "\n"
			} else {
				f.out[cmd] = "--------------e------- " + fields[2] + "\n"
			}
		}
	}
}

func immutableEnv(t *testing.T) (*control.Env, *fakeRunner, map[string]bool) {
	env, run, _ := sysEnv(t)
	flagged := map[string]bool{}
	attrSim(run, flagged)
	writeFile(t, env, "/etc/sysctl.d/99-server-hardening-kernel.conf", managed("x")+"\n")
	writeFile(t, env, "/etc/sysctl.d/10-other.conf", "kernel.sysrq = 1\n")
	writeFile(t, env, "/etc/ssh/sshd_config.d/00-server-hardening-port.conf", managed("y")+"\n")
	writeFile(t, env, "/etc/passwd", "root:x:0:0\n")
	return env, run, flagged
}

func TestImmutableOffersOnlyFilesOfThisTool(t *testing.T) {
	env, _, _ := immutableEnv(t)
	in, _ := immutableControl().Inputs(context.Background(), env)
	if len(in) != 2 || in[0].Key != "files" {
		t.Fatalf("inputs: %+v", in)
	}
	var got []string
	for _, o := range in[0].Options {
		got = append(got, o.Value)
	}
	want := "/etc/ssh/sshd_config.d/00-server-hardening-port.conf,/etc/sysctl.d/99-server-hardening-kernel.conf"
	if strings.Join(got, ",") != want || strings.Join(in[0].DefaultMulti, ",") != want {
		t.Fatalf("offered %v, ticked %v", got, in[0].DefaultMulti)
	}
}

func TestImmutableLockAndUnlock(t *testing.T) {
	ctx := context.Background()
	env, _, flagged := immutableEnv(t)
	c := immutableControl()
	if state(t, c, env) != control.NotApplied {
		t.Fatal("should start not applied")
	}
	f1, f2 := "/etc/sysctl.d/99-server-hardening-kernel.conf", "/etc/sysctl.d/10-other.conf"
	must(t, c.Apply(ctx, env, control.Values{"files": {f1}, "extra": {f2}}))
	if !flagged[f1] || !flagged[f2] {
		t.Fatalf("flags: %v", flagged)
	}
	if state(t, c, env) != control.Applied {
		t.Fatal("should be applied")
	}
	flagged[f2] = false // someone ran chattr -i
	if state(t, c, env) != control.Partial {
		t.Fatal("a file that lost its flag is partial")
	}
	flagged[f2] = true
	must(t, c.Revert(ctx, env))
	if flagged[f1] || flagged[f2] || env.Rec.Has(immutableID) {
		t.Fatalf("revert: %v", flagged)
	}
}

func TestImmutableRefusals(t *testing.T) {
	env, _, flagged := immutableEnv(t)
	c := immutableControl()
	for _, v := range []control.Values{
		{"extra": {"/etc/passwd"}},
		{"extra": {"/etc/shadow"}},
		{"extra": {"/var/log/syslog"}},
		{"extra": {"/var/lib/rpm/rpmdb.sqlite"}},
		{"extra": {"etc/relative"}},
		{"extra": {"/etc/../etc/passwd"}},
		{"extra": {"/etc/nothere.conf"}},
		{"files": {"/etc/sysctl.d/10-other.conf"}}, // not a file this tool wrote
	} {
		if err := c.Apply(context.Background(), env, v); err == nil {
			t.Fatalf("%v must be refused", v)
		}
	}
	if len(flagged) != 0 {
		t.Fatalf("nothing may be locked: %v", flagged)
	}
}

func TestImmutableUnsupportedFilesystem(t *testing.T) {
	env, run, flagged := immutableEnv(t)
	f1 := "/etc/sysctl.d/99-server-hardening-kernel.conf"
	run.fail["chattr +i "+f1] = true
	c := immutableControl()
	if err := c.Apply(context.Background(), env, control.Values{"files": {f1}}); err == nil {
		t.Fatal("if nothing can be locked, say so")
	}
	// One of two works: the control continues and records only that one.
	f2 := "/etc/ssh/sshd_config.d/00-server-hardening-port.conf"
	must(t, c.Apply(context.Background(), env, control.Values{"files": {f1, f2}}))
	if flagged[f1] || !flagged[f2] {
		t.Fatalf("flags: %v", flagged)
	}
	if v, _, _ := env.Rec.Get(immutableID, "files"); v != f2 {
		t.Fatalf("record: %q", v)
	}
}
