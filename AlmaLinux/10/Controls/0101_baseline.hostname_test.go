// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Danang Galuh Tegar Prasetyo

package controls

import (
	"context"
	"testing"

	"github.com/danang-id/server-hardening/internal/control"
)

func TestHostnameRoundTrip(t *testing.T) {
	ctx := context.Background()
	env, run := testEnv(t)
	c := &hostname{control.Base{M: control.Meta{ID: hostnameID}}}

	if st, _ := c.Check(ctx, env); st != control.NotApplied {
		t.Fatalf("before apply: got %v", st)
	}
	if err := c.Apply(ctx, env, control.Values{"hostname": {"Web-1.Example.com"}}); err != nil {
		t.Fatal(err)
	}
	if st, _ := c.Check(ctx, env); st != control.Applied {
		t.Fatalf("after apply: got %v", st)
	}
	if got := read(t, env, "/etc/hostname"); got != "web-1.example.com\n" {
		t.Fatalf("hostname file: %q", got)
	}
	if got := read(t, env, cloudInitPreserv); got != "preserve_hostname: true\n" {
		t.Fatalf("cloud-init file: %q", got)
	}
	if want := "hostnamectl set-hostname web-1.example.com"; run.calls[0] != want {
		t.Fatalf("command: %q", run.calls[0])
	}

	if err := c.Revert(ctx, env); err != nil {
		t.Fatal(err)
	}
	if st, _ := c.Check(ctx, env); st != control.NotApplied {
		t.Fatalf("after revert: got %v", st)
	}
	if got := read(t, env, "/etc/hostname"); got != "localhost.localdomain\n" {
		t.Fatalf("hostname not restored: %q", got)
	}
	if got := read(t, env, cloudInitPreserv); got != "<missing>" {
		t.Fatalf("cloud-init file should be gone: %q", got)
	}
	if last := run.calls[len(run.calls)-1]; last != "hostnamectl set-hostname localhost.localdomain" {
		t.Fatalf("revert command: %q", last)
	}
}

func TestHostnameRevertWithoutRecordLeavesItAlone(t *testing.T) {
	env, run := testEnv(t)
	c := &hostname{control.Base{M: control.Meta{ID: hostnameID}}}
	if err := c.Revert(context.Background(), env); err != nil {
		t.Fatal(err)
	}
	if len(run.calls) != 0 || read(t, env, "/etc/hostname") != "localhost.localdomain\n" {
		t.Fatal("revert without a record changed something")
	}
}

func TestValidFQDN(t *testing.T) {
	for _, ok := range []string{"web-1.example.com", "a.b"} {
		if err := validFQDN(ok); err != nil {
			t.Errorf("%q: %v", ok, err)
		}
	}
	for _, bad := range []string{"alma", "-a.example.com", "a..b", "a_b.example.com", ""} {
		if validFQDN(bad) == nil {
			t.Errorf("%q should be rejected", bad)
		}
	}
}
