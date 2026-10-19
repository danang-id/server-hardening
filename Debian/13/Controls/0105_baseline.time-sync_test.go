// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Danang Galuh Tegar Prasetyo

package controls

import (
	"context"
	"testing"

	"github.com/danang-id/server-hardening/internal/control"
)

func syncControl() *timeSync { return &timeSync{control.Base{M: control.Meta{ID: syncID}}} }

func TestTimeSyncChronyRoundTrip(t *testing.T) {
	ctx := context.Background()
	env, run := testEnv(t)
	c := syncControl()

	must(t, c.Apply(ctx, env, control.Values{"service": {"chrony"}, "servers": {"0.pool.example 1.pool.example"}}))
	if got := read(t, env, chronyDropIn); got != "server 0.pool.example iburst\nserver 1.pool.example iburst\n" {
		t.Fatalf("drop-in: %q", got)
	}
	for _, want := range []string{"install chrony", "systemctl disable --now systemd-timesyncd", "systemctl enable --now chrony", "systemctl restart chrony"} {
		if !run.did(want) {
			t.Errorf("missing command %q in %v", want, run.calls)
		}
	}
	if run.did("disable --now chrony") {
		t.Fatal("the chosen service must not be disabled")
	}

	run.out["timedatectl show -p NTPSynchronized --value"] = "yes\n"
	if state(t, c, env) != control.Applied {
		t.Fatal("synchronised clock should be applied")
	}
	run.out["timedatectl show -p NTPSynchronized --value"] = "no\n"
	if state(t, c, env) != control.Partial {
		t.Fatal("unsynchronised clock should be partial")
	}
	run.fail["systemctl is-active --quiet chrony"] = true
	if state(t, c, env) != control.NotApplied {
		t.Fatal("stopped service should be not applied")
	}
	delete(run.fail, "systemctl is-active --quiet chrony")

	must(t, c.Revert(ctx, env))
	for _, want := range []string{"systemctl disable --now chrony", "systemctl enable systemd-timesyncd", "systemctl start systemd-timesyncd"} {
		if !run.did(want) {
			t.Errorf("missing revert command %q", want)
		}
	}
	if got := read(t, env, chronyDropIn); got != "<missing>" {
		t.Fatalf("drop-in should be gone: %q", got)
	}
	if env.Rec.Has(syncID) {
		t.Fatal("record should be deleted")
	}
}

func TestTimeSyncTimesyncdAndDefaultServers(t *testing.T) {
	ctx := context.Background()
	env, _ := testEnv(t)
	c := syncControl()

	must(t, c.Apply(ctx, env, control.Values{"service": {"systemd-timesyncd"}, "servers": {"ntp.example"}}))
	if got := read(t, env, timesyncDropIn); got != "[Time]\nNTP=ntp.example\n" {
		t.Fatalf("drop-in: %q", got)
	}
	must(t, c.Revert(ctx, env))

	must(t, c.Apply(ctx, env, control.Values{"service": {"chrony"}}))
	if got := read(t, env, chronyDropIn); got != "<missing>" {
		t.Fatalf("no servers means no drop-in, got %q", got)
	}
}

func TestTimeSyncRejectsBadInput(t *testing.T) {
	env, run := testEnv(t)
	c := syncControl()
	for _, in := range []control.Values{
		{"service": {"ntpd"}},
		{"service": {"chrony"}, "servers": {"bad host;rm -rf"}},
	} {
		if err := c.Apply(context.Background(), env, in); err == nil {
			t.Errorf("%v should be rejected", in)
		}
	}
	if run.did("disable") || run.did("install") {
		t.Fatal("a rejected apply changed something")
	}
}
