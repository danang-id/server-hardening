// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Danang Galuh Tegar Prasetyo

package controls

import (
	"context"
	"strings"
	"testing"

	"github.com/danang-id/server-hardening/internal/control"
)

func syncControl() *timeSync { return &timeSync{control.Base{M: control.Meta{ID: syncID}}} }

const stockChrony = "pool 2.almalinux.pool.ntp.org iburst\ndriftfile /var/lib/chrony/drift\n"

func TestTimeSyncRoundTrip(t *testing.T) {
	ctx := context.Background()
	env, run := testEnv(t)
	must(t, writeTestFile(env, chronyConf, stockChrony))
	run.fail["systemctl is-active --quiet systemd-timesyncd"] = true
	run.fail["systemctl is-enabled --quiet systemd-timesyncd"] = true
	run.fail["systemctl is-active --quiet ntpd"] = true
	run.fail["systemctl is-enabled --quiet ntpd"] = true
	run.fail["systemctl is-active --quiet ntpsec"] = true
	run.fail["systemctl is-enabled --quiet ntpsec"] = true
	run.fail["systemctl is-active --quiet openntpd"] = true
	run.fail["systemctl is-enabled --quiet openntpd"] = true
	run.fail["rpm -q --quiet chrony"] = true // not installed yet
	c := syncControl()

	must(t, c.Apply(ctx, env, control.Values{"servers": {"0.pool.example 1.pool.example"}}))
	if got := read(t, env, chronyDropIn); !strings.Contains(got, "server 0.pool.example iburst\nserver 1.pool.example iburst\n") {
		t.Fatalf("drop-in: %q", got)
	}
	if got := read(t, env, chronyConf); !strings.HasPrefix(got, stockChrony) || !strings.Contains(got, "\nconfdir /etc/chrony.d\n") {
		t.Fatalf("chrony.conf must keep its lines and read the drop-in folder: %q", got)
	}
	for _, want := range []string{"rpm -q --quiet chrony", "dnf -y install chrony", "systemctl enable --now chronyd", "systemctl restart chronyd"} {
		if !run.did(want) {
			t.Errorf("missing command %q in %v", want, run.calls)
		}
	}

	run.out["timedatectl show -p NTPSynchronized --value"] = "yes\n"
	if state(t, c, env) != control.Applied {
		t.Fatal("synchronised clock should be applied")
	}
	run.out["timedatectl show -p NTPSynchronized --value"] = "no\n"
	if state(t, c, env) != control.Pending {
		t.Fatal("unsynchronised clock should be pending")
	}
	run.fail["systemctl is-active --quiet chronyd"] = true
	if state(t, c, env) != control.NotApplied {
		t.Fatal("stopped service should be not applied")
	}
	delete(run.fail, "systemctl is-active --quiet chronyd")

	must(t, c.Revert(ctx, env))
	if !run.did("systemctl disable --now chronyd") {
		t.Errorf("missing revert command in %v", run.calls)
	}
	if got := read(t, env, chronyDropIn); got != "<missing>" {
		t.Fatalf("drop-in should be gone: %q", got)
	}
	if got := read(t, env, chronyConf); got != stockChrony {
		t.Fatalf("chrony.conf not restored: %q", got)
	}
	if env.Rec.Has(syncID) {
		t.Fatal("record should be deleted")
	}
}

func TestTimeSyncWithoutServersKeepsTheDefaultPool(t *testing.T) {
	ctx := context.Background()
	env, _ := testEnv(t)
	must(t, writeTestFile(env, chronyConf, stockChrony))
	must(t, syncControl().Apply(ctx, env, control.Values{}))
	if got := read(t, env, chronyDropIn); got != "<missing>" {
		t.Fatalf("no servers means no drop-in, got %q", got)
	}
	if got := read(t, env, chronyConf); got != stockChrony {
		t.Fatalf("chrony.conf must stay as it is: %q", got)
	}
}

func TestTimeSyncDoesNotAddTheIncludeTwice(t *testing.T) {
	env, _ := testEnv(t)
	must(t, writeTestFile(env, chronyConf, stockChrony+"confdir /etc/chrony.d\n"))
	must(t, syncControl().Apply(context.Background(), env, control.Values{"servers": {"ntp.example"}}))
	if got := read(t, env, chronyConf); strings.Count(got, "confdir") != 1 {
		t.Fatalf("chrony.conf: %q", got)
	}
}

func TestTimeSyncStopsOtherTimeServicesAndStartsThemAgain(t *testing.T) {
	ctx := context.Background()
	env, run := testEnv(t)
	run.fail["systemctl is-active --quiet ntpd"] = true
	run.fail["systemctl is-enabled --quiet ntpd"] = true
	run.fail["systemctl is-active --quiet ntpsec"] = true
	run.fail["systemctl is-enabled --quiet ntpsec"] = true
	run.fail["systemctl is-active --quiet openntpd"] = true
	run.fail["systemctl is-enabled --quiet openntpd"] = true
	c := syncControl()
	must(t, c.Apply(ctx, env, control.Values{}))
	if !run.did("systemctl disable --now systemd-timesyncd") {
		t.Fatalf("the other service must be stopped: %v", run.calls)
	}
	must(t, c.Revert(ctx, env))
	if !run.did("systemctl enable systemd-timesyncd") || !run.did("systemctl start systemd-timesyncd") {
		t.Fatalf("the other service must come back: %v", run.calls)
	}
}

func TestTimeSyncRejectsBadInput(t *testing.T) {
	env, run := testEnv(t)
	if err := syncControl().Apply(context.Background(), env, control.Values{"servers": {"bad host!"}}); err == nil {
		t.Fatal("a bad server name must be rejected")
	}
	if run.did("install") {
		t.Fatal("a package was installed for invalid input")
	}
}
