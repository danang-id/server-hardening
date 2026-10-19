// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Danang Galuh Tegar Prasetyo

package controls

import (
	"context"
	"strings"
	"testing"

	"github.com/danang-id/server-hardening/internal/control"
)

func servicesControl() *reviewServices {
	return &reviewServices{control.Base{M: control.Meta{ID: servicesID}}}
}

func servicesEnv(t *testing.T) (*control.Env, *fakeRunner, *sysSim) {
	env, run, s := sysEnv(t)
	for _, u := range []string{"ssh.service", "systemd-timesyncd.service", "avahi-daemon.service", "cups.service", "exim4.service", "foo.service", "getty@.service"} {
		s.enabled[u], s.active[u] = true, true
	}
	s.units = map[string]string{"foo.service": "Foo daemon"}
	s.listEnabled(run)
	run.out["ss -H -lntup"] = "" +
		"udp UNCONN 0 0 0.0.0.0:5353 0.0.0.0:* users:((\"avahi-daemon\",pid=1,fd=1))\n" +
		"tcp LISTEN 0 4096 0.0.0.0:631 0.0.0.0:* users:((\"cupsd\",pid=2,fd=2))\n" +
		"tcp LISTEN 0 4096 0.0.0.0:22 0.0.0.0:* users:((\"sshd\",pid=3,fd=3))\n"
	return env, run, s
}

func TestServicesInputsHideProtectedAndExplain(t *testing.T) {
	env, _, _ := servicesEnv(t)
	in, err := servicesControl().Inputs(context.Background(), env)
	must(t, err)
	if len(in) != 1 {
		t.Fatalf("want one input, got %+v", in)
	}
	var names []string
	help := map[string]string{}
	for _, o := range in[0].Options {
		names = append(names, o.Value)
		help[o.Value] = o.Help
	}
	if got := strings.Join(names, ","); got != "avahi-daemon.service,cups.service,exim4.service,foo.service" {
		t.Fatalf("offered: %s", got)
	}
	wantContains(t, help["avahi-daemon.service"], "mDNS", "udp 5353")
	wantContains(t, help["cups.service"], "tcp 631")
	wantContains(t, help["foo.service"], "Foo daemon")
	if got := strings.Join(in[0].DefaultMulti, ","); got != "avahi-daemon.service,cups.service" {
		t.Fatalf("ticked at first: %s", got)
	}
}

func TestServicesDisableAndRevert(t *testing.T) {
	ctx := context.Background()
	env, _, s := servicesEnv(t)
	s.active["foo.service"] = false // enabled but not running
	c := servicesControl()
	if state(t, c, env) != control.NotApplied {
		t.Fatal("should start not applied")
	}
	must(t, c.Apply(ctx, env, control.Values{"services": {"avahi-daemon.service", "foo.service"}}))
	if s.enabled["avahi-daemon.service"] || s.active["avahi-daemon.service"] || s.enabled["foo.service"] {
		t.Fatalf("services should be off: %v %v", s.enabled, s.active)
	}
	if !s.enabled["cups.service"] {
		t.Fatal("cups was not chosen")
	}
	if state(t, c, env) != control.Applied {
		t.Fatal("should be applied")
	}
	s.enabled["foo.service"] = true
	if state(t, c, env) != control.Partial {
		t.Fatal("a service enabled again is partial")
	}
	s.enabled["foo.service"] = false

	must(t, c.Revert(ctx, env))
	if !s.enabled["avahi-daemon.service"] || !s.active["avahi-daemon.service"] {
		t.Fatal("avahi should be running again")
	}
	if !s.enabled["foo.service"] || s.active["foo.service"] {
		t.Fatalf("foo was enabled but stopped before: enabled=%v active=%v", s.enabled["foo.service"], s.active["foo.service"])
	}
	if env.Rec.Has(servicesID) {
		t.Fatal("record should be gone")
	}
}

func TestServicesRefuseProtectedAndUnknown(t *testing.T) {
	ctx := context.Background()
	env, _, s := servicesEnv(t)
	for _, u := range []string{"ssh.service", "systemd-timesyncd.service", "nothere.service"} {
		if err := servicesControl().Apply(ctx, env, control.Values{"services": {u}}); err == nil {
			t.Fatalf("%s must be refused", u)
		}
	}
	if !s.enabled["ssh.service"] {
		t.Fatal("ssh must stay")
	}
}

func TestServicesRollBackWhenOneFails(t *testing.T) {
	ctx := context.Background()
	env, run, s := servicesEnv(t)
	run.fail["systemctl disable --now cups.service"] = true
	err := servicesControl().Apply(ctx, env, control.Values{"services": {"avahi-daemon.service", "cups.service"}})
	if err == nil {
		t.Fatal("expected an error")
	}
	if !s.enabled["avahi-daemon.service"] || !s.active["avahi-daemon.service"] {
		t.Fatal("the first service must be put back")
	}
}

func TestServicesEmptyChoiceCountsAsReviewed(t *testing.T) {
	env, _, _ := servicesEnv(t)
	c := servicesControl()
	must(t, c.Apply(context.Background(), env, control.Values{}))
	if state(t, c, env) != control.Applied {
		t.Fatal("a review with no change is applied")
	}
}
