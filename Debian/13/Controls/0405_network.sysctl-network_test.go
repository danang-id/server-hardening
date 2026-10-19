// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Danang Galuh Tegar Prasetyo

package controls

import (
	"context"
	"strings"
	"testing"

	"github.com/danang-id/server-hardening/internal/control"
)

func netSysctlControl() *sysctlNetwork {
	return &sysctlNetwork{control.Base{M: control.Meta{ID: netSysctlID}}}
}

// kernelWith returns a fake kernel that has every network parameter, set to a permissive value.
func kernelWith(t *testing.T) (*control.Env, *fakeRunner, *sysctlSim) {
	params := allOf(networkSettings(false), "1")
	for _, k := range []string{"net.ipv6.conf.all.accept_ra", "net.ipv6.conf.default.accept_ra"} {
		params[k] = "1"
	}
	env, run, k := sysctlEnv(t, params)
	// A static IPv6 setup: no router advertisement in use.
	run.out["ip -6 route show"] = "2001:db8::/64 dev eth0 proto kernel metric 256\ndefault via 2001:db8::1 dev eth0 metric 1024\n"
	return env, run, k
}

func TestNetworkSysctlStaticIPv6(t *testing.T) {
	ctx := context.Background()
	env, _, k := kernelWith(t)
	c := netSysctlControl()
	ins, _ := c.Inputs(ctx, env)
	if ins[0].Default != "no" {
		t.Fatalf("static IPv6: default %q", ins[0].Default)
	}
	must(t, c.Apply(ctx, env, control.Values{"ra": {"no"}}))
	for k2, want := range map[string]string{
		"net.ipv4.conf.all.accept_redirects": "0", "net.ipv6.conf.default.accept_redirects": "0",
		"net.ipv4.conf.all.send_redirects": "0", "net.ipv4.conf.all.accept_source_route": "0",
		"net.ipv4.conf.all.rp_filter": "2", "net.ipv4.conf.default.log_martians": "1",
		"net.ipv4.tcp_syncookies": "1", "net.ipv4.icmp_echo_ignore_broadcasts": "1",
		"net.ipv6.conf.all.accept_ra": "0", "net.ipv6.conf.default.accept_ra": "0",
	} {
		if k.get(k2) != want {
			t.Errorf("%s = %q, want %q", k2, k.get(k2), want)
		}
	}
	if state(t, c, env) != control.Applied {
		t.Fatal("should be applied")
	}
	must(t, c.Revert(ctx, env))
	for _, key := range k.keys() {
		if k.get(key) != "1" {
			t.Errorf("%s = %q after the revert, the old value was 1", key, k.get(key))
		}
	}
}

func TestNetworkSysctlKeepsRA(t *testing.T) {
	ctx := context.Background()
	env, run, k := kernelWith(t)
	run.out["ip -6 route show"] = "default via fe80::1 dev eth0 proto ra metric 1024\n"
	c := netSysctlControl()
	ins, _ := c.Inputs(ctx, env)
	if ins[0].Default != "yes" {
		t.Fatalf("router advertisement in use: default %q", ins[0].Default)
	}
	must(t, c.Apply(ctx, env, control.Values{"ra": {"yes"}}))
	if strings.Contains(read(t, env, sysctlFile("network")), "accept_ra") {
		t.Fatal("accept_ra must be left alone")
	}
	if k.get("net.ipv6.conf.all.accept_ra") != "1" {
		t.Fatal("running accept_ra must be untouched")
	}
}

func TestNetworkSysctlDetectsDynamicAddress(t *testing.T) {
	env, run, _ := kernelWith(t)
	run.out["ip -6 addr show scope global dynamic"] = "2: eth0: <BROADCAST>\n    inet6 2001:db8::5/64 scope global dynamic mngtmpaddr\n"
	if !raInUse(context.Background(), env) {
		t.Fatal("a dynamic global address means router advertisements are in use")
	}
}

func TestNetworkSysctlSwitchingChoiceRestoresOldValue(t *testing.T) {
	ctx := context.Background()
	env, _, k := kernelWith(t)
	c := netSysctlControl()
	must(t, c.Apply(ctx, env, control.Values{"ra": {"no"}}))
	must(t, c.Apply(ctx, env, control.Values{"ra": {"yes"}}))
	if k.get("net.ipv6.conf.all.accept_ra") != "1" {
		t.Fatal("accept_ra must go back to its old value when it is no longer managed")
	}
	if strings.Contains(read(t, env, sysctlFile("network")), "accept_ra") {
		t.Fatal("the file must not set accept_ra any more")
	}
}

func TestNetworkSysctlWarnsWhenRAInUse(t *testing.T) {
	env, run, _ := kernelWith(t)
	run.out["ip -6 route show"] = "default via fe80::1 dev eth0 proto ra\n"
	var warned []string
	env.Log = captureLog{&warned}
	must(t, netSysctlControl().Apply(context.Background(), env, control.Values{"ra": {"no"}}))
	if len(warned) == 0 || !strings.Contains(warned[0], "IPv6 will stop") {
		t.Fatalf("warnings: %v", warned)
	}
}

func TestNetworkSysctlRejectsBadAnswer(t *testing.T) {
	env, _, _ := kernelWith(t)
	if err := netSysctlControl().Apply(context.Background(), env, control.Values{"ra": {"maybe"}}); err == nil {
		t.Fatal("bad answer accepted")
	}
}

// captureLog collects warnings.
type captureLog struct{ warns *[]string }

func (captureLog) Infof(string, ...any) {}
func (c captureLog) Warnf(f string, a ...any) {
	*c.warns = append(*c.warns, fmtSprintf(f, a...))
}
