// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Danang Galuh Tegar Prasetyo

package controls

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/danang-id/server-hardening/internal/control"
)

func networkdControl() *networkd { return &networkd{control.Base{M: control.Meta{ID: networkdID}}} }

// netEnv is a server with a static IPv4 and IPv6 address on eth0 and ifupdown.
func netEnv(t *testing.T) (*control.Env, *fakeRunner) {
	t.Helper()
	env, run := testEnv(t)
	must(t, os.MkdirAll(env.Path("/sys/class/net/eth0"), 0o755))
	writeFile(t, env, networkdBin, "")
	writeFile(t, env, "/etc/network/interfaces", "auto eth0\niface eth0 inet static\n address 203.0.113.5/24\n gateway 203.0.113.1\n")
	writeFile(t, env, "/etc/network/interfaces.d/extra", "# extra\n")
	writeFile(t, env, "/etc/resolv.conf", "nameserver 9.9.9.9\nnameserver 149.112.112.112\n")
	run.out["ip -4 route show default"] = "default via 203.0.113.1 dev eth0 proto static\n"
	run.out["ip -6 route show default"] = "default via 2001:db8::1 dev eth0 metric 1024 pref medium\n"
	run.out["ip -o -4 addr show dev eth0 scope global"] = "2: eth0    inet 203.0.113.5/24 brd 203.0.113.255 scope global eth0\\       valid_lft forever preferred_lft forever\n"
	run.out["ip -o -6 addr show dev eth0 scope global"] = "2: eth0    inet6 2001:db8::5/64 scope global \\       valid_lft forever preferred_lft forever\n"
	return env, run
}

func staticIn() control.Values {
	return control.Values{
		"iface": {"eth0"}, "mode": {"static"}, "addresses": {"203.0.113.5/24 2001:db8::5/64"},
		"gateway4": {"203.0.113.1"}, "gateway6": {"2001:db8::1"}, "ra": {"no"}, "dns": {"9.9.9.9 149.112.112.112"},
	}
}

func TestNetworkdDetectsTheRunningConfiguration(t *testing.T) {
	env, _ := netEnv(t)
	ins, err := networkdControl().Inputs(context.Background(), env)
	must(t, err)
	def := map[string]string{}
	for _, in := range ins {
		def[in.Key] = in.Default
	}
	want := map[string]string{
		"iface": "eth0", "mode": "static", "addresses": "203.0.113.5/24 2001:db8::5/64",
		"gateway4": "203.0.113.1", "gateway6": "2001:db8::1", "ra": "no", "dns": "9.9.9.9 149.112.112.112",
	}
	for k, v := range want {
		if def[k] != v {
			t.Errorf("%s: %q, want %q", k, def[k], v)
		}
	}
}

func TestNetworkdDetectsDHCPAndRouterAdvertisements(t *testing.T) {
	env, run := netEnv(t)
	run.out["ip -o -4 addr show dev eth0 scope global"] = "2: eth0    inet 192.0.2.10/24 brd 192.0.2.255 scope global dynamic eth0\\       valid_lft 3000sec\n"
	run.out["ip -o -6 addr show dev eth0 scope global"] = "2: eth0    inet6 2001:db8::abcd/64 scope global dynamic mngtmpaddr \\\n" +
		"2: eth0    inet6 2001:db8::1234/64 scope global temporary dynamic \\\n"
	run.out["ip -6 route show default"] = "default via fe80::1 dev eth0 proto ra metric 1024\n"
	d := detectNetwork(context.Background(), env)
	if !d.DHCP4 || !d.RA || len(d.Addrs) != 0 {
		t.Fatalf("detected: %+v", d)
	}
}

func TestNetworkdIgnoresTheLocalStubResolver(t *testing.T) {
	got := resolvConfServers("nameserver 127.0.0.53\nnameserver 1.1.1.1\nsearch example\n")
	if len(got) != 1 || got[0] != "1.1.1.1" {
		t.Fatalf("servers: %v", got)
	}
}

func TestNetworkdApply(t *testing.T) {
	ctx := context.Background()
	env, run := netEnv(t)
	c := networkdControl()
	if state(t, c, env) != control.NotApplied {
		t.Fatal("should start not applied")
	}
	must(t, c.Apply(ctx, env, staticIn()))

	got := read(t, env, networkdFile("eth0"))
	wantContains(t, got, "[Match]\nName=eth0", "DHCP=no", "IPv6AcceptRA=no", "Address=203.0.113.5/24", "Address=2001:db8::5/64",
		"DNS=9.9.9.9", "DNS=149.112.112.112", "Gateway=203.0.113.1", "Gateway=2001:db8::1")
	if strings.Contains(got, "GatewayOnLink") {
		t.Fatalf("both gateways are inside their subnets:\n%s", got)
	}
	// The earlier configuration is saved and the old service goes off.
	for _, p := range []string{"/etc/network/interfaces", "/etc/network/interfaces.d/extra"} {
		if v, _, _ := env.Rec.Get(networkdID, "saved"); !strings.Contains(v, p) {
			t.Errorf("%s is not saved: %q", p, v)
		}
	}
	if read(t, env, "/etc/network/interfaces") == "<missing>" {
		t.Fatal("the old file stays in place")
	}
	wantContains(t, read(t, env, cloudNetOff), "network: {config: disabled}")
	if !run.did("systemctl disable networking") || !run.did("systemctl enable systemd-networkd") {
		t.Fatalf("calls: %v", run.calls)
	}
	// networkd takes the interface over at the next boot, not now.
	if run.did("start systemd-networkd") || run.did("restart systemd-networkd") || run.did("--now") || run.did("netplan apply") {
		t.Fatalf("the network must not change while you are connected: %v", run.calls)
	}
	if st := state(t, c, env); st != control.Applied {
		t.Fatalf("state %v", st)
	}
}

func TestNetworkdWaitsForRebootWhenNotRunning(t *testing.T) {
	ctx := context.Background()
	env, run := netEnv(t)
	run.fail["systemctl is-active --quiet systemd-networkd"] = true
	c := networkdControl()
	must(t, c.Apply(ctx, env, staticIn()))
	if state(t, c, env) != control.Partial {
		t.Fatal("written but not running yet is partial")
	}
}

func TestNetworkdGatewayOutsideTheSubnet(t *testing.T) {
	env, _ := netEnv(t)
	in := staticIn()
	in["addresses"] = []string{"203.0.113.5/32 2001:db8::5/64"}
	in["gateway4"] = []string{"198.51.100.1"}
	must(t, networkdControl().Apply(context.Background(), env, in))
	got := read(t, env, networkdFile("eth0"))
	if strings.Count(got, "GatewayOnLink=yes") != 1 || !strings.Contains(got, "Gateway=198.51.100.1\nGatewayOnLink=yes") {
		t.Fatalf("only the IPv4 gateway is off-link:\n%s", got)
	}
}

func TestNetworkdDHCP(t *testing.T) {
	env, _ := netEnv(t)
	in := control.Values{"iface": {"eth0"}, "mode": {"dhcp"}, "addresses": {""}, "gateway4": {""}, "gateway6": {""}, "ra": {"yes"}, "dns": {""}}
	must(t, networkdControl().Apply(context.Background(), env, in))
	got := read(t, env, networkdFile("eth0"))
	wantContains(t, got, "DHCP=ipv4", "IPv6AcceptRA=yes")
	if strings.Contains(got, "Address=") || strings.Contains(got, "[Route]") || strings.Contains(got, "DNS=") {
		t.Fatalf("DHCP gives all of that:\n%s", got)
	}
}

func TestNetworkdRefusesAConfigurationThatCouldCutTheServerOff(t *testing.T) {
	ctx := context.Background()
	for name, tc := range map[string]struct {
		change func(control.Values)
		want   string
	}{
		"no interface":      {func(v control.Values) { v["iface"] = []string{"eth9"} }, "no network interface"},
		"bad interface":     {func(v control.Values) { v["iface"] = []string{"../x"} }, "no network interface"},
		"static no address": {func(v control.Values) { v["addresses"] = []string{"2001:db8::5/64"} }, "at least one address"},
		"static no gateway": {func(v control.Values) { v["gateway4"] = []string{""} }, "needs a gateway"},
		"v6 gw in v4":       {func(v control.Values) { v["gateway4"] = []string{"2001:db8::1"} }, "not an IPv4 address"},
		"v4 gw in v6":       {func(v control.Values) { v["gateway6"] = []string{"203.0.113.1"} }, "not an IPv6 address"},
		"v6 no gateway":     {func(v control.Values) { v["gateway6"] = []string{""} }, "IPv6 gateway"},
		"bad address":       {func(v control.Values) { v["addresses"] = []string{"203.0.113.5 2001:db8::5/64"} }, "prefix length"},
		"dhcp with address": {func(v control.Values) { v["mode"] = []string{"dhcp"} }, "DHCP"},
	} {
		env, run := netEnv(t)
		in := staticIn()
		tc.change(in)
		err := networkdControl().Apply(ctx, env, in)
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: error %v", name, err)
		}
		if _, err := os.Stat(env.Path(networkdFile("eth0"))); err == nil || run.did("disable networking") || env.Rec.Has(networkdID) {
			t.Errorf("%s: nothing may change", name)
		}
	}
}

func TestNetworkdInstallsThePackageIfMissing(t *testing.T) {
	env, run := netEnv(t)
	must(t, os.Remove(env.Path(networkdBin)))
	err := networkdControl().Apply(context.Background(), env, staticIn())
	if err == nil || !strings.Contains(err.Error(), "not available") {
		t.Fatalf("error: %v", err)
	}
	if !run.did("install systemd-networkd") {
		t.Fatalf("it must try to install the package: %v", run.calls)
	}
	noFile(t, env, networkdFile("eth0"))
}

func TestNetworkdFailureSwitchesTheOldServiceBackOn(t *testing.T) {
	env, run := netEnv(t)
	run.fail["systemctl enable systemd-networkd"] = true
	if err := networkdControl().Apply(context.Background(), env, staticIn()); err == nil {
		t.Fatal("expected an error")
	}
	if !run.did("systemctl enable networking") {
		t.Fatalf("the old service must be on again: %v", run.calls)
	}
}

func TestNetworkdHasNoRevert(t *testing.T) {
	env, _ := netEnv(t)
	c := networkdControl()
	if err := c.Revert(context.Background(), env); !errors.Is(err, control.ErrNoRevert) {
		t.Fatalf("revert: %v", err)
	}
	m, _ := System.Get(networkdID)
	meta := m.Meta()
	if meta.Revertible() || meta.NoRevertReason == "" || meta.EffectiveWeight() != 800 ||
		!meta.Has(control.TagLockout) || !meta.Has(control.TagReboot) || meta.Default {
		t.Fatalf("meta: %+v", meta)
	}
}

func TestNetworkdRender(t *testing.T) {
	cfg := netConfig{Iface: "ens3", DHCP4: true, RA: true, DNS: []string{"1.1.1.1"}}
	got := cfg.render()
	if got != sshdMarker(networkdID)+"\n[Match]\nName=ens3\n\n[Network]\nDHCP=ipv4\nIPv6AcceptRA=yes\nDNS=1.1.1.1\n" {
		t.Fatalf("render:\n%s", got)
	}
}
