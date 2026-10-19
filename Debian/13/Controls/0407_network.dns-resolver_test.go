// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Danang Galuh Tegar Prasetyo

package controls

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/danang-id/server-hardening/internal/control"
)

func dnsControl() *dnsResolver { return &dnsResolver{control.Base{M: control.Meta{ID: dnsID}}} }

func dnsIn(dns, dot, dnssec string) control.Values {
	return control.Values{"dns": {dns}, "dot": {dot}, "dnssec": {dnssec}}
}

// dnsEnv is a server with a plain /etc/resolv.conf and no resolver service.
func dnsEnv(t *testing.T) (*control.Env, *fakeRunner) {
	t.Helper()
	env, run := testEnv(t)
	writeFile(t, env, resolvConf, "nameserver 9.9.9.9\nnameserver 149.112.112.112\n")
	run.fail["systemctl is-active --quiet systemd-resolved"] = true
	run.fail["systemctl is-enabled --quiet systemd-resolved"] = true
	run.hook = chain(run.hook, func(f *fakeRunner, cmd string) {
		if cmd == "systemctl enable --now systemd-resolved" {
			delete(f.fail, "systemctl is-active --quiet systemd-resolved")
			delete(f.fail, "systemctl is-enabled --quiet systemd-resolved")
		}
	})
	return env, run
}

func TestDNSResolverApplyAndRevert(t *testing.T) {
	ctx := context.Background()
	env, run := dnsEnv(t)
	c := dnsControl()
	ins, _ := c.Inputs(ctx, env)
	if ins[0].Default != "9.9.9.9 149.112.112.112" || ins[1].Default != "opportunistic" || ins[2].Default != "allow-downgrade" {
		t.Fatalf("defaults: %q %q %q", ins[0].Default, ins[1].Default, ins[2].Default)
	}
	if state(t, c, env) != control.NotApplied {
		t.Fatal("should start not applied")
	}
	must(t, c.Apply(ctx, env, dnsIn("9.9.9.9 149.112.112.112", "opportunistic", "allow-downgrade")))

	wantContains(t, read(t, env, resolvedCfg), sshdMarker(dnsID), "[Resolve]", "DNS=9.9.9.9 149.112.112.112",
		"FallbackDNS=\n", "DNSOverTLS=opportunistic", "DNSSEC=allow-downgrade")
	if target, err := os.Readlink(env.Path(resolvConf)); err != nil || target != resolvStub {
		t.Fatalf("resolv.conf must link to the stub: %q %v", target, err)
	}
	if !run.did("install systemd-resolved") || !run.did("systemctl enable --now systemd-resolved") {
		t.Fatalf("calls: %v", run.calls)
	}
	if !run.did("resolvectl query --legend=no deb.debian.org") {
		t.Fatal("a test lookup must prove the resolver answers")
	}
	if state(t, c, env) != control.Applied {
		t.Fatal("should be applied")
	}

	must(t, c.Revert(ctx, env))
	noFile(t, env, resolvedCfg)
	if fi, err := os.Lstat(env.Path(resolvConf)); err != nil || fi.Mode()&os.ModeSymlink != 0 {
		t.Fatalf("resolv.conf must be a plain file again: %v %v", fi, err)
	}
	if read(t, env, resolvConf) != "nameserver 9.9.9.9\nnameserver 149.112.112.112\n" {
		t.Fatalf("resolv.conf:\n%s", read(t, env, resolvConf))
	}
	if !run.did("disable --now systemd-resolved") {
		t.Fatal("the service was off before and must be off again")
	}
	if env.Rec.Has(dnsID) {
		t.Fatal("record should be gone")
	}
}

func TestDNSResolverRestoresALink(t *testing.T) {
	ctx := context.Background()
	env, _ := dnsEnv(t)
	must(t, os.Remove(env.Path(resolvConf)))
	must(t, os.Symlink("../run/systemd/resolve/resolv.conf", env.Path(resolvConf)))
	c := dnsControl()
	must(t, c.Apply(ctx, env, dnsIn("1.1.1.1", "yes", "yes")))
	must(t, c.Revert(ctx, env))
	if target, err := os.Readlink(env.Path(resolvConf)); err != nil || target != "../run/systemd/resolve/resolv.conf" {
		t.Fatalf("the earlier link must be back: %q %v", target, err)
	}
}

func TestDNSResolverRollsBackWhenLookupsFail(t *testing.T) {
	env, run := dnsEnv(t)
	run.fail["resolvectl query --legend=no deb.debian.org"] = true
	err := dnsControl().Apply(context.Background(), env, dnsIn("1.1.1.1", "yes", "yes"))
	if err == nil || !strings.Contains(err.Error(), "test lookup failed") {
		t.Fatalf("error: %v", err)
	}
	noFile(t, env, resolvedCfg)
	if fi, err := os.Lstat(env.Path(resolvConf)); err != nil || fi.Mode()&os.ModeSymlink != 0 {
		t.Fatal("resolv.conf must be a plain file again")
	}
	if read(t, env, resolvConf) != "nameserver 9.9.9.9\nnameserver 149.112.112.112\n" {
		t.Fatal("the old resolv.conf must be back")
	}
}

func TestDNSResolverKeepsARunningResolver(t *testing.T) {
	ctx := context.Background()
	env, run := dnsEnv(t)
	delete(run.fail, "systemctl is-active --quiet systemd-resolved")
	delete(run.fail, "systemctl is-enabled --quiet systemd-resolved")
	c := dnsControl()
	must(t, c.Apply(ctx, env, dnsIn("1.1.1.1", "no", "no")))
	run.calls = nil
	must(t, c.Revert(ctx, env))
	if run.did("disable") || run.did("stop") || !run.did("restart systemd-resolved") {
		t.Fatalf("a resolver that ran before must keep running: %v", run.calls)
	}
}

func TestDNSResolverRefusesAClashingDNSServer(t *testing.T) {
	env, run := dnsEnv(t)
	run.out["ss -H -lntup"] = `udp UNCONN 0 0 0.0.0.0:53 0.0.0.0:* users:(("dnsmasq",pid=9,fd=4))` + "\n"
	err := dnsControl().Apply(context.Background(), env, dnsIn("1.1.1.1", "no", "no"))
	if err == nil || !strings.Contains(err.Error(), "dnsmasq") {
		t.Fatalf("error: %v", err)
	}
	noFile(t, env, resolvedCfg)
	// The resolver's own stub on 127.0.0.53 is fine.
	run.out["ss -H -lntup"] = `udp UNCONN 0 0 127.0.0.53%lo:53 0.0.0.0:* users:(("systemd-resolve",pid=9,fd=4))` + "\n"
	must(t, dnsControl().Apply(context.Background(), env, dnsIn("1.1.1.1", "no", "no")))
}

func TestDNSResolverValidation(t *testing.T) {
	env, run := dnsEnv(t)
	c := dnsControl()
	for name, in := range map[string]control.Values{
		"no servers": dnsIn("", "no", "no"),
		"bad server": dnsIn("dns.example", "no", "no"),
		"bad dot":    dnsIn("1.1.1.1", "sometimes", "no"),
		"bad dnssec": dnsIn("1.1.1.1", "no", "strict"),
	} {
		if err := c.Apply(context.Background(), env, in); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	if run.did("install") || env.Rec.Has(dnsID) {
		t.Fatal("nothing may change")
	}
	ins, _ := c.Inputs(context.Background(), env)
	if ins[0].Validate("") == nil || ins[0].Validate("1.1.1.1 2606:4700:4700::1111") != nil {
		t.Fatal("server validation")
	}
}

func TestDNSResolverMeta(t *testing.T) {
	c, _ := System.Get(dnsID)
	m := c.Meta()
	if m.EffectiveWeight() != 810 || strings.Join(m.Requires, ",") != networkdID || m.Default {
		t.Fatalf("meta: %+v", m)
	}
}
