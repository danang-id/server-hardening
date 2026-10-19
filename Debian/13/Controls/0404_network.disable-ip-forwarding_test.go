// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Danang Galuh Tegar Prasetyo

package controls

import (
	"context"
	"strings"
	"testing"

	"github.com/danang-id/server-hardening/internal/control"
)

func forwardControl() *disableIPForwarding {
	return &disableIPForwarding{control.Base{M: control.Meta{ID: forwardID}}}
}

func TestDisableForwarding(t *testing.T) {
	ctx := context.Background()
	env, _, k := sysctlEnv(t, map[string]string{"net.ipv4.ip_forward": "1", "net.ipv6.conf.all.forwarding": "1"})
	c := forwardControl()
	if state(t, c, env) != control.NotApplied {
		t.Fatal("should start not applied")
	}
	must(t, c.Apply(ctx, env, nil))
	wantContains(t, read(t, env, sysctlFile("no-forwarding")), sysctlMarker(forwardID),
		"net.ipv4.ip_forward = 0", "net.ipv6.conf.all.forwarding = 0")
	if k.get("net.ipv4.ip_forward") != "0" || k.get("net.ipv6.conf.all.forwarding") != "0" {
		t.Fatalf("running: %v", k.running)
	}
	if state(t, c, env) != control.Applied {
		t.Fatal("should be applied")
	}

	// Docker switched forwarding back on: the file is right, the kernel is not.
	k.running["net.ipv4.ip_forward"] = "1"
	if state(t, c, env) != control.Partial {
		t.Fatal("a kernel that disagrees with the file is partial")
	}
	k.running["net.ipv4.ip_forward"] = "0"

	must(t, c.Revert(ctx, env))
	noFile(t, env, sysctlFile("no-forwarding"))
	if k.get("net.ipv4.ip_forward") != "1" || k.get("net.ipv6.conf.all.forwarding") != "1" {
		t.Fatalf("the recorded values must come back: %v", k.running)
	}
	if env.Rec.Has(forwardID) {
		t.Fatal("record should be gone")
	}
}

func TestDisableForwardingSkipsMissingIPv6(t *testing.T) {
	env, _, k := sysctlEnv(t, map[string]string{"net.ipv4.ip_forward": "1"})
	must(t, forwardControl().Apply(context.Background(), env, nil))
	if strings.Contains(read(t, env, sysctlFile("no-forwarding")), "ipv6") {
		t.Fatal("a parameter the kernel lacks must not be written")
	}
	if k.get("net.ipv4.ip_forward") != "0" {
		t.Fatal("IPv4 forwarding must be off")
	}
}

func TestSysctlRollsBackWhenKernelRefuses(t *testing.T) {
	env, run, k := sysctlEnv(t, map[string]string{"net.ipv4.ip_forward": "1"})
	writeFile(t, env, sysctlFile("no-forwarding"), "# earlier\n")
	run.hook = chain(run.hook, func(f *fakeRunner, cmd string) {
		if strings.HasPrefix(cmd, "sysctl -p") {
			f.fail[cmd] = true
		}
	})
	err := forwardControl().Apply(context.Background(), env, nil)
	if err == nil || !strings.Contains(err.Error(), "refused") {
		t.Fatalf("error: %v", err)
	}
	if read(t, env, sysctlFile("no-forwarding")) != "# earlier\n" {
		t.Fatal("the earlier file must be back")
	}
	if k.get("net.ipv4.ip_forward") != "1" {
		t.Fatal("the running value must be untouched")
	}
}

func TestSysctlRollsBackWhenValueDoesNotStick(t *testing.T) {
	env, run, k := sysctlEnv(t, map[string]string{"net.ipv4.ip_forward": "1"})
	// Something else sets the value back as soon as sysctl -p ran.
	run.hook = func(f *fakeRunner, cmd string) {
		k.hook(f, cmd)
		if strings.HasPrefix(cmd, "sysctl -p") {
			k.running["net.ipv4.ip_forward"] = "1"
		}
	}
	err := forwardControl().Apply(context.Background(), env, nil)
	if err == nil || !strings.Contains(err.Error(), "did not take") {
		t.Fatalf("error: %v", err)
	}
	noFile(t, env, sysctlFile("no-forwarding"))
}

func TestSysctlRevertWithoutRecord(t *testing.T) {
	env, run, _ := sysctlEnv(t, map[string]string{"net.ipv4.ip_forward": "0"})
	writeFile(t, env, sysctlFile("no-forwarding"), "net.ipv4.ip_forward = 0\n")
	must(t, forwardControl().Revert(context.Background(), env))
	if read(t, env, sysctlFile("no-forwarding")) == "<missing>" || run.did("sysctl -w") {
		t.Fatal("a file this tool did not write must stay")
	}
}
