// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Danang Galuh Tegar Prasetyo

package controls

import (
	"context"
	"strings"
	"testing"

	"github.com/danang-id/server-hardening/internal/control"
)

func portControl() *sshPort { return &sshPort{control.Base{M: control.Meta{ID: portID}}} }

func portIn(p string) control.Values { return control.Values{"port": {p}} }

func ints(ns []int) string { return joinInts(ns) }

func TestValidPort(t *testing.T) {
	for _, ok := range []string{"2222", " 22022 ", "1", "65535"} {
		if validPort(ok) != nil {
			t.Errorf("%q refused", ok)
		}
	}
	for _, bad := range []string{"", "22", "0", "65536", "-1", "ssh", "22.5"} {
		if validPort(bad) == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestPortTwoPhases(t *testing.T) {
	ctx := context.Background()
	env, _, sim := sshEnv(t)
	c := portControl()
	if state(t, c, env) != control.NotApplied {
		t.Fatal("should start not applied")
	}
	must(t, c.Apply(ctx, env, portIn("2222")))

	// Phase 1: both ports, so the user can test the new one while the old one still works.
	if got := ints(sim.listen); got != "22,2222" {
		t.Fatalf("listening on %s", got)
	}
	wantContains(t, dropIn(t, env, "port"), "Port 22\n", "Port 2222\n")
	if state(t, c, env) != control.Applied {
		t.Fatal("should be applied")
	}

	// Phase 2, after the user has confirmed: only the new port.
	must(t, c.Finalize(ctx, env))
	if got := ints(sim.listen); got != "2222" {
		t.Fatalf("listening on %s", got)
	}
	if strings.Contains(dropIn(t, env, "port"), "Port 22\n") {
		t.Fatal("the old port must be gone from the drop-in")
	}
	if state(t, c, env) != control.Applied {
		t.Fatal("should still be applied")
	}

	must(t, c.Revert(ctx, env))
	if got := ints(sim.listen); got != "22" {
		t.Fatalf("listening on %s after the revert", got)
	}
	noFile(t, env, sshdFile("port"))
	if env.Rec.Has(portID) {
		t.Fatal("record should be gone")
	}
}

func TestPortRevertBeforeFinalize(t *testing.T) {
	ctx := context.Background()
	env, _, sim := sshEnv(t)
	c := portControl()
	must(t, c.Apply(ctx, env, portIn("2222")))
	must(t, c.Revert(ctx, env)) // the safety timer fired
	if ints(sim.listen) != "22" {
		t.Fatalf("listening on %s", ints(sim.listen))
	}
}

func TestPortRefusesWhenSetElsewhere(t *testing.T) {
	for _, file := range []string{"/etc/ssh/sshd_config", "/etc/ssh/sshd_config.d/10-custom.conf"} {
		env, run, _ := sshEnv(t)
		writeFile(t, env, file, "Include /etc/ssh/sshd_config.d/*.conf\nPort 2200\n")
		err := portControl().Apply(context.Background(), env, portIn("2222"))
		if err == nil || !strings.Contains(err.Error(), file) {
			t.Fatalf("%s: error: %v", file, err)
		}
		noFile(t, env, sshdFile("port"))
		if run.did("reload") {
			t.Fatal("nothing may change")
		}
	}
	// A commented line is not a setting.
	env, _, _ := sshEnv(t)
	writeFile(t, env, "/etc/ssh/sshd_config", "#Port 22\n")
	must(t, portControl().Apply(context.Background(), env, portIn("2222")))
}

func TestPortInUse(t *testing.T) {
	env, run, sim := sshEnv(t)
	sim.others[8080] = "nginx"
	err := portControl().Apply(context.Background(), env, portIn("8080"))
	if err == nil || !strings.Contains(err.Error(), "another service") {
		t.Fatalf("error: %v", err)
	}
	noFile(t, env, sshdFile("port"))
	if run.did("reload") {
		t.Fatal("nothing may change")
	}
}

func TestPortNotListeningRollsBack(t *testing.T) {
	env, run, sim := sshEnv(t)
	run.out["ufw status"] = "Status: active\n"
	sim.noListen = true
	err := portControl().Apply(context.Background(), env, portIn("2222"))
	if err == nil || !strings.Contains(err.Error(), "not listening") {
		t.Fatalf("error: %v", err)
	}
	noFile(t, env, sshdFile("port"))
	if !run.did("ufw delete allow 2222/tcp") {
		t.Fatalf("the firewall rule must be taken back: %v", run.calls)
	}
}

func TestPortSSHDRefusesRollsBack(t *testing.T) {
	env, run, _ := sshEnv(t)
	run.out["ufw status"] = "Status: active\n"
	run.hook = chain(run.hook, func(f *fakeRunner, cmd string) {
		if cmd == "sshd -t" {
			f.fail[cmd] = true
		}
	})
	if err := portControl().Apply(context.Background(), env, portIn("2222")); err == nil {
		t.Fatal("expected an error")
	}
	noFile(t, env, sshdFile("port"))
	if !run.did("ufw delete allow 2222/tcp") {
		t.Fatalf("the firewall rule must be taken back: %v", run.calls)
	}
}

func TestPortUFW(t *testing.T) {
	ctx := context.Background()
	env, run, _ := sshEnv(t)
	run.out["ufw status"] = "Status: active\n\nTo Action From\n22/tcp ALLOW Anywhere\n"
	c := portControl()
	must(t, c.Apply(ctx, env, portIn("2222")))
	if !run.did("ufw allow 2222/tcp") {
		t.Fatalf("the new port must be opened: %v", run.calls)
	}
	// The new port is opened before sshd listens on it.
	iAllow, iReload := -1, -1
	for i, cmd := range run.calls {
		if cmd == "ufw allow 2222/tcp" && iAllow < 0 {
			iAllow = i
		}
		if cmd == "systemctl reload ssh" && iReload < 0 {
			iReload = i
		}
	}
	if iAllow < 0 || iReload < iAllow {
		t.Fatalf("firewall first, then sshd: %v", run.calls)
	}
	run.calls = nil
	run.out["ufw status"] = "Status: active\n\nTo Action From\n22/tcp ALLOW Anywhere\n2222/tcp ALLOW Anywhere\n"
	must(t, c.Revert(ctx, env))
	if run.did("ufw allow 22/tcp") {
		t.Fatal("port 22 is open already, no new rule")
	}
	if !run.did("ufw delete allow 2222/tcp") {
		t.Fatalf("the rule this control added must go: %v", run.calls)
	}
}

func TestPortUFWRuleThatExistedStays(t *testing.T) {
	ctx := context.Background()
	env, run, _ := sshEnv(t)
	run.out["ufw status"] = "Status: active\n\n22/tcp ALLOW Anywhere\n2222/tcp ALLOW Anywhere\n"
	c := portControl()
	must(t, c.Apply(ctx, env, portIn("2222")))
	if run.did("ufw allow 2222/tcp") {
		t.Fatal("the rule exists, nothing to add")
	}
	must(t, c.Revert(ctx, env))
	if run.did("ufw delete") {
		t.Fatal("a rule this control did not add must stay")
	}
}

func TestPortFirewalld(t *testing.T) {
	ctx := context.Background()
	env, run, _ := sshEnv(t)
	run.out["firewall-cmd --state"] = "running\n"
	run.fail["firewall-cmd --permanent --query-port=2222/tcp"] = true
	c := portControl()
	must(t, c.Apply(ctx, env, portIn("2222")))
	if !run.did("firewall-cmd --permanent --add-port=2222/tcp") || !run.did("firewall-cmd --reload") {
		t.Fatalf("the port must be opened and the firewall reloaded: %v", run.calls)
	}
	must(t, c.Revert(ctx, env))
	if !run.did("firewall-cmd --permanent --remove-port=2222/tcp") {
		t.Fatalf("the rule must be removed: %v", run.calls)
	}
}

func TestPortRefusesNftablesDrop(t *testing.T) {
	env, run, _ := sshEnv(t)
	run.out["nft list ruleset"] = "table inet filter {\n\tchain input {\n\t\ttype filter hook input priority filter; policy drop;\n\t}\n}\n"
	err := portControl().Apply(context.Background(), env, portIn("2222"))
	if err == nil || !strings.Contains(err.Error(), "nftables") {
		t.Fatalf("error: %v", err)
	}
	noFile(t, env, sshdFile("port"))
	if run.did("reload") {
		t.Fatal("nothing may change")
	}
	// An accepting policy is fine.
	run.out["nft list ruleset"] = "table inet filter {\n\tchain input {\n\t\ttype filter hook input priority filter; policy accept;\n\t}\n}\n"
	must(t, portControl().Apply(context.Background(), env, portIn("2222")))
}

func TestPortSocketActivation(t *testing.T) {
	ctx := context.Background()
	env, run, sim := sshEnv(t)
	delete(run.fail, "systemctl is-active --quiet ssh.socket")
	c := portControl()
	must(t, c.Apply(ctx, env, portIn("2222")))
	wantContains(t, read(t, env, portSocketFile), sshdMarker(portID), "ListenStream=\n", "ListenStream=22\n", "ListenStream=2222\n")
	if !run.did("systemctl daemon-reload") || !run.did("systemctl restart ssh.socket") {
		t.Fatalf("the socket must be restarted: %v", run.calls)
	}
	if ints(sim.listen) != "22,2222" {
		t.Fatalf("listening on %s", ints(sim.listen))
	}

	must(t, c.Finalize(ctx, env))
	if ints(sim.listen) != "2222" {
		t.Fatalf("listening on %s", ints(sim.listen))
	}
	if strings.Contains(read(t, env, portSocketFile), "ListenStream=22\n") {
		t.Fatal("the old port must leave the socket")
	}

	must(t, c.Revert(ctx, env))
	noFile(t, env, portSocketFile)
	if ints(sim.listen) != "22" {
		t.Fatalf("listening on %s", ints(sim.listen))
	}
}

func TestPortSecondRun(t *testing.T) {
	ctx := context.Background()
	env, run, sim := sshEnv(t)
	run.out["ufw status"] = "Status: active\n22/tcp ALLOW Anywhere\n"
	c := portControl()
	must(t, c.Apply(ctx, env, portIn("2222")))

	// The same port again: the old port 22 is still the one that is remembered,
	// and the firewall rule stays with this control.
	run.out["ufw status"] = "Status: active\n22/tcp ALLOW Anywhere\n2222/tcp ALLOW Anywhere\n"
	must(t, c.Apply(ctx, env, portIn("2222")))
	if v, _, _ := env.Rec.Get(portID, "old-ports"); v != "22" {
		t.Fatalf("old ports %q", v)
	}
	if v, _, _ := env.Rec.Get(portID, "firewall-added"); v != "yes" {
		t.Fatalf("the rule is still ours: %q", v)
	}

	// Another port: the earlier rule is closed.
	run.calls = nil
	must(t, c.Apply(ctx, env, portIn("2223")))
	if ints(sim.listen) != "22,2223" {
		t.Fatalf("listening on %s", ints(sim.listen))
	}
	if !run.did("ufw delete allow 2222/tcp") {
		t.Fatalf("the earlier rule must go: %v", run.calls)
	}
}

func TestPortFinalizeWithoutRecord(t *testing.T) {
	env, run, _ := sshEnv(t)
	must(t, portControl().Finalize(context.Background(), env))
	if len(run.calls) != 0 {
		t.Fatalf("nothing to do: %v", run.calls)
	}
}

func TestPortRevertWithoutRecord(t *testing.T) {
	env, run, _ := sshEnv(t)
	writeFile(t, env, sshdFile("port"), "Port 2222\n")
	must(t, portControl().Revert(context.Background(), env))
	if read(t, env, sshdFile("port")) == "<missing>" || run.did("reload") {
		t.Fatal("a file this tool did not write must stay")
	}
}

func TestPortIsLockoutAndInput(t *testing.T) {
	c, ok := System.Get(portID)
	if !ok {
		t.Fatal("not registered")
	}
	m := c.Meta()
	if !m.Has(control.TagLockout) || !m.Has(control.TagInput) || m.Default {
		t.Fatalf("meta: %+v", m)
	}
	if _, ok := c.(control.Finalizer); !ok {
		t.Fatal("the port control must close the old port after confirmation")
	}
}

func TestPortOpensItInTheOwnNftablesTable(t *testing.T) {
	ctx := context.Background()
	env, _, _, fw := fwEnv(t)
	applyFW(t, env, "nftables")
	if strings.Contains(read(t, env, nftFile), "2222") {
		t.Fatal("precondition")
	}
	c := portControl()
	must(t, c.Apply(ctx, env, portIn("2222")))
	// Phase 1: the firewall lets both ports in.
	wantContains(t, read(t, env, nftFile), "tcp dport { 22, 2222 } accept")
	if !strings.Contains(fw.nftLoadedText, "2222") {
		t.Fatal("the rule must be loaded")
	}
	if v, _, _ := env.Rec.Get(portID, "firewall-added"); v != "yes" {
		t.Fatalf("firewall-added %q", v)
	}
	must(t, c.Finalize(ctx, env))
	must(t, c.Revert(ctx, env))
	if strings.Contains(read(t, env, nftFile), "2222") {
		t.Fatalf("the revert must close the new port again:\n%s", read(t, env, nftFile))
	}
	wantContains(t, read(t, env, nftFile), "tcp dport { 22 } accept")
}

func TestPortFailureRemovesNftablesRule(t *testing.T) {
	env, _, ssh, _ := fwEnv(t)
	applyFW(t, env, "nftables")
	ssh.noListen = true
	if err := portControl().Apply(context.Background(), env, portIn("2222")); err == nil {
		t.Fatal("expected an error")
	}
	if strings.Contains(read(t, env, nftFile), "2222") {
		t.Fatal("the rule must be taken back")
	}
}
