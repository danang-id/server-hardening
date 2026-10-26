// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Danang Galuh Tegar Prasetyo

package controls

import (
	"context"
	"strings"
	"testing"

	"github.com/danang-id/server-hardening/internal/control"
)

func fwControl() *hostFirewall { return &hostFirewall{control.Base{M: control.Meta{ID: fwID}}} }

func engineIn(e string) control.Values { return control.Values{"engine": {e}} }

func TestFirewallNftables(t *testing.T) {
	ctx := context.Background()
	env, run, _, fw := fwEnv(t)
	origConf := read(t, env, nftConf)
	c := fwControl()
	if state(t, c, env) != control.NotApplied {
		t.Fatal("should start not applied")
	}
	must(t, c.Apply(ctx, env, engineIn("nftables")))

	rules := read(t, env, nftFile)
	wantContains(t, rules, "table inet server_hardening", "delete table inet server_hardening", "policy drop",
		"ct state established,related accept", "iif lo accept", "ip protocol icmp accept", "ip6 nexthdr ipv6-icmp accept",
		"tcp dport { 22 } accept")
	if strings.Contains(rules, "log prefix") {
		t.Fatal("logging is another control")
	}
	if !strings.Contains(read(t, env, nftConf), nftInc) {
		t.Fatal("nftables.conf must include the rules file at boot")
	}
	if !strings.HasPrefix(read(t, env, nftConf), origConf) {
		t.Fatal("the lines that were in the file must stay")
	}
	if !run.did("nft -c -f") || !run.did("nft -f "+env.Path(nftFile)) {
		t.Fatalf("rules must be checked, then loaded: %v", run.calls)
	}
	if !run.did("systemctl enable nftables") {
		t.Fatal("rules must be loaded at boot")
	}
	if run.did("systemctl start nftables") || run.did("systemctl restart nftables") || run.did("enable --now nftables") {
		t.Fatalf("starting the service flushes other software's rules: %v", run.calls)
	}
	if fw.nftLoadedText == "" || state(t, c, env) != control.Applied {
		t.Fatal("should be applied")
	}

	// Rules gone from the kernel (a flush): partial.
	fw.nftLoadedText = ""
	if state(t, c, env) != control.Partial {
		t.Fatal("a firewall that is not loaded is partial")
	}
	fw.nftLoadedText = rules

	must(t, c.Revert(ctx, env))
	if fw.nftLoadedText != "" {
		t.Fatal("the table must be removed")
	}
	noFile(t, env, nftFile)
	if read(t, env, nftConf) != origConf {
		t.Fatalf("nftables.conf must be as before:\n%s", read(t, env, nftConf))
	}
	if env.Rec.Has(fwID) {
		t.Fatal("record should be gone")
	}
	if run.did("systemctl disable nftables") {
		t.Fatal("the service was enabled before, it stays")
	}
}

func TestFirewallNftablesDisablesServiceThatWasOff(t *testing.T) {
	ctx := context.Background()
	env, run, _, _ := fwEnv(t)
	run.fail["systemctl is-enabled --quiet nftables"] = true
	must(t, fwControl().Apply(ctx, env, engineIn("nftables")))
	must(t, fwControl().Revert(ctx, env))
	if !run.did("systemctl disable nftables") {
		t.Fatal("the service was off before and must go back")
	}
}

func TestFirewallKeepsTheCurrentSessionPort(t *testing.T) {
	env, _, ssh, _ := fwEnv(t)
	ssh.listen = []int{22, 2200}
	t.Setenv("SSH_CONNECTION", "198.51.100.7 51234 203.0.113.5 2299")
	must(t, fwControl().Apply(context.Background(), env, engineIn("nftables")))
	wantContains(t, read(t, env, nftFile), "tcp dport { 22, 2200, 2299 } accept")
}

func TestFirewallRefusesWithoutSSH(t *testing.T) {
	env, run, ssh, _ := fwEnv(t)
	ssh.listen = nil
	run.fail["systemctl is-active --quiet sshd"] = true
	err := fwControl().Apply(context.Background(), env, engineIn("nftables"))
	if err == nil || !strings.Contains(err.Error(), "no SSH port") {
		t.Fatalf("error: %v", err)
	}
	noFile(t, env, nftFile)
	if run.did("nft -f") {
		t.Fatal("nothing may be loaded")
	}
}

func TestFirewallFallsBackToConfiguredSSHPort(t *testing.T) {
	// sshd is active but idle (socket activated), so ss does not show it.
	env, _, ssh, _ := fwEnv(t)
	ssh.listen = nil
	must(t, fwControl().Apply(context.Background(), env, engineIn("nftables")))
	wantContains(t, read(t, env, nftFile), "tcp dport { 22 } accept")
}

func TestFirewallRefusesForeignDropPolicy(t *testing.T) {
	env, run, _, fw := fwEnv(t)
	fw.foreign = "table inet filter {\n\tchain input {\n\t\ttype filter hook input priority filter; policy drop;\n\t}\n}\n"
	err := fwControl().Apply(context.Background(), env, engineIn("nftables"))
	if err == nil || !strings.Contains(err.Error(), "already loaded") {
		t.Fatalf("error: %v", err)
	}
	if run.did("nft -f") {
		t.Fatal("nothing may be loaded")
	}
}

func TestFirewallNftablesRefusedRulesChangeNothing(t *testing.T) {
	env, _, _, fw := fwEnv(t)
	fw.nftBad = true
	origConf := read(t, env, nftConf)
	err := fwControl().Apply(context.Background(), env, engineIn("nftables"))
	if err == nil || !strings.Contains(err.Error(), "refused") {
		t.Fatalf("error: %v", err)
	}
	noFile(t, env, nftFile)
	if read(t, env, nftConf) != origConf {
		t.Fatal("nftables.conf must be as before")
	}
	if env.Rec.Has(fwID) || fw.nftLoadedText != "" {
		t.Fatal("no record and no loaded table after a failure")
	}
}

func TestFirewallFirewalld(t *testing.T) {
	ctx := context.Background()
	env, run, _, fw := fwEnv(t)
	fw.fwdZone = "work"
	c := fwControl()
	must(t, c.Apply(ctx, env, engineIn("firewalld")))
	if !fw.fwdRunning || fw.fwdZone != "public" {
		t.Fatalf("running %v zone %q", fw.fwdRunning, fw.fwdZone)
	}
	if len(fw.fwdPorts) != 1 || fw.fwdPorts[0] != "22/tcp" {
		t.Fatalf("ports %v", fw.fwdPorts)
	}
	if got := strings.Join(fw.fwdServices, ","); got != "dhcpv6-client" {
		t.Fatalf("services %q: ssh and cockpit are closed, dhcpv6-client stays", got)
	}
	if v, _, _ := env.Rec.Get(fwID, "prev-zone"); v != "work" {
		t.Fatalf("prev zone %q", v)
	}
	if state(t, c, env) != control.Applied {
		t.Fatal("should be applied")
	}
	must(t, c.Revert(ctx, env))
	if fw.fwdRunning {
		t.Fatal("firewalld was not running before")
	}
	if !run.did("disable --now firewalld") {
		t.Fatalf("calls: %v", run.calls)
	}
}

func TestFirewallSwitchingEngineNeedsRevert(t *testing.T) {
	ctx := context.Background()
	env, _, _, _ := fwEnv(t)
	c := fwControl()
	must(t, c.Apply(ctx, env, engineIn("nftables")))
	err := c.Apply(ctx, env, engineIn("firewalld"))
	if err == nil || !strings.Contains(err.Error(), "Revert this control") {
		t.Fatalf("error: %v", err)
	}
	ins, _ := c.Inputs(ctx, env)
	if len(ins[0].Options) != 1 || ins[0].Default != "nftables" {
		t.Fatalf("only the recorded engine is offered: %+v", ins[0])
	}
	// A second run with the same engine is fine.
	must(t, c.Apply(ctx, env, engineIn("nftables")))
}

func TestFirewallUnknownEngine(t *testing.T) {
	env, _, _, _ := fwEnv(t)
	if err := fwControl().Apply(context.Background(), env, engineIn("iptables")); err == nil {
		t.Fatal("unknown engine accepted")
	}
}

func TestFirewallMeta(t *testing.T) {
	c, _ := System.Get(fwID)
	m := c.Meta()
	if !m.Has(control.TagLockout) || !m.Has(control.TagInput) || !m.Default {
		t.Fatalf("meta: %+v", m)
	}
}

func TestRevertWithoutRecordTouchesNoFirewall(t *testing.T) {
	env, run, _, _ := fwEnv(t)
	must(t, fwControl().Revert(context.Background(), env))
	if run.did("nft") || run.did("firewall-cmd") {
		t.Fatalf("calls: %v", run.calls)
	}
}

func TestFirewallNftablesReplacesRunningFirewalld(t *testing.T) {
	ctx := context.Background()
	env, run, _, fw := fwEnv(t)
	fw.fwdRunning = true
	run.out["systemctl is-enabled firewalld"] = ""
	c := fwControl()
	ins, _ := c.Inputs(ctx, env)
	if len(ins[0].Options) != 2 || ins[0].Default != "firewalld" {
		t.Fatalf("both engines are offered, firewalld first: %+v", ins[0])
	}
	must(t, c.Apply(ctx, env, engineIn("nftables")))
	if fw.fwdRunning {
		t.Fatal("two firewall managers fight over the rules, firewalld must stop")
	}
	// Our rules load before firewalld stops, so there is no moment without a firewall.
	iLoad, iStop := -1, -1
	for i, cmd := range run.calls {
		if cmd == "nft -f "+env.Path(nftFile) && iLoad < 0 {
			iLoad = i
		}
		if cmd == "systemctl disable --now firewalld" && iStop < 0 {
			iStop = i
		}
	}
	if iLoad < 0 || iStop < iLoad {
		t.Fatalf("load the rules first, then stop firewalld: %v", run.calls)
	}
	must(t, c.Revert(ctx, env))
	if !fw.fwdRunning {
		t.Fatal("firewalld was running before and must come back")
	}
	if fw.nftLoadedText != "" {
		t.Fatal("the nftables table must be gone")
	}
}

func TestFirewallNftablesFailsWhenFirewalldWillNotStop(t *testing.T) {
	env, run, _, fw := fwEnv(t)
	fw.fwdRunning = true
	run.fail["systemctl disable --now firewalld"] = true
	if err := fwControl().Apply(context.Background(), env, engineIn("nftables")); err == nil {
		t.Fatal("expected an error")
	}
	if fw.nftLoadedText != "" || env.Rec.Has(fwID) {
		t.Fatal("nothing may stay behind")
	}
}
