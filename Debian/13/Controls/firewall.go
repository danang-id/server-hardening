// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Danang Galuh Tegar Prasetyo

package controls

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/danang-id/server-hardening/internal/apt"
	"github.com/danang-id/server-hardening/internal/control"
	"github.com/danang-id/server-hardening/internal/files"
	fwrules "github.com/danang-id/server-hardening/internal/firewall"
	"github.com/danang-id/server-hardening/internal/systemd"
)

// Shared code of the three firewall controls (network.firewall,
// network.open-ports, network.firewall-log-denied).
//
// Three engines are supported. ufw and firewalld are driven through their
// commands. nftables is driven through one file with one table, which is
// rebuilt from the records of the three controls every time one of them
// changes, so the rules always agree with what the records say.

const (
	fwID    = "network.firewall"
	portsID = "network.open-ports"
	fwLogID = "network.firewall-log-denied"

	nftFile  = "/etc/nftables.d/server-hardening.nft"
	nftConf  = "/etc/nftables.conf"
	nftTable = "server_hardening"
	nftInc   = `include "/etc/nftables.d/*.nft"`

	nftables firewall = "nftables" // the engine of this tool's own nftables table
)

var firewalldPoll = struct {
	tries int
	every time.Duration
}{20, 500 * time.Millisecond}

// Port rules, which internal/firewall reads and writes

type portRule = fwrules.PortRule

func parsePortRule(line string) (portRule, error) { return fwrules.ParsePortRule(line) }

func parsePortRules(text string) ([]portRule, error) { return fwrules.ParsePortRules(text) }

func ruleLines(rs []portRule) string { return fwrules.RuleLines(rs) }

func firewalldRule(r portRule) (rich string, port string) { return fwrules.FirewalldRule(r) }

func nftRender(ssh []int, rules []portRule, logRate string) string {
	return fwrules.NftRender(sshdMarker(fwID), nftTable, ssh, rules, logRate)
}

func recordedRules(env *control.Env) ([]portRule, error) {
	v, _, err := env.Rec.Get(portsID, "rules")
	if err != nil {
		return nil, err
	}
	return parsePortRules(v)
}

// Finding SSH and the engine

// sshPorts lists the ports to keep open for SSH: those sshd listens on, and
// the port of the session the user is using now.
func sshPorts(ctx context.Context, env *control.Env) ([]int, error) {
	set := map[int]bool{}
	if used, err := listeningPorts(ctx, env); err == nil {
		for p, line := range used {
			if strings.Contains(line, `"sshd"`) {
				set[p] = true
			}
		}
	}
	if len(set) == 0 && systemd.IsActive(ctx, env, sshdService) {
		if ps, err := currentPorts(ctx, env); err == nil {
			for _, p := range ps {
				set[p] = true
			}
		}
	}
	// SSH_CONNECTION is "client-ip client-port server-ip server-port".
	if f := strings.Fields(os.Getenv("SSH_CONNECTION")); len(f) == 4 {
		if p, err := strconv.Atoi(f[3]); err == nil {
			set[p] = true
		}
	}
	var out []int
	for p := range set {
		out = append(out, p)
	}
	sort.Ints(out)
	if len(out) == 0 {
		return nil, fmt.Errorf("found no SSH port to keep open, and a firewall that drops everything else could lock you out. " +
			"Install and start the SSH server first (remote-access controls)")
	}
	return out, nil
}

// activeEngine finds a firewall manager that is running and is not ours.
func activeEngine(ctx context.Context, env *control.Env) firewall {
	if out, err := env.Run.Run(ctx, "ufw", "status"); err == nil && strings.Contains(string(out), "Status: active") {
		return ufw
	}
	if out, err := env.Run.Run(ctx, "firewall-cmd", "--state"); err == nil && strings.TrimSpace(string(out)) == "running" {
		return firewalld
	}
	return noFirewall
}

// engineOf returns the engine that network.firewall set up.
func engineOf(env *control.Env) (firewall, error) {
	if !env.Rec.Has(fwID) {
		return noFirewall, fmt.Errorf("%s has not been applied. Apply it first", fwID)
	}
	e, _, err := env.Rec.Get(fwID, "engine")
	if err != nil {
		return noFirewall, err
	}
	if e == "" {
		return noFirewall, fmt.Errorf("%s has no recorded engine", fwID)
	}
	return firewall(e), nil
}

// nftables

func nftSSHPorts(env *control.Env) ([]int, error) {
	a, _, err := env.Rec.Get(fwID, "ssh-ports")
	if err != nil {
		return nil, err
	}
	b, _, err := env.Rec.Get(fwID, "extra-ssh")
	if err != nil {
		return nil, err
	}
	set := map[int]bool{}
	for _, p := range append(splitInts(a), splitInts(b)...) {
		set[p] = true
	}
	var out []int
	for p := range set {
		out = append(out, p)
	}
	sort.Ints(out)
	return out, nil
}

// nftRebuild writes the table file from the records and loads it. The load is
// one transaction: either all rules are replaced or none are.
func nftRebuild(ctx context.Context, env *control.Env) error {
	ssh, err := nftSSHPorts(env)
	if err != nil {
		return err
	}
	if len(ssh) == 0 {
		return fmt.Errorf("no SSH port is recorded, refusing to write a firewall that could lock you out")
	}
	rules, err := recordedRules(env)
	if err != nil {
		return err
	}
	rate, _, err := env.Rec.Get(fwLogID, "rate")
	if err != nil {
		return err
	}
	path := env.Path(nftFile)
	old, err := files.ReadOptional(path)
	if err != nil {
		return err
	}
	tmp := path + ".new"
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	if err := files.WriteAtomic(tmp, []byte(nftRender(ssh, rules, rate)), 0o644); err != nil {
		return err
	}
	defer os.Remove(tmp)
	if _, err := env.Run.Run(ctx, "nft", "-c", "-f", tmp); err != nil {
		return fmt.Errorf("nft refused the rules, nothing was changed: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	if _, err := env.Run.Run(ctx, "nft", "-f", path); err != nil {
		if old == nil {
			_ = os.Remove(path)
		} else {
			_ = files.WriteAtomic(path, old, 0o644)
		}
		return fmt.Errorf("loading the rules: %w", err)
	}
	return nil
}

func nftLoaded(ctx context.Context, env *control.Env) bool {
	out, err := env.Run.Run(ctx, "nft", "list", "table", "inet", nftTable)
	return err == nil && strings.Contains(string(out), "policy drop")
}

func nftSetup(ctx context.Context, env *control.Env, ssh []int) error {
	if err := apt.Install(ctx, env, "nftables"); err != nil {
		return err
	}
	for _, f := range []string{nftConf, nftFile} {
		if err := env.Rec.Backup(fwID, env.Path(f)); err != nil {
			return err
		}
	}
	if err := env.Rec.Put(fwID, "ssh-ports", joinInts(ssh)); err != nil {
		return err
	}
	conf, err := files.ReadOptional(env.Path(nftConf))
	if err != nil {
		return err
	}
	// nftables.conf starts with "flush ruleset", so the include of this tool must come after it.
	if !strings.Contains(string(conf), nftInc) {
		c := string(conf)
		if c == "" {
			c = "#!/usr/sbin/nft -f\n\nflush ruleset\n"
		} else if !strings.HasSuffix(c, "\n") {
			c += "\n"
		}
		c += "\n# Added by server-hardening\n" + nftInc + "\n"
		if err := files.WriteAtomic(env.Path(nftConf), []byte(c), 0o755); err != nil {
			return err
		}
	}
	if err := env.Rec.Put(fwID, "enabled-before", yesNo(systemd.IsEnabled(ctx, env, "nftables"))); err != nil {
		return err
	}
	if err := nftRebuild(ctx, env); err != nil {
		_, _ = env.Rec.Restore(fwID, env.Path(nftConf))
		return err
	}
	if !nftLoaded(ctx, env) {
		_ = nftTeardown(ctx, env)
		return fmt.Errorf("the firewall table is not loaded after loading it, so it was removed")
	}
	// Only enable: starting the service would run "flush ruleset" and drop the
	// rules of other software (Docker, for example).
	return systemd.Enable(ctx, env, "nftables")
}

func nftTeardown(ctx context.Context, env *control.Env) error {
	_, _ = env.Run.Run(ctx, "nft", "delete", "table", "inet", nftTable)
	if _, err := env.Rec.Restore(fwID, env.Path(nftFile)); err != nil {
		return err
	}
	_, err := env.Rec.Restore(fwID, env.Path(nftConf))
	return err
}

// ufw

var ufwFiles = []string{"/etc/ufw/ufw.conf", "/etc/default/ufw", "/etc/ufw/user.rules", "/etc/ufw/user6.rules"}

func ufwSetup(ctx context.Context, env *control.Env, ssh []int) error {
	if err := apt.Install(ctx, env, "ufw"); err != nil {
		return err
	}
	for _, f := range ufwFiles {
		if err := env.Rec.Backup(fwID, env.Path(f)); err != nil {
			return err
		}
	}
	if out, err := env.Run.Run(ctx, "ufw", "status"); err == nil {
		if err := env.Rec.Put(fwID, "was-active", yesNo(strings.Contains(string(out), "Status: active"))); err != nil {
			return err
		}
	}
	run := func(args ...string) error { _, err := env.Run.Run(ctx, "ufw", args...); return err }
	rollback := func() {
		_ = run("--force", "disable")
		for _, f := range ufwFiles {
			_, _ = env.Rec.Restore(fwID, env.Path(f))
		}
	}
	steps := [][]string{{"default", "deny", "incoming"}, {"default", "allow", "outgoing"}}
	for _, p := range ssh {
		steps = append(steps, []string{"allow", strconv.Itoa(p) + "/tcp"})
	}
	steps = append(steps, []string{"--force", "enable"})
	for _, s := range steps {
		if err := run(s...); err != nil {
			rollback()
			return fmt.Errorf("ufw %s: %w", strings.Join(s, " "), err)
		}
	}
	return env.Rec.Put(fwID, "ssh-ports", joinInts(ssh))
}

func ufwTeardown(ctx context.Context, env *control.Env) error {
	wasActive, _, _ := env.Rec.Get(fwID, "was-active")
	if wasActive != "yes" {
		_, _ = env.Run.Run(ctx, "ufw", "--force", "disable")
	}
	for _, f := range ufwFiles {
		if _, err := env.Rec.Restore(fwID, env.Path(f)); err != nil {
			return err
		}
	}
	if wasActive == "yes" {
		_, err := env.Run.Run(ctx, "ufw", "reload")
		return err
	}
	return nil
}

func ufwSpec(r portRule) []string {
	port := strings.ReplaceAll(r.Port, "-", ":")
	if r.Source == "" {
		return []string{port + "/" + r.Proto}
	}
	return []string{"from", r.Source, "to", "any", "port", port, "proto", r.Proto}
}

// firewalld

var firewalldFiles = []string{"/etc/firewalld/firewalld.conf", "/etc/firewalld/zones/public.xml"}

func fwcmd(ctx context.Context, env *control.Env, args ...string) error {
	_, err := env.Run.Run(ctx, "firewall-cmd", args...)
	return err
}

func firewalldSetup(ctx context.Context, env *control.Env, ssh []int) error {
	if err := apt.Install(ctx, env, "firewalld"); err != nil {
		return err
	}
	for _, f := range firewalldFiles {
		if err := env.Rec.Backup(fwID, env.Path(f)); err != nil {
			return err
		}
	}
	for k, v := range map[string]string{
		"was-running": yesNo(systemd.IsActive(ctx, env, "firewalld")),
		"was-enabled": yesNo(systemd.IsEnabled(ctx, env, "firewalld")),
	} {
		if err := env.Rec.Put(fwID, k, v); err != nil {
			return err
		}
	}
	rollback := func() { _ = firewalldTeardown(ctx, env) }
	if err := systemd.EnableNow(ctx, env, "firewalld"); err != nil {
		rollback()
		return err
	}
	running := false
	for i := 0; i < firewalldPoll.tries && !running; i++ {
		if out, err := env.Run.Run(ctx, "firewall-cmd", "--state"); err == nil && strings.TrimSpace(string(out)) == "running" {
			running = true
			break
		}
		time.Sleep(firewalldPoll.every)
	}
	if !running {
		rollback()
		return fmt.Errorf("firewalld did not start")
	}
	if out, err := env.Run.Run(ctx, "firewall-cmd", "--get-default-zone"); err == nil {
		_ = env.Rec.Put(fwID, "prev-zone", strings.TrimSpace(string(out)))
	}
	steps := [][]string{{"--set-default-zone=public"}}
	for _, p := range ssh {
		steps = append(steps, []string{"--permanent", "--zone=public", "--add-port=" + strconv.Itoa(p) + "/tcp"})
	}
	steps = append(steps, []string{"--reload"})
	for _, s := range steps {
		if err := fwcmd(ctx, env, s...); err != nil {
			rollback()
			return fmt.Errorf("firewall-cmd %s: %w", strings.Join(s, " "), err)
		}
	}
	return env.Rec.Put(fwID, "ssh-ports", joinInts(ssh))
}

func firewalldTeardown(ctx context.Context, env *control.Env) error {
	for _, f := range firewalldFiles {
		if _, err := env.Rec.Restore(fwID, env.Path(f)); err != nil {
			return err
		}
	}
	if v, _, _ := env.Rec.Get(fwID, "was-running"); v != "yes" {
		_ = systemd.DisableNow(ctx, env, "firewalld")
		if v, _, _ := env.Rec.Get(fwID, "was-enabled"); v == "yes" {
			_ = systemd.Enable(ctx, env, "firewalld")
		}
		return nil
	}
	return fwcmd(ctx, env, "--reload")
}
