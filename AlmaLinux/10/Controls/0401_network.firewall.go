// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Danang Galuh Tegar Prasetyo

package controls

import (
	"context"
	"fmt"
	"strings"

	"github.com/danang-id/server-hardening/internal/control"
	"github.com/danang-id/server-hardening/internal/systemd"
)

type hostFirewall struct{ control.Base }

func init() {
	System.Add(&hostFirewall{control.Base{M: control.Meta{
		ID:           fwID,
		Category:     control.Network,
		Number:       1,
		Title:        "Install a host firewall that blocks incoming traffic by default",
		Default:      true,
		Tags:         []control.Tag{control.TagLockout, control.TagInput},
		RevertLimits: "The engine's package stays installed.",
	}}})
}

var engineOptions = map[firewall]control.Option{
	firewalld: {Value: "firewalld", Label: "firewalld (AlmaLinux's own firewall)", Help: "A zone-based manager. It is installed on most AlmaLinux servers already."},
	nftables:  {Value: "nftables", Label: "nftables", Help: "Rules in one file, in a table of its own. A running firewalld is stopped and turned off, and comes back on revert."},
}

func (h *hostFirewall) Inputs(ctx context.Context, env *control.Env) ([]control.Input, error) {
	opts := []control.Option{engineOptions[firewalld], engineOptions[nftables]}
	def := "firewalld"
	help := "Pick one. Two firewall managers on one server fight over the same rules."
	if rec, _, _ := env.Rec.Get(fwID, "engine"); rec != "" {
		opts, def = []control.Option{engineOptions[firewall(rec)]}, rec
		help = "This engine is already set up by this tool. To switch engines, revert this control first."
	}
	return []control.Input{{Key: "engine", Label: "Firewall engine", Help: help, Kind: control.Choice, Options: opts, Default: def}}, nil
}

func (h *hostFirewall) Check(ctx context.Context, env *control.Env) (control.State, error) {
	if !env.Rec.Has(fwID) {
		return control.NotApplied, nil
	}
	e, _, err := env.Rec.Get(fwID, "engine")
	if err != nil || e == "" {
		return control.NotApplied, err
	}
	live := false
	switch firewall(e) {
	case nftables:
		live = nftLoaded(ctx, env)
	case firewalld:
		out, err := env.Run.Run(ctx, "firewall-cmd", "--state")
		live = err == nil && strings.TrimSpace(string(out)) == "running"
	}
	if !live {
		return control.Partial, nil
	}
	return control.Applied, nil
}

func (h *hostFirewall) Apply(ctx context.Context, env *control.Env, in control.Values) error {
	engine := firewall(in.String("engine"))
	if _, ok := engineOptions[engine]; !ok {
		return fmt.Errorf("unknown firewall engine %q", engine)
	}
	if rec, _, _ := env.Rec.Get(fwID, "engine"); rec != "" && rec != string(engine) {
		return fmt.Errorf("%s is already set up with %s. Revert this control before switching to %s", fwID, rec, engine)
	}
	fwdRunning := activeEngine(ctx, env) == firewalld
	if engine == nftables && !env.Rec.Has(fwID) && !fwdRunning {
		if out, err := env.Run.Run(ctx, "nft", "list", "ruleset"); err == nil && nftDropsInput.Match(out) {
			return fmt.Errorf("a firewall that drops incoming traffic is already loaded in nftables, and it is not this tool's. " +
				"Remove it or manage the rules there yourself")
		}
	}
	ssh, err := sshPorts(ctx, env)
	if err != nil {
		return err
	}
	env.Log.Infof("SSH stays open on port(s) %s", joinInts(ssh))

	fresh := !env.Rec.Has(fwID)
	var setup func(context.Context, *control.Env, []int) error
	switch engine {
	case nftables:
		setup = nftSetup
	case firewalld:
		setup = firewalldSetup
	}
	if err := setup(ctx, env, ssh); err != nil {
		if fresh {
			_ = env.Rec.Delete(fwID)
		}
		return err
	}
	if err := env.Rec.Put(fwID, "engine", string(engine)); err != nil {
		return err
	}
	if engine == nftables && fwdRunning {
		// The rules of this tool are loaded and keep SSH open, so firewalld can go
		// without a gap. Two managers on one server would fight over the rules.
		if err := recordUnit(ctx, env, fwID, "firewalld"); err != nil {
			return err
		}
		if err := systemd.DisableNow(ctx, env, "firewalld"); err != nil {
			_ = nftTeardown(ctx, env)
			_ = restoreUnit(ctx, env, fwID, "firewalld")
			if fresh {
				_ = env.Rec.Delete(fwID)
			}
			return fmt.Errorf("stopping firewalld: %w", err)
		}
		env.Log.Infof("firewalld is stopped and turned off, nftables took over")
	}
	env.Log.Infof("incoming traffic is blocked, except SSH. Open more ports with %s", portsID)
	return nil
}

func (h *hostFirewall) Revert(ctx context.Context, env *control.Env) error {
	if !env.Rec.Has(fwID) {
		env.Log.Warnf("%s: no record, leaving the firewall alone", fwID)
		return nil
	}
	e, _, err := env.Rec.Get(fwID, "engine")
	if err != nil {
		return err
	}
	switch firewall(e) {
	case nftables:
		// Bring firewalld back first, if this control turned it off, so that the
		// server is never without a firewall.
		if err = restoreUnit(ctx, env, fwID, "firewalld"); err == nil {
			err = nftTeardown(ctx, env)
		}
		if err == nil {
			if v, _, _ := env.Rec.Get(fwID, "enabled-before"); v != "yes" {
				_, _ = env.Run.Run(ctx, "systemctl", "disable", "nftables")
			}
		}
	case firewalld:
		err = firewalldTeardown(ctx, env)
	default:
		env.Log.Warnf("%s: no engine was recorded, nothing to undo", fwID)
	}
	if err != nil {
		return err
	}
	return env.Rec.Delete(fwID)
}
