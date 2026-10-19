// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Danang Galuh Tegar Prasetyo

package controls

import (
	"context"
	"fmt"
	"strings"

	"github.com/danang-id/server-hardening/internal/control"
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
	nftables:  {Value: "nftables", Label: "nftables (Debian's own firewall)", Help: "Rules in one file, in a table of its own. Other rules on the server stay."},
	ufw:       {Value: "ufw", Label: "ufw", Help: "A simple front end for the Linux firewall, with plain commands."},
	firewalld: {Value: "firewalld", Label: "firewalld", Help: "A zone-based manager. It pulls in Python and D-Bus."},
}

func (h *hostFirewall) Inputs(ctx context.Context, env *control.Env) ([]control.Input, error) {
	opts := []control.Option{engineOptions[nftables], engineOptions[ufw], engineOptions[firewalld]}
	def := "nftables"
	help := "Pick one. Two firewall managers on one server fight over the same rules."
	if rec, _, _ := env.Rec.Get(fwID, "engine"); rec != "" {
		opts, def = []control.Option{engineOptions[firewall(rec)]}, rec
		help = "This engine is already set up by this tool. To switch engines, revert this control first."
	} else if a := activeEngine(ctx, env); a != noFirewall {
		opts, def = []control.Option{engineOptions[a]}, string(a)
		help = fmt.Sprintf("%s is already running on this server, so it is the only choice. A second firewall manager would fight with it.", a)
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
	case ufw:
		out, err := env.Run.Run(ctx, "ufw", "status", "verbose")
		live = err == nil && strings.Contains(string(out), "Status: active") && strings.Contains(string(out), "deny (incoming)")
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
	if a := activeEngine(ctx, env); a != noFirewall && a != engine {
		return fmt.Errorf("%s is already running. Two firewall managers on one server fight over the same rules, "+
			"so use %s, or stop %s and revert its rules first", a, a, a)
	}
	if engine == nftables && !env.Rec.Has(fwID) {
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
	case ufw:
		setup = ufwSetup
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
		err = nftTeardown(ctx, env)
		if err == nil {
			if v, _, _ := env.Rec.Get(fwID, "enabled-before"); v != "yes" {
				_, _ = env.Run.Run(ctx, "systemctl", "disable", "nftables")
			}
		}
	case ufw:
		err = ufwTeardown(ctx, env)
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
