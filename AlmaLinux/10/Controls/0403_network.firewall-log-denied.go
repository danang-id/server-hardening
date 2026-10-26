// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Danang Galuh Tegar Prasetyo

package controls

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/danang-id/server-hardening/internal/control"
)

type firewallLogDenied struct{ control.Base }

func init() {
	System.Add(&firewallLogDenied{control.Base{M: control.Meta{
		ID:       fwLogID,
		Category: control.Network,
		Number:   3,
		Title:    "Log dropped incoming packets",
		Default:  false,
		Requires: []string{fwID},
		Tags:     []control.Tag{control.TagInput},
	}}})
}

var (
	logRate      = regexp.MustCompile(`^[1-9][0-9]{0,5}/(second|minute|hour)$`)
	firewalldLog = map[string]bool{"all": true, "unicast": true, "broadcast": true, "multicast": true}
)

func (l *firewallLogDenied) Inputs(_ context.Context, env *control.Env) ([]control.Input, error) {
	e, err := engineOf(env)
	if err != nil {
		return nil, nil // Apply explains it
	}
	switch e {
	case firewalld:
		return []control.Input{{
			Key: "mode", Label: "Which dropped packets to log", Kind: control.Choice, Default: "unicast",
			Options: []control.Option{
				{Value: "unicast", Label: "unicast (recommended)"},
				{Value: "all", Label: "all"},
				{Value: "broadcast", Label: "broadcast"},
				{Value: "multicast", Label: "multicast"},
			},
		}}, nil
	}
	return []control.Input{{
		Key: "rate", Label: "Highest number of logged packets (count/second, minute or hour)",
		Help: "For example 5/minute", Default: "5/minute",
		Validate: func(s string) error {
			if !logRate.MatchString(strings.TrimSpace(s)) {
				return fmt.Errorf("use the form 5/minute")
			}
			return nil
		},
	}}, nil
}

func (l *firewallLogDenied) Check(ctx context.Context, env *control.Env) (control.State, error) {
	if !env.Rec.Has(fwLogID) {
		return control.NotApplied, nil
	}
	e, err := engineOf(env)
	if err != nil {
		return control.NotApplied, nil
	}
	want, _, _ := env.Rec.Get(fwLogID, "want")
	live := false
	switch e {
	case nftables:
		out, err := env.Run.Run(ctx, "nft", "list", "table", "inet", nftTable)
		live = err == nil && strings.Contains(string(out), "log prefix")
	case firewalld:
		out, err := env.Run.Run(ctx, "firewall-cmd", "--get-log-denied")
		live = err == nil && strings.TrimSpace(string(out)) == want
	}
	if !live {
		return control.Partial, nil
	}
	return control.Applied, nil
}

func (l *firewallLogDenied) Apply(ctx context.Context, env *control.Env, in control.Values) error {
	e, err := engineOf(env)
	if err != nil {
		return err
	}
	fresh := !env.Rec.Has(fwLogID)
	fail := func(err error) error {
		if fresh {
			_ = env.Rec.Delete(fwLogID)
		}
		return err
	}
	switch e {
	case nftables:
		rate := strings.TrimSpace(in.String("rate"))
		if !logRate.MatchString(rate) {
			return fmt.Errorf("the rate %q is not of the form 5/minute", rate)
		}
		prev, _, _ := env.Rec.Get(fwLogID, "rate")
		if err := env.Rec.Put(fwLogID, "rate", rate); err != nil {
			return err
		}
		if err := nftRebuild(ctx, env); err != nil {
			if fresh {
				_ = env.Rec.Delete(fwLogID)
			} else {
				_ = env.Rec.Put(fwLogID, "rate", prev)
			}
			return err
		}
		return env.Rec.Put(fwLogID, "want", rate)
	case firewalld:
		mode := in.String("mode")
		if !firewalldLog[mode] {
			return fmt.Errorf("unknown denied-packet mode %q", mode)
		}
		if _, ok, _ := env.Rec.Get(fwLogID, "prev"); !ok {
			out, _ := env.Run.Run(ctx, "firewall-cmd", "--get-log-denied")
			if err := env.Rec.Put(fwLogID, "prev", strings.TrimSpace(string(out))); err != nil {
				return err
			}
		}
		if err := fwcmd(ctx, env, "--set-log-denied="+mode); err != nil {
			return fail(err)
		}
		if err := fwcmd(ctx, env, "--reload"); err != nil {
			return fail(err)
		}
		return env.Rec.Put(fwLogID, "want", mode)
	}
	return fmt.Errorf("unknown engine %s", e)
}

func (l *firewallLogDenied) Revert(ctx context.Context, env *control.Env) error {
	if !env.Rec.Has(fwLogID) {
		env.Log.Warnf("%s: no record, leaving the logging alone", fwLogID)
		return nil
	}
	e, err := engineOf(env)
	if err != nil {
		return env.Rec.Delete(fwLogID) // the firewall went first and took its settings with it
	}
	prev, _, _ := env.Rec.Get(fwLogID, "prev")
	switch e {
	case nftables:
		if err := env.Rec.Put(fwLogID, "rate", ""); err != nil {
			return err
		}
		if err := nftRebuild(ctx, env); err != nil {
			return err
		}
	case firewalld:
		if prev == "" {
			prev = "off"
		}
		if err := fwcmd(ctx, env, "--set-log-denied="+prev); err != nil {
			return err
		}
		if err := fwcmd(ctx, env, "--reload"); err != nil {
			return err
		}
	}
	return env.Rec.Delete(fwLogID)
}
