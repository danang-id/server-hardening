// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Danang Galuh Tegar Prasetyo

package controls

import (
	"context"
	"fmt"
	"strings"

	"github.com/danang-id/server-hardening/internal/control"
)

const netSysctlID = "network.sysctl-network"

type sysctlNetwork struct{ control.Base }

func init() {
	System.Add(&sysctlNetwork{control.Base{M: control.Meta{
		ID:       netSysctlID,
		Category: control.Network,
		Number:   5,
		Title:    "Harden the kernel's network behaviour",
		Default:  true,
		Tags:     []control.Tag{control.TagInput},
	}}})
}

// Every setting is written for "all" and for "default", so interfaces that
// appear later (a VPN, a container bridge) get the same values.
func perInterface(name, value string, v6 bool) []setting {
	fam := "ipv4"
	if v6 {
		fam = "ipv6"
	}
	return []setting{
		{"net." + fam + ".conf.all." + name, value},
		{"net." + fam + ".conf.default." + name, value},
	}
}

func networkSettings(acceptRA bool) []setting {
	var s []setting
	add := func(l []setting) { s = append(s, l...) }
	add(perInterface("accept_redirects", "0", false))
	add(perInterface("accept_redirects", "0", true))
	add(perInterface("secure_redirects", "0", false))
	add(perInterface("send_redirects", "0", false))
	add(perInterface("accept_source_route", "0", false))
	add(perInterface("accept_source_route", "0", true))
	add(perInterface("rp_filter", "2", false)) // loose: also right for servers with more than one address
	add(perInterface("log_martians", "1", false))
	s = append(s,
		setting{"net.ipv4.tcp_syncookies", "1"},
		setting{"net.ipv4.icmp_echo_ignore_broadcasts", "1"},
		setting{"net.ipv4.icmp_ignore_bogus_error_responses", "1"},
	)
	if !acceptRA {
		add(perInterface("accept_ra", "0", true))
	}
	return s
}

// raInUse reports whether the IPv6 address or route of this server came from a
// router advertisement. Switching those off would end IPv6 at the next renewal.
func raInUse(ctx context.Context, env *control.Env) bool {
	if out, err := env.Run.Run(ctx, "ip", "-6", "route", "show"); err == nil && strings.Contains(string(out), "proto ra") {
		return true
	}
	if out, err := env.Run.Run(ctx, "ip", "-6", "addr", "show", "scope", "global", "dynamic"); err == nil {
		for l := range strings.SplitSeq(string(out), "\n") {
			if strings.Contains(l, "inet6") && strings.Contains(l, "dynamic") {
				return true
			}
		}
	}
	return false
}

func (n *sysctlNetwork) Inputs(ctx context.Context, env *control.Env) ([]control.Input, error) {
	def, help := "no", "No IPv6 router advertisement is in use here: the address and route are static."
	if raInUse(ctx, env) {
		def, help = "yes", "This server's IPv6 address or route came from a router advertisement. Answering no would end IPv6 at the next renewal."
	}
	return []control.Input{{
		Key:   "ra",
		Label: "Accept IPv6 router advertisements?",
		Help:  help,
		Kind:  control.Choice, Default: def,
		Options: []control.Option{
			{Value: "no", Label: "No: ignore them", Help: "Another machine on the network segment cannot hand this server a fake route."},
			{Value: "yes", Label: "Yes: keep accepting them", Help: "Needed if the provider hands out IPv6 this way."},
		},
	}}, nil
}

func (n *sysctlNetwork) Check(ctx context.Context, env *control.Env) (control.State, error) {
	return sysctlCheck(ctx, env, netSysctlID, "network")
}

func (n *sysctlNetwork) Apply(ctx context.Context, env *control.Env, in control.Values) error {
	ra := in.String("ra")
	if ra != "yes" && ra != "no" {
		return fmt.Errorf("answer yes or no to the router advertisements question, not %q", ra)
	}
	if ra == "no" && raInUse(ctx, env) {
		env.Log.Warnf("%s: this server's IPv6 comes from a router advertisement. IPv6 will stop working at the next renewal or reboot", netSysctlID)
	}
	skipped, err := sysctlApply(ctx, env, netSysctlID, "network", networkSettings(ra == "yes"))
	if err != nil {
		return err
	}
	if len(skipped) > 0 {
		env.Log.Infof("not on this kernel, skipped: %s", strings.Join(skipped, ", "))
	}
	env.Log.Infof("network kernel settings are hardened")
	return nil
}

func (n *sysctlNetwork) Revert(ctx context.Context, env *control.Env) error {
	return sysctlRevert(ctx, env, netSysctlID, "network")
}
