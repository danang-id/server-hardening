// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Danang Galuh Tegar Prasetyo

package controls

import (
	"context"

	"github.com/danang-id/server-hardening/internal/control"
)

const forwardID = "network.disable-ip-forwarding"

type disableIPForwarding struct{ control.Base }

func init() {
	System.Add(&disableIPForwarding{control.Base{M: control.Meta{
		ID:       forwardID,
		Category: control.Network,
		Number:   4,
		Title:    "Disable IPv4 and IPv6 forwarding",
		Default:  true,
		Tags:     []control.Tag{control.TagCompat},
	}}})
}

var forwardingSettings = []setting{
	{"net.ipv4.ip_forward", "0"},
	{"net.ipv6.conf.all.forwarding", "0"},
}

func (d *disableIPForwarding) Check(ctx context.Context, env *control.Env) (control.State, error) {
	return sysctlCheck(ctx, env, forwardID, "no-forwarding")
}

func (d *disableIPForwarding) Apply(ctx context.Context, env *control.Env, _ control.Values) error {
	skipped, err := sysctlApply(ctx, env, forwardID, "no-forwarding", forwardingSettings)
	if err != nil {
		return err
	}
	for _, k := range skipped {
		env.Log.Infof("%s does not exist on this kernel, skipped", k)
	}
	env.Log.Infof("the server does not forward packets. Docker and VPN gateways need this switched back on")
	return nil
}

func (d *disableIPForwarding) Revert(ctx context.Context, env *control.Env) error {
	return sysctlRevert(ctx, env, forwardID, "no-forwarding")
}
