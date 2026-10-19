// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Danang Galuh Tegar Prasetyo

package controls

import (
	"context"
	"fmt"

	"github.com/danang-id/server-hardening/internal/control"
)

const forwardingID = "remote-access.ssh-disable-forwarding"

type sshDisableForwarding struct{ control.Base }

func init() {
	System.Add(&sshDisableForwarding{control.Base{M: control.Meta{
		ID:       forwardingID,
		Category: control.RemoteAccess,
		Number:   9,
		Title:    "Disable X11 and agent forwarding, restrict TCP forwarding",
		Default:  true,
		Tags:     []control.Tag{control.TagInput},
	}}})
}

var tcpForwardingModes = map[string]bool{"no": true, "local": true, "remote": true, "yes": true}

func (f *sshDisableForwarding) Inputs(context.Context, *control.Env) ([]control.Input, error) {
	return []control.Input{{
		Key:   "tcp",
		Label: "TCP forwarding (tunnels through the server)",
		Kind:  control.Choice, Default: "no",
		Options: []control.Option{
			{Value: "no", Label: "No tunnels at all", Help: "Jump hosts (-J), ssh -L and tools such as VS Code Remote-SSH stop working."},
			{Value: "local", Label: "Local only: ssh -L, jump hosts", Help: "Tunnels from your computer through the server."},
			{Value: "remote", Label: "Remote only: ssh -R", Help: "Tunnels back from the server to your computer."},
			{Value: "yes", Label: "Both directions"},
		},
	}}, nil
}

func (f *sshDisableForwarding) Check(ctx context.Context, env *control.Env) (control.State, error) {
	return sshdCheck(ctx, env, forwardingID, "forwarding")
}

func (f *sshDisableForwarding) Apply(ctx context.Context, env *control.Env, in control.Values) error {
	mode := in.String("tcp")
	if !tcpForwardingModes[mode] {
		return fmt.Errorf("unknown TCP forwarding mode %q", mode)
	}
	ds := []directive{
		{"X11Forwarding", "no"},
		{"AllowAgentForwarding", "no"},
		{"AllowTcpForwarding", mode},
	}
	if err := sshdApply(ctx, env, forwardingID, "forwarding", ds); err != nil {
		return err
	}
	env.Log.Infof("forwarding is restricted (TCP forwarding: %s)", mode)
	return nil
}

func (f *sshDisableForwarding) Revert(ctx context.Context, env *control.Env) error {
	return sshdRevert(ctx, env, forwardingID, "forwarding")
}
