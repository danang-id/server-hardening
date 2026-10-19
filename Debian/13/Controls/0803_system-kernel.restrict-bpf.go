// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Danang Galuh Tegar Prasetyo

package controls

import (
	"context"
	"fmt"
	"strings"

	"github.com/danang-id/server-hardening/internal/control"
)

const bpfID = "system-kernel.restrict-bpf"

type restrictBPF struct{ control.Base }

func init() {
	System.Add(&restrictBPF{control.Base{M: control.Meta{
		ID:           bpfID,
		Category:     control.SystemKernel,
		Number:       3,
		Title:        "Restrict eBPF to root",
		Default:      true,
		Tags:         []control.Tag{control.TagInput},
		RevertLimits: "If mode 1 was chosen, the previous values only come back after a reboot.",
	}}})
}

func (r *restrictBPF) Inputs(context.Context, *control.Env) ([]control.Input, error) {
	return []control.Input{{
		Key: "mode", Label: "Unprivileged eBPF", Kind: control.Choice, Default: "2",
		Options: []control.Option{
			{Value: "2", Label: "2: disabled for ordinary users, root can switch it back (recommended)"},
			{Value: "1", Label: "1: disabled and locked until the next reboot"},
		},
	}}, nil
}

func (r *restrictBPF) Check(ctx context.Context, env *control.Env) (control.State, error) {
	return sysctlCheck(ctx, env, bpfID, "bpf")
}

func (r *restrictBPF) Apply(ctx context.Context, env *control.Env, in control.Values) error {
	mode := in.String("mode")
	if mode != "1" && mode != "2" {
		return fmt.Errorf("the eBPF mode %q is not 1 or 2", mode)
	}
	// bpf_jit_harden only exists when the compiler is built in: it is skipped otherwise.
	skipped, err := sysctlApply(ctx, env, bpfID, "bpf", []setting{
		{"kernel.unprivileged_bpf_disabled", mode},
		{"net.core.bpf_jit_harden", "2"},
	})
	if err != nil {
		return err
	}
	if len(skipped) > 0 {
		env.Log.Infof("not on this kernel, skipped: %s", strings.Join(skipped, ", "))
	}
	if mode == "1" {
		env.Log.Warnf("mode 1 cannot be lowered until the next reboot")
	}
	return nil
}

func (r *restrictBPF) Revert(ctx context.Context, env *control.Env) error {
	return sysctlRevert(ctx, env, bpfID, "bpf")
}
