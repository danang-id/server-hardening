// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Danang Galuh Tegar Prasetyo

package controls

import (
	"context"
	"fmt"

	"github.com/danang-id/server-hardening/internal/control"
)

const ptraceID = "system-kernel.restrict-ptrace"

type restrictPtrace struct{ control.Base }

func init() {
	System.Add(&restrictPtrace{control.Base{M: control.Meta{
		ID:           ptraceID,
		Category:     control.SystemKernel,
		Number:       2,
		Title:        "Restrict process tracing",
		Default:      true,
		Tags:         []control.Tag{control.TagInput, control.TagCompat},
		RevertLimits: "If scope 3 was chosen, the previous value only comes back after a reboot.",
	}}})
}

func (r *restrictPtrace) Inputs(context.Context, *control.Env) ([]control.Input, error) {
	return []control.Input{{
		Key: "scope", Label: "Who may attach a debugger to a process", Kind: control.Choice, Default: "1",
		Options: []control.Option{
			{Value: "1", Label: "1: only to its own child processes (recommended)"},
			{Value: "2", Label: "2: only administrators"},
			{Value: "3", Label: "3: nobody. It cannot be lowered until the next reboot"},
		},
	}}, nil
}

func (r *restrictPtrace) Check(ctx context.Context, env *control.Env) (control.State, error) {
	return sysctlCheck(ctx, env, ptraceID, "ptrace")
}

func (r *restrictPtrace) Apply(ctx context.Context, env *control.Env, in control.Values) error {
	scope := in.String("scope")
	if scope != "1" && scope != "2" && scope != "3" {
		return fmt.Errorf("the ptrace scope %q is not 1, 2 or 3", scope)
	}
	if _, ok := sysctlGet(ctx, env, "kernel.yama.ptrace_scope"); !ok {
		return fmt.Errorf("this kernel has no Yama module, so the ptrace scope cannot be set")
	}
	if _, err := sysctlApply(ctx, env, ptraceID, "ptrace", []setting{{"kernel.yama.ptrace_scope", scope}}); err != nil {
		return err
	}
	if scope == "3" {
		env.Log.Warnf("scope 3 cannot be lowered until the next reboot")
	}
	return nil
}

func (r *restrictPtrace) Revert(ctx context.Context, env *control.Env) error {
	return sysctlRevert(ctx, env, ptraceID, "ptrace")
}
