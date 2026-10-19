// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Danang Galuh Tegar Prasetyo

package controls

import (
	"context"
	"fmt"
	"strings"

	"github.com/danang-id/server-hardening/internal/control"
)

const kernelSysctlID = "system-kernel.sysctl-kernel"

type sysctlKernel struct{ control.Base }

func init() {
	System.Add(&sysctlKernel{control.Base{M: control.Meta{
		ID:       kernelSysctlID,
		Category: control.SystemKernel,
		Number:   1,
		Title:    "Harden kernel settings",
		Default:  true,
		Tags:     []control.Tag{control.TagInput},
	}}})
}

func kernelSettings(sysrq string) []setting {
	return []setting{
		{"kernel.kptr_restrict", "2"},
		{"kernel.dmesg_restrict", "1"},
		{"kernel.perf_event_paranoid", "3"},
		{"fs.protected_hardlinks", "1"},
		{"fs.protected_symlinks", "1"},
		{"fs.protected_fifos", "2"},
		{"fs.protected_regular", "2"},
		{"fs.suid_dumpable", "0"},
		{"kernel.randomize_va_space", "2"},
		{"kernel.sysrq", sysrq},
	}
}

// sysrqValue turns the answer into the bit mask the kernel expects. "safe"
// allows sync (16), remount read-only (32) and reboot (128).
func sysrqValue(mode string) (string, error) {
	switch mode {
	case "off":
		return "0", nil
	case "safe":
		return "176", nil
	}
	return "", fmt.Errorf("the SysRq mode %q is not off or safe", mode)
}

func (k *sysctlKernel) Inputs(context.Context, *control.Env) ([]control.Input, error) {
	return []control.Input{{
		Key: "sysrq", Label: "Magic SysRq key", Kind: control.Choice, Default: "off",
		Help: "A keyboard sequence on the console that talks straight to the kernel.",
		Options: []control.Option{
			{Value: "off", Label: "Off (recommended)"},
			{Value: "safe", Label: "Safe: only sync, remount read-only and reboot"},
		},
	}}, nil
}

func (k *sysctlKernel) Check(ctx context.Context, env *control.Env) (control.State, error) {
	return sysctlCheck(ctx, env, kernelSysctlID, "kernel")
}

func (k *sysctlKernel) Apply(ctx context.Context, env *control.Env, in control.Values) error {
	v, err := sysrqValue(in.String("sysrq"))
	if err != nil {
		return err
	}
	skipped, err := sysctlApply(ctx, env, kernelSysctlID, "kernel", kernelSettings(v))
	if err != nil {
		return err
	}
	if len(skipped) > 0 {
		env.Log.Infof("not on this kernel, skipped: %s", strings.Join(skipped, ", "))
	}
	env.Log.Infof("kernel settings are hardened. Ordinary users need sudo for dmesg")
	return nil
}

func (k *sysctlKernel) Revert(ctx context.Context, env *control.Env) error {
	return sysctlRevert(ctx, env, kernelSysctlID, "kernel")
}
