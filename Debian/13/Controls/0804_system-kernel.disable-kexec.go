// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Danang Galuh Tegar Prasetyo

package controls

import (
	"context"

	"github.com/danang-id/server-hardening/internal/control"
)

const kexecID = "system-kernel.disable-kexec"

type disableKexec struct{ control.Base }

func init() {
	System.Add(&disableKexec{control.Base{M: control.Meta{
		ID:           kexecID,
		Category:     control.SystemKernel,
		Number:       4,
		Title:        "Disable loading a new kernel at runtime",
		Default:      true,
		Tags:         []control.Tag{control.TagCompat},
		RevertLimits: "The kernel does not allow the setting to be lowered while running, so it is only lifted at the next reboot.",
	}}})
}

func (d *disableKexec) Check(ctx context.Context, env *control.Env) (control.State, error) {
	return sysctlCheck(ctx, env, kexecID, "kexec")
}

func (d *disableKexec) Apply(ctx context.Context, env *control.Env, _ control.Values) error {
	if _, err := sysctlApply(ctx, env, kexecID, "kexec", []setting{{"kernel.kexec_load_disabled", "1"}}); err != nil {
		return err
	}
	env.Log.Warnf("kexec stays disabled until the next reboot, even if you revert this control. kdump needs kexec")
	return nil
}

func (d *disableKexec) Revert(ctx context.Context, env *control.Env) error {
	if env.Rec.Has(kexecID) {
		env.Log.Warnf("the kernel keeps kexec disabled until the next reboot")
	}
	return sysctlRevert(ctx, env, kexecID, "kexec")
}
