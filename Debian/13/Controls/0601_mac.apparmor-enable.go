// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Danang Galuh Tegar Prasetyo

package controls

import (
	"context"
	"fmt"

	"github.com/danang-id/server-hardening/internal/apt"
	"github.com/danang-id/server-hardening/internal/control"
	"github.com/danang-id/server-hardening/internal/files"
	"github.com/danang-id/server-hardening/internal/systemd"
)

const (
	apparmorID   = "mac.apparmor-enable"
	apparmorUnit = "apparmor.service"
	apparmorGrub = "/etc/default/grub.d/99-server-hardening-apparmor.cfg"
)

type apparmorEnable struct{ control.Base }

func init() {
	System.Add(&apparmorEnable{control.Base{M: control.Meta{
		ID:           apparmorID,
		Category:     control.MAC,
		Number:       1,
		Title:        "Enable AppArmor",
		Default:      true,
		Tags:         []control.Tag{control.TagReboot},
		RevertLimits: "The kernel keeps running AppArmor until the next reboot. The packages stay installed.",
	}}})
}

func apparmorInKernel(ctx context.Context, env *control.Env) bool {
	_, err := env.Run.Run(ctx, "aa-status", "--enabled")
	return err == nil
}

// apparmorPackages are what Apply installs. The tools in apparmor-utils
// (aa-enforce, aa-complain) are what the next control, mac.apparmor-enforce-
// profiles, runs, so "applied" must include them.
var apparmorPackages = []string{"apparmor", "apparmor-utils", "apparmor-profiles"}

// Check reports Applied only when Apply would have nothing left to do. Debian
// has had AppArmor on in the kernel by default since Debian 10, so a new
// server often has it running already, but without the tools: that is Partial.
func (a *apparmorEnable) Check(ctx context.Context, env *control.Env) (control.State, error) {
	if !apt.Installed(ctx, env, "apparmor") {
		return control.NotApplied, nil
	}
	if !apparmorInKernel(ctx, env) {
		if hasMarker(env, apparmorGrub, apparmorID) {
			return control.Pending, nil // set, waiting for the reboot
		}
		return control.NotApplied, nil
	}
	if !systemd.IsEnabled(ctx, env, apparmorUnit) {
		return control.Partial, nil
	}
	for _, p := range apparmorPackages {
		if !apt.Installed(ctx, env, p) {
			return control.Partial, nil // running, but without the tools
		}
	}
	return control.Applied, nil
}

func (a *apparmorEnable) Apply(ctx context.Context, env *control.Env, _ control.Values) error {
	if err := apt.Install(ctx, env, apparmorPackages...); err != nil {
		return err
	}
	if err := recordUnit(ctx, env, apparmorID, apparmorUnit); err != nil {
		return err
	}
	if err := systemd.EnableNow(ctx, env, apparmorUnit); err != nil {
		return fmt.Errorf("cannot enable the AppArmor service: %w", err)
	}
	if apparmorInKernel(ctx, env) {
		env.Log.Infof("AppArmor is active in the kernel")
		return nil
	}

	// The kernel runs without AppArmor: ask for it on the kernel command line.
	if !files.Exists(env.Path("/etc/default/grub")) {
		env.Log.Warnf("AppArmor is not active in the kernel, and this server does not boot with GRUB. " +
			"Add \"apparmor=1 security=apparmor\" to the kernel command line by hand, then reboot")
		return nil
	}
	content := managed(apparmorID) + "\n" +
		"GRUB_CMDLINE_LINUX_DEFAULT=\"$GRUB_CMDLINE_LINUX_DEFAULT apparmor=1 security=apparmor\"\n"
	if err := putFile(env, apparmorID, apparmorGrub, content, 0o644); err != nil {
		return err
	}
	if _, err := env.Run.Run(ctx, "update-grub"); err != nil {
		_ = restoreFile(env, apparmorID, apparmorGrub)
		return fmt.Errorf("update-grub failed: %w", err)
	}
	env.Log.Warnf("reboot the server to switch AppArmor on in the kernel")
	return nil
}

func (a *apparmorEnable) Revert(ctx context.Context, env *control.Env) error {
	if !env.Rec.Has(apparmorID) {
		env.Log.Warnf("%s: no record, leaving AppArmor alone", apparmorID)
		return nil
	}
	if hasMarker(env, apparmorGrub, apparmorID) {
		if err := restoreFile(env, apparmorID, apparmorGrub); err != nil {
			return err
		}
		if _, err := env.Run.Run(ctx, "update-grub"); err != nil {
			return fmt.Errorf("update-grub failed: %w", err)
		}
	}
	if err := restoreUnit(ctx, env, apparmorID, apparmorUnit); err != nil {
		return err
	}
	return env.Rec.Delete(apparmorID)
}
