// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Danang Galuh Tegar Prasetyo

// Package apt wraps the few apt and dpkg commands that controls need.
package apt

import (
	"context"
	"strings"

	"github.com/danang-id/server-hardening/internal/control"
)

var noninteractive = []string{
	"env", "DEBIAN_FRONTEND=noninteractive",
	"apt-get", "-y", "-o", "Dpkg::Options::=--force-confdef", "-o", "Dpkg::Options::=--force-confold",
}

func run(ctx context.Context, env *control.Env, args ...string) error {
	cmd := append(append([]string(nil), noninteractive...), args...)
	_, err := env.Run.Run(ctx, cmd[0], cmd[1:]...)
	return err
}

// Installed reports whether a package is installed.
func Installed(ctx context.Context, env *control.Env, pkg string) bool {
	out, err := env.Run.Run(ctx, "dpkg-query", "-W", "-f=${Status}", pkg)
	return err == nil && strings.Contains(string(out), "install ok installed")
}

// Install installs the packages that are not installed yet.
func Install(ctx context.Context, env *control.Env, pkgs ...string) error {
	var missing []string
	for _, p := range pkgs {
		if !Installed(ctx, env, p) {
			missing = append(missing, p)
		}
	}
	if len(missing) == 0 {
		return nil
	}
	env.Log.Infof("installing %s", strings.Join(missing, ", "))
	return run(ctx, env, append([]string{"install"}, missing...)...)
}

// Update refreshes the package lists.
func Update(ctx context.Context, env *control.Env) error {
	_, err := env.Run.Run(ctx, "apt-get", "update")
	return err
}

// FullUpgrade installs all available updates, keeping existing configuration.
func FullUpgrade(ctx context.Context, env *control.Env) error {
	return run(ctx, env, "full-upgrade")
}

// Purge removes the packages together with their configuration, and the
// packages that were only installed to satisfy them.
func Purge(ctx context.Context, env *control.Env, pkgs ...string) error {
	return run(ctx, env, append([]string{"purge", "--auto-remove"}, pkgs...)...)
}

// PurgePlan lists every package that Purge would remove, without removing
// anything. The names that were asked for are part of the list.
func PurgePlan(ctx context.Context, env *control.Env, pkgs ...string) ([]string, error) {
	out, err := env.Run.Run(ctx, "apt-get", append([]string{"-s", "purge", "--auto-remove"}, pkgs...)...)
	if err != nil {
		return nil, err
	}
	var plan []string
	for l := range strings.SplitSeq(string(out), "\n") {
		if f := strings.Fields(l); len(f) >= 2 && (f[0] == "Purg" || f[0] == "Remv") {
			plan = append(plan, f[1])
		}
	}
	return plan, nil
}
