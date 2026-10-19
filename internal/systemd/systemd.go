// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Danang Galuh Tegar Prasetyo

// Package systemd wraps the few systemctl commands that controls need.
package systemd

import (
	"context"

	"github.com/danang-id/server-hardening/internal/control"
)

func ctl(ctx context.Context, env *control.Env, args ...string) error {
	_, err := env.Run.Run(ctx, "systemctl", args...)
	return err
}

// IsActive reports whether the unit is running.
func IsActive(ctx context.Context, env *control.Env, unit string) bool {
	return ctl(ctx, env, "is-active", "--quiet", unit) == nil
}

// IsEnabled reports whether the unit is enabled.
func IsEnabled(ctx context.Context, env *control.Env, unit string) bool {
	return ctl(ctx, env, "is-enabled", "--quiet", unit) == nil
}

// EnableNow enables the units and starts them.
func EnableNow(ctx context.Context, env *control.Env, units ...string) error {
	return ctl(ctx, env, append([]string{"enable", "--now"}, units...)...)
}

// DisableNow disables the units and stops them.
func DisableNow(ctx context.Context, env *control.Env, units ...string) error {
	return ctl(ctx, env, append([]string{"disable", "--now"}, units...)...)
}

// Enable enables the units without starting them.
func Enable(ctx context.Context, env *control.Env, units ...string) error {
	return ctl(ctx, env, append([]string{"enable"}, units...)...)
}

// Disable disables the units without stopping them.
func Disable(ctx context.Context, env *control.Env, units ...string) error {
	return ctl(ctx, env, append([]string{"disable"}, units...)...)
}

// Start starts the unit.
func Start(ctx context.Context, env *control.Env, unit string) error {
	return ctl(ctx, env, "start", unit)
}

// Restart restarts the unit.
func Restart(ctx context.Context, env *control.Env, unit string) error {
	return ctl(ctx, env, "restart", unit)
}
