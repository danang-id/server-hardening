// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Danang Galuh Tegar Prasetyo

package controls

import (
	"context"

	"github.com/danang-id/server-hardening/internal/control"
	"github.com/danang-id/server-hardening/internal/kit"
	"github.com/danang-id/server-hardening/internal/sysctl"
)

// Short names for internal/sysctl, which every system shares.

type setting struct{ Key, Value string }

func shared(l []setting) []sysctl.Setting {
	out := make([]sysctl.Setting, len(l))
	for i, s := range l {
		out[i] = sysctl.Setting{Key: s.Key, Value: s.Value}
	}
	return out
}

func sysctlFile(name string) string { return sysctl.File(name) }

func sysctlMarker(id string) string { return kit.Marker(id) }

func sysctlGet(ctx context.Context, env *control.Env, key string) (string, bool) {
	return sysctl.Get(ctx, env, key)
}

func parseSysctl(content string) []setting {
	var out []setting
	for _, s := range sysctl.Parse(content) {
		out = append(out, setting{s.Key, s.Value})
	}
	return out
}

func sysctlApply(ctx context.Context, env *control.Env, id, name string, want []setting) ([]string, error) {
	return sysctl.Apply(ctx, env, id, name, shared(want))
}

func sysctlCheck(ctx context.Context, env *control.Env, id, name string) (control.State, error) {
	return sysctl.Check(ctx, env, id, name)
}

func sysctlRevert(ctx context.Context, env *control.Env, id, name string) error {
	return sysctl.Revert(ctx, env, id, name)
}
