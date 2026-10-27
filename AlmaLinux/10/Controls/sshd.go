// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Danang Galuh Tegar Prasetyo

package controls

import (
	"context"

	"github.com/danang-id/server-hardening/internal/control"
	"github.com/danang-id/server-hardening/internal/dnf"
	"github.com/danang-id/server-hardening/internal/kit"
	"github.com/danang-id/server-hardening/internal/sshd"
)

// Short names for internal/sshd, which every system shares. The three things
// that differ on AlmaLinux are the unit name, the package and the folder that
// sshd -t needs (none).

const (
	sshdDir     = sshd.Dir
	sshdService = "sshd"
	sshdPackage = "openssh-server"
)

var sshdServer = sshd.Server{
	Service: sshdService,
	Install: func(ctx context.Context, env *control.Env) error {
		return dnf.Install(ctx, env, sshdPackage)
	},
}

type directive struct{ Key, Value string }

func shareDirectives(l []directive) []sshd.Directive {
	out := make([]sshd.Directive, len(l))
	for i, d := range l {
		out[i] = sshd.Directive{Key: d.Key, Value: d.Value}
	}
	return out
}

func sshdFile(name string) string { return sshd.File(name) }

func sshdMarker(id string) string { return kit.Marker(id) }

func parseSSHD(content string) []directive {
	var out []directive
	for _, d := range sshd.Parse(content) {
		out = append(out, directive{d.Key, d.Value})
	}
	return out
}

func sshdEffective(ctx context.Context, env *control.Env) (map[string][]string, error) {
	return sshd.Effective(ctx, env)
}

func sshdCheck(ctx context.Context, env *control.Env, id, name string) (control.State, error) {
	return sshd.Check(ctx, env, id, name)
}

func sshdValidate(ctx context.Context, env *control.Env) error { return sshdServer.Validate(ctx, env) }

func sshdReload(ctx context.Context, env *control.Env) error { return sshdServer.Reload(ctx, env) }

func sshdApply(ctx context.Context, env *control.Env, id, name string, ds []directive) error {
	return sshdServer.Apply(ctx, env, id, name, shareDirectives(ds))
}

func sshdRevert(ctx context.Context, env *control.Env, id, name string) error {
	return sshdServer.Revert(ctx, env, id, name)
}
