// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Danang Galuh Tegar Prasetyo

// Package dnf wraps the few dnf and rpm commands that controls need on the
// Red Hat family (AlmaLinux, Rocky Linux).
package dnf

import (
	"context"
	"strings"

	"github.com/danang-id/server-hardening/internal/control"
)

func run(ctx context.Context, env *control.Env, args ...string) error {
	_, err := env.Run.Run(ctx, "dnf", append([]string{"-y"}, args...)...)
	return err
}

// Installed reports whether a package is installed.
func Installed(ctx context.Context, env *control.Env, pkg string) bool {
	_, err := env.Run.Run(ctx, "rpm", "-q", "--quiet", pkg)
	return err == nil
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

// MakeCache refreshes the package metadata.
func MakeCache(ctx context.Context, env *control.Env) error {
	return run(ctx, env, "makecache")
}

// CleanAll forgets the cached metadata, so the next command reads the
// repositories again.
func CleanAll(ctx context.Context, env *control.Env) error {
	return run(ctx, env, "clean", "all")
}

// Upgrade installs all available updates.
func Upgrade(ctx context.Context, env *control.Env) error {
	return run(ctx, env, "upgrade", "--refresh")
}

// Remove removes the packages and the dependencies that only they needed.
func Remove(ctx context.Context, env *control.Env, pkgs ...string) error {
	return run(ctx, env, append([]string{"remove"}, pkgs...)...)
}

// RemovePlan lists every package that Remove would remove, without removing
// anything. The names that were asked for are part of the list. dnf stops
// with an error at the question when it is told to answer no, so the error is
// ignored and the output is read.
func RemovePlan(ctx context.Context, env *control.Env, pkgs ...string) ([]string, error) {
	out, _ := env.Run.Run(ctx, "dnf", append([]string{"remove", "--assumeno"}, pkgs...)...)
	var plan []string
	in := false
	for l := range strings.SplitSeq(string(out), "\n") {
		t := strings.TrimSpace(l)
		switch {
		case strings.HasPrefix(t, "Removing"):
			in = true
		case t == "" || strings.HasPrefix(t, "Transaction Summary") || strings.HasPrefix(t, "===") || strings.HasPrefix(t, "Package "):
			if strings.HasPrefix(t, "Transaction Summary") {
				in = false
			}
		case in && strings.HasPrefix(l, " "):
			if f := strings.Fields(l); len(f) >= 2 {
				plan = append(plan, f[0])
			}
		}
	}
	return plan, nil
}

// Orphans lists the installed packages that no other package needs and that
// were installed as a dependency (dnf's "autoremove" candidates).
func Orphans(ctx context.Context, env *control.Env) []string {
	out, err := env.Run.Run(ctx, "dnf", "repoquery", "--unneeded", "--queryformat", "%{name}\\n")
	if err != nil {
		return nil
	}
	return strings.Fields(string(out))
}

// RepoEnabled reports whether a repository id is enabled.
func RepoEnabled(ctx context.Context, env *control.Env, id string) bool {
	out, err := env.Run.Run(ctx, "dnf", "repolist", "--enabled", "-q")
	if err != nil {
		return false
	}
	for l := range strings.SplitSeq(string(out), "\n") {
		if f := strings.Fields(l); len(f) > 0 && f[0] == id {
			return true
		}
	}
	return false
}
