// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Danang Galuh Tegar Prasetyo

package controls

import (
	"context"

	"github.com/danang-id/server-hardening/internal/control"
	"github.com/danang-id/server-hardening/internal/mounts"
)

// Short names for internal/mounts, which every system shares.

type fstabLine = mounts.FstabLine

var sizeValue = mounts.SizeValue

func mountOptions(ctx context.Context, env *control.Env, mnt string) (map[string]bool, string, error) {
	return mounts.Options(ctx, env, mnt)
}

func flagsOf(set map[string]bool) (nosuid, nodev, noexec bool) { return mounts.Flags(set) }

func remountFlags(ctx context.Context, env *control.Env, mnt string, nosuid, nodev, noexec bool) error {
	return mounts.Remount(ctx, env, mnt, nosuid, nodev, noexec)
}

func fstabHas(content, mnt string) (fstabLine, bool) { return mounts.FstabHas(content, mnt) }

func fstabSet(content, mnt, id, entry string) string { return mounts.FstabSet(content, mnt, id, entry) }

func readFstab(env *control.Env) (string, error) { return mounts.ReadFstab(env) }
