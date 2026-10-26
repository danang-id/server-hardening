// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Danang Galuh Tegar Prasetyo

package controls

import (
	"context"
	"io/fs"

	"github.com/danang-id/server-hardening/internal/control"
	"github.com/danang-id/server-hardening/internal/kit"
)

// Short names for the helpers in internal/kit, which every system shares.

const (
	libexecDir = kit.LibexecDir
	notifyPath = kit.NotifyPath
)

func managed(id string) string { return kit.Marker(id) }

func hasMarker(env *control.Env, path, id string) bool { return kit.HasMarker(env, path, id) }

func putFile(env *control.Env, id, path, content string, perm fs.FileMode) error {
	return kit.PutFile(env, id, path, content, perm)
}

func restoreFile(env *control.Env, id, path string) error { return kit.RestoreFile(env, id, path) }

func recordUnit(ctx context.Context, env *control.Env, id, unit string) error {
	return kit.RecordUnit(ctx, env, id, unit)
}

func restoreUnit(ctx context.Context, env *control.Env, id, unit string) error {
	return kit.RestoreUnit(ctx, env, id, unit)
}

func setKeyValue(content, key, value string) string { return kit.SetKeyValue(content, key, value) }

func getKeyValue(content, key string) (string, bool) { return kit.GetKeyValue(content, key) }

func listItems(s string) []string { return kit.ListItems(s) }

func lines(s string) []string { return kit.Lines(s) }

func errMissing(other, path string) error { return kit.ErrMissing(other, path) }

func yesNo(b bool) string { return kit.YesNo(b) }
