// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Danang Galuh Tegar Prasetyo

package controls

import (
	"context"
	"fmt"
	"io/fs"
	"regexp"
	"strings"

	"github.com/danang-id/server-hardening/internal/control"
	"github.com/danang-id/server-hardening/internal/files"
	"github.com/danang-id/server-hardening/internal/systemd"
)

// Small helpers shared by many controls.

// managed is the marker line written into every file this tool owns.
func managed(id string) string {
	return "# Managed by github.com/danang-id/server-hardening (" + id + ")"
}

// hasMarker reports whether a file exists and carries the marker of a control.
func hasMarker(env *control.Env, path, id string) bool {
	b, err := files.ReadOptional(env.Path(path))
	return err == nil && strings.Contains(string(b), managed(id))
}

// putFile saves the earlier state of a file, then writes the new content.
func putFile(env *control.Env, id, path, content string, perm fs.FileMode) error {
	if err := env.Rec.Backup(id, env.Path(path)); err != nil {
		return err
	}
	return files.WriteAtomic(env.Path(path), []byte(content), perm)
}

// restoreFile puts a file back as it was before putFile.
func restoreFile(env *control.Env, id, path string) error {
	_, err := env.Rec.Restore(id, env.Path(path))
	return err
}

// recordUnit remembers whether a unit was enabled and running, the first time only.
func recordUnit(ctx context.Context, env *control.Env, id, unit string) error {
	if _, ok, err := env.Rec.Get(id, "enabled:"+unit); err != nil || ok {
		return err
	}
	if err := env.Rec.Put(id, "enabled:"+unit, yesNo(systemd.IsEnabled(ctx, env, unit))); err != nil {
		return err
	}
	return env.Rec.Put(id, "active:"+unit, yesNo(systemd.IsActive(ctx, env, unit)))
}

// restoreUnit puts a unit back to the state recordUnit saw.
func restoreUnit(ctx context.Context, env *control.Env, id, unit string) error {
	en, ok, err := env.Rec.Get(id, "enabled:"+unit)
	if err != nil || !ok {
		return err
	}
	ac, _, _ := env.Rec.Get(id, "active:"+unit)
	switch {
	case en == "yes" && ac == "yes":
		return systemd.EnableNow(ctx, env, unit)
	case en == "yes":
		if err := systemd.Enable(ctx, env, unit); err != nil {
			return err
		}
		_, err := env.Run.Run(ctx, "systemctl", "stop", unit)
		return err
	case ac == "yes":
		if err := systemd.Disable(ctx, env, unit); err != nil {
			return err
		}
		return systemd.Start(ctx, env, unit)
	}
	return systemd.DisableNow(ctx, env, unit)
}

// setKeyValue sets "key = value" in a configuration text, replacing every
// active line of that key (and keeping the other lines as they are). If the key
// is missing, the line is added at the end.
func setKeyValue(content, key, value string) string {
	re := regexp.MustCompile(`(?m)^[ \t]*` + regexp.QuoteMeta(key) + `[ \t]*=.*$`)
	line := key + " = " + value
	if re.MatchString(content) {
		done := false
		return re.ReplaceAllStringFunc(content, func(string) string {
			if done {
				return "# (replaced by server-hardening) " + line
			}
			done = true
			return line
		})
	}
	if content != "" && !strings.HasSuffix(content, "\n") {
		content += "\n"
	}
	return content + line + "\n"
}

// getKeyValue reads the last active "key = value" of a configuration text.
func getKeyValue(content, key string) (string, bool) {
	re := regexp.MustCompile(`(?m)^[ \t]*` + regexp.QuoteMeta(key) + `[ \t]*=[ \t]*(.*?)[ \t]*$`)
	m := re.FindAllStringSubmatch(content, -1)
	if len(m) == 0 {
		return "", false
	}
	return m[len(m)-1][1], true
}

// listItems splits a list of names separated by spaces, commas or new lines.
func listItems(s string) []string {
	return strings.FieldsFunc(s, func(r rune) bool { return r == ' ' || r == ',' || r == '\n' || r == '\t' })
}

// lines splits a stored list that has one entry per line.
func lines(s string) []string {
	var l []string
	for x := range strings.SplitSeq(s, "\n") {
		if x = strings.TrimSpace(x); x != "" {
			l = append(l, x)
		}
	}
	return l
}

// Where this project keeps the small helper programs that it installs.
const (
	libexecDir = "/usr/local/libexec/server-hardening"
	notifyPath = libexecDir + "/notify" // written by misc.notify, used when it exists
)

// errMissing says that a control needs a file that another control makes.
func errMissing(other, path string) error {
	return fmt.Errorf("%s is missing. Apply %s first", path, other)
}
