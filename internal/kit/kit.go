// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Danang Galuh Tegar Prasetyo

// Package kit holds the small helpers that the controls of every system share:
// managed-file markers, backed-up file writes, remembered unit states and the
// reading of "key = value" configuration text. Nothing here knows about a
// package manager, so every Linux system can use it.
package kit

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

// Where this project keeps the small helper programs that it installs.
const (
	LibexecDir = "/usr/local/libexec/server-hardening"
	NotifyPath = LibexecDir + "/notify" // written by misc.notify, used when it exists
)

// Marker is the line written into every file this tool owns.
func Marker(id string) string {
	return "# Managed by github.com/danang-id/server-hardening (" + id + ")"
}

// HasMarker reports whether a file exists and carries the marker of a control.
func HasMarker(env *control.Env, path, id string) bool {
	b, err := files.ReadOptional(env.Path(path))
	return err == nil && strings.Contains(string(b), Marker(id))
}

// PutFile saves the earlier state of a file, then writes the new content.
func PutFile(env *control.Env, id, path, content string, perm fs.FileMode) error {
	if err := env.Rec.Backup(id, env.Path(path)); err != nil {
		return err
	}
	return files.WriteAtomic(env.Path(path), []byte(content), perm)
}

// RestoreFile puts a file back as it was before PutFile.
func RestoreFile(env *control.Env, id, path string) error {
	_, err := env.Rec.Restore(id, env.Path(path))
	return err
}

// YesNo is how a boolean is stored in the records.
func YesNo(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

// RecordUnit remembers whether a unit was enabled and running, the first time only.
func RecordUnit(ctx context.Context, env *control.Env, id, unit string) error {
	if _, ok, err := env.Rec.Get(id, "enabled:"+unit); err != nil || ok {
		return err
	}
	if err := env.Rec.Put(id, "enabled:"+unit, YesNo(systemd.IsEnabled(ctx, env, unit))); err != nil {
		return err
	}
	return env.Rec.Put(id, "active:"+unit, YesNo(systemd.IsActive(ctx, env, unit)))
}

// RestoreUnit puts a unit back to the state RecordUnit saw.
func RestoreUnit(ctx context.Context, env *control.Env, id, unit string) error {
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

// SetKeyValue sets "key = value" in a configuration text, replacing every
// active line of that key (and keeping the other lines as they are). If the key
// is missing, the line is added at the end.
func SetKeyValue(content, key, value string) string {
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

// GetKeyValue reads the last active "key = value" of a configuration text.
func GetKeyValue(content, key string) (string, bool) {
	re := regexp.MustCompile(`(?m)^[ \t]*` + regexp.QuoteMeta(key) + `[ \t]*=[ \t]*(.*?)[ \t]*$`)
	m := re.FindAllStringSubmatch(content, -1)
	if len(m) == 0 {
		return "", false
	}
	return m[len(m)-1][1], true
}

// ListItems splits a list of names separated by spaces, commas or new lines.
func ListItems(s string) []string {
	return strings.FieldsFunc(s, func(r rune) bool { return r == ' ' || r == ',' || r == '\n' || r == '\t' })
}

// Lines splits a stored list that has one entry per line.
func Lines(s string) []string {
	var l []string
	for x := range strings.SplitSeq(s, "\n") {
		if x = strings.TrimSpace(x); x != "" {
			l = append(l, x)
		}
	}
	return l
}

// ErrMissing says that a control needs a file that another control makes.
func ErrMissing(other, path string) error {
	return fmt.Errorf("%s is missing. Apply %s first", path, other)
}

// SetINI sets "key = value" inside [section] of an INI-style text. The first
// active line of the key in that section is replaced, later ones are commented
// out, and the other lines stay as they are. If the key is missing it is added
// at the end of the section, and a missing section is added at the end of the
// text.
func SetINI(content, section, key, value string) string {
	line := key + " = " + value
	ls := strings.Split(strings.TrimSuffix(content, "\n"), "\n")
	if content == "" {
		ls = nil
	}
	in, found, done := false, false, false
	lastInSection := -1 // index of the last non-blank line of the section
	for i, l := range ls {
		t := strings.TrimSpace(l)
		if strings.HasPrefix(t, "[") && strings.HasSuffix(t, "]") {
			in = strings.TrimSpace(t[1:len(t)-1]) == section
			found = found || in
			if in {
				lastInSection = i
			}
			continue
		}
		if !in {
			continue
		}
		if t != "" {
			lastInSection = i
		}
		if t == "" || strings.HasPrefix(t, "#") || strings.HasPrefix(t, ";") {
			continue
		}
		if k, _, ok := strings.Cut(t, "="); ok && strings.TrimSpace(k) == key {
			if done {
				ls[i] = "# (replaced by server-hardening) " + t
			} else {
				ls[i] = line
				done = true
			}
		}
	}
	switch {
	case done:
	case found:
		ls = append(ls[:lastInSection+1], append([]string{line}, ls[lastInSection+1:]...)...)
	default:
		if len(ls) > 0 {
			ls = append(ls, "")
		}
		ls = append(ls, "["+section+"]", line)
	}
	return strings.Join(ls, "\n") + "\n"
}

// GetINI reads the last active "key = value" inside [section] of an INI-style text.
func GetINI(content, section, key string) (string, bool) {
	in, val, ok := false, "", false
	for l := range strings.SplitSeq(content, "\n") {
		t := strings.TrimSpace(l)
		if strings.HasPrefix(t, "[") && strings.HasSuffix(t, "]") {
			in = strings.TrimSpace(t[1:len(t)-1]) == section
			continue
		}
		if !in || t == "" || strings.HasPrefix(t, "#") || strings.HasPrefix(t, ";") {
			continue
		}
		if k, v, has := strings.Cut(t, "="); has && strings.TrimSpace(k) == key {
			val, ok = strings.TrimSpace(v), true
		}
	}
	return val, ok
}
