// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Danang Galuh Tegar Prasetyo

// Package mounts reads and changes mount options and /etc/fstab the same way
// for every system.
package mounts

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/danang-id/server-hardening/internal/control"
	"github.com/danang-id/server-hardening/internal/files"
	"github.com/danang-id/server-hardening/internal/kit"
)

// Helpers for the controls that change mount options.

// Options returns the options a mount point has now, as a set, and as raw text.
// A directory that is not a mount point (/tmp on AlmaLinux) gives the options of
// the file system it lives on.
func Options(ctx context.Context, env *control.Env, mnt string) (map[string]bool, string, error) {
	out, err := env.Run.Run(ctx, "findmnt", "-n", "-o", "OPTIONS", "-T", mnt)
	if err != nil {
		return nil, "", fmt.Errorf("cannot read the mount options of %s: %w", mnt, err)
	}
	Raw := strings.TrimSpace(string(out))
	set := map[string]bool{}
	for o := range strings.SplitSeq(Raw, ",") {
		set[o] = true
	}
	return set, Raw, nil
}

// Flags reports which of nosuid, nodev and noexec a mount point has.
func Flags(set map[string]bool) (nosuid, nodev, noexec bool) {
	return set["nosuid"], set["nodev"], set["noexec"]
}

// Remount remounts a mount point with the three flags on or off.
func Remount(ctx context.Context, env *control.Env, mnt string, nosuid, nodev, noexec bool) error {
	pick := func(on bool, yes, no string) string {
		if on {
			return yes
		}
		return no
	}
	opts := "remount," + pick(nosuid, "nosuid", "suid") + "," + pick(nodev, "nodev", "dev") + "," + pick(noexec, "noexec", "exec")
	if out, err := env.Run.Run(ctx, "mount", "-o", opts, mnt); err != nil {
		return fmt.Errorf("cannot remount %s: %w: %s", mnt, err, strings.TrimSpace(string(out)))
	}
	return nil
}

// FstabLine is one entry of /etc/fstab.
type FstabLine struct {
	Raw    string
	Fields []string
}

// ParseFstab splits /etc/fstab into lines and fields.
func ParseFstab(content string) []FstabLine {
	var out []FstabLine
	for l := range strings.SplitSeq(strings.TrimSuffix(content, "\n"), "\n") {
		t := strings.TrimSpace(l)
		if t == "" || strings.HasPrefix(t, "#") {
			out = append(out, FstabLine{Raw: l})
			continue
		}
		out = append(out, FstabLine{Raw: l, Fields: strings.Fields(t)})
	}
	return out
}

// RenderFstab writes the lines back.
func RenderFstab(lines []FstabLine) string {
	var b strings.Builder
	for _, l := range lines {
		b.WriteString(l.Raw)
		b.WriteString("\n")
	}
	return b.String()
}

// FstabHas finds the entry for a mount point.
func FstabHas(content, mnt string) (FstabLine, bool) {
	for _, l := range ParseFstab(content) {
		if len(l.Fields) >= 2 && l.Fields[1] == mnt {
			return l, true
		}
	}
	return FstabLine{}, false
}

// FstabSet replaces the entry of a mount point, or adds one at the end. The
// entry is preceded by a comment line with the marker of the control.
func FstabSet(content, mnt, id, entry string) string {
	lines := ParseFstab(content)
	var out []FstabLine
	done := false
	for i, l := range lines {
		if len(l.Fields) >= 2 && l.Fields[1] == mnt {
			if done {
				continue // a second entry for the same mount point
			}
			if i == 0 || !strings.Contains(lines[i-1].Raw, kit.Marker(id)) {
				out = append(out, FstabLine{Raw: kit.Marker(id)})
			}
			out = append(out, FstabLine{Raw: entry, Fields: strings.Fields(entry)})
			done = true
			continue
		}
		out = append(out, l)
	}
	if !done {
		out = append(out, FstabLine{Raw: kit.Marker(id)}, FstabLine{Raw: entry, Fields: strings.Fields(entry)})
	}
	return RenderFstab(out)
}

// ReadFstab reads /etc/fstab. A missing file gives an empty text.
func ReadFstab(env *control.Env) (string, error) {
	b, err := files.ReadOptional(env.Path("/etc/fstab"))
	return string(b), err
}

// SizeValue is a size such as 1G or 20%.
var SizeValue = regexp.MustCompile(`^[1-9][0-9]{0,6}(%|[KMGkmg])?$`)
