// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Danang Galuh Tegar Prasetyo

package controls

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/danang-id/server-hardening/internal/control"
	"github.com/danang-id/server-hardening/internal/files"
)

// Helpers for the controls that change mount options.

// mountOptions returns the options a mount point has now, as a set.
func mountOptions(ctx context.Context, env *control.Env, mnt string) (map[string]bool, string, error) {
	out, err := env.Run.Run(ctx, "findmnt", "-n", "-o", "OPTIONS", mnt)
	if err != nil {
		return nil, "", fmt.Errorf("cannot read the mount options of %s: %w", mnt, err)
	}
	raw := strings.TrimSpace(string(out))
	set := map[string]bool{}
	for o := range strings.SplitSeq(raw, ",") {
		set[o] = true
	}
	return set, raw, nil
}

// flagsOf reports which of nosuid, nodev and noexec a mount point has.
func flagsOf(set map[string]bool) (nosuid, nodev, noexec bool) {
	return set["nosuid"], set["nodev"], set["noexec"]
}

// remountFlags remounts a mount point with the three flags on or off.
func remountFlags(ctx context.Context, env *control.Env, mnt string, nosuid, nodev, noexec bool) error {
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

// fstabLine is one entry of /etc/fstab.
type fstabLine struct {
	raw    string
	fields []string
}

func parseFstab(content string) []fstabLine {
	var out []fstabLine
	for l := range strings.SplitSeq(strings.TrimSuffix(content, "\n"), "\n") {
		t := strings.TrimSpace(l)
		if t == "" || strings.HasPrefix(t, "#") {
			out = append(out, fstabLine{raw: l})
			continue
		}
		out = append(out, fstabLine{raw: l, fields: strings.Fields(t)})
	}
	return out
}

func renderFstab(lines []fstabLine) string {
	var b strings.Builder
	for _, l := range lines {
		b.WriteString(l.raw)
		b.WriteString("\n")
	}
	return b.String()
}

// fstabHas finds the entry for a mount point.
func fstabHas(content, mnt string) (fstabLine, bool) {
	for _, l := range parseFstab(content) {
		if len(l.fields) >= 2 && l.fields[1] == mnt {
			return l, true
		}
	}
	return fstabLine{}, false
}

// fstabSet replaces the entry of a mount point, or adds one at the end. The
// entry is preceded by a comment line with the marker of the control.
func fstabSet(content, mnt, id, entry string) string {
	lines := parseFstab(content)
	var out []fstabLine
	done := false
	for i, l := range lines {
		if len(l.fields) >= 2 && l.fields[1] == mnt {
			if done {
				continue // a second entry for the same mount point
			}
			if i == 0 || !strings.Contains(lines[i-1].raw, managed(id)) {
				out = append(out, fstabLine{raw: managed(id)})
			}
			out = append(out, fstabLine{raw: entry, fields: strings.Fields(entry)})
			done = true
			continue
		}
		out = append(out, l)
	}
	if !done {
		out = append(out, fstabLine{raw: managed(id)}, fstabLine{raw: entry, fields: strings.Fields(entry)})
	}
	return renderFstab(out)
}

func readFstab(env *control.Env) (string, error) {
	b, err := files.ReadOptional(env.Path("/etc/fstab"))
	return string(b), err
}

var sizeValue = regexp.MustCompile(`^[1-9][0-9]{0,6}(%|[KMGkmg])?$`)
