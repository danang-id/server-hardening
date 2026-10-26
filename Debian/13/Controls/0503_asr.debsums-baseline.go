// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Danang Galuh Tegar Prasetyo

package controls

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/danang-id/server-hardening/internal/apt"
	"github.com/danang-id/server-hardening/internal/control"
)

const debsumsID = "asr.debsums-baseline"

type debsumsBaseline struct{ control.Base }

func init() {
	System.Add(&debsumsBaseline{control.Base{M: control.Meta{
		ID:       debsumsID,
		Category: control.ASR,
		Number:   3,
		Title:    "Check installed files against package checksums",
		Default:  true,
		Tags:     []control.Tag{control.TagReadonly},
	}}})
}

// debsumsMissing starts the line that debsums prints for a file that its
// package lists but that is not on the disk.
const debsumsMissing = "debsums: missing file "

// leftOutPrefixes are the places where images and containers commonly leave
// package files out on purpose (dpkg path-exclude): documentation and
// translations. A missing file there is not a finding.
var leftOutPrefixes = []string{
	"/usr/share/man/", "/usr/share/doc/", "/usr/share/info/",
	"/usr/share/locale/", "/usr/share/lintian/",
}

func leftOut(path string) bool {
	for _, p := range leftOutPrefixes {
		if strings.HasPrefix(path, p) {
			return true
		}
	}
	return false
}

// changedFiles runs debsums and returns the files that differ from their
// package or that are missing, sorted. Files that are missing only because the
// system leaves out documentation are not returned: absent counts them.
//
// debsums exits with an error when it finds a difference or a missing file, so
// the output counts even when the command reports failure.
func changedFiles(ctx context.Context, env *control.Env) (files []string, absent int, err error) {
	out, runErr := env.Run.Run(ctx, "debsums", "-c")
	for l := range strings.SplitSeq(string(out), "\n") {
		l = strings.TrimSpace(l)
		switch {
		case strings.HasPrefix(l, "/"):
			files = append(files, l)
		case strings.HasPrefix(l, debsumsMissing):
			path, _, _ := strings.Cut(strings.TrimPrefix(l, debsumsMissing), " ")
			if leftOut(path) {
				absent++
			} else {
				files = append(files, path)
			}
		}
	}
	if runErr != nil && len(files) == 0 && absent == 0 {
		return nil, 0, fmt.Errorf("debsums failed: %w: %s", runErr, strings.TrimSpace(string(out)))
	}
	sort.Strings(files)
	return files, absent, nil
}

func (d *debsumsBaseline) Check(_ context.Context, env *control.Env) (control.State, error) {
	if !env.Rec.Has(debsumsID) {
		return control.NotApplied, nil
	}
	if v, _, _ := env.Rec.Get(debsumsID, "changed"); strings.TrimSpace(v) != "" {
		return control.Partial, nil
	}
	return control.Applied, nil
}

func (d *debsumsBaseline) Apply(ctx context.Context, env *control.Env, _ control.Values) error {
	if err := apt.Install(ctx, env, "debsums"); err != nil {
		return err
	}
	now, absent, err := changedFiles(ctx, env)
	if err != nil {
		return err
	}
	if absent > 0 {
		env.Log.Infof("%d documentation files that packages list are not installed on this system. They are not counted", absent)
	}
	prev, had, _ := env.Rec.Get(debsumsID, "changed")
	before := map[string]bool{}
	for _, f := range strings.Fields(prev) {
		before[f] = true
	}
	var fresh []string
	for _, f := range now {
		if !before[f] {
			fresh = append(fresh, f)
		}
	}
	switch {
	case len(now) == 0:
		env.Log.Infof("every checked file matches its package")
	case had:
		env.Log.Warnf("%d file(s) differ from their package, %d of them new since the last baseline:", len(now), len(fresh))
	default:
		env.Log.Warnf("%d file(s) differ from their package:", len(now))
	}
	show := now
	if had {
		show = fresh
	}
	for _, f := range show {
		env.Log.Warnf("  %s", f)
	}
	return env.Rec.Put(debsumsID, "changed", strings.Join(now, "\n"))
}

func (d *debsumsBaseline) Revert(context.Context, *control.Env) error { return control.ErrNoRevert }
