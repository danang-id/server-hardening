// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Danang Galuh Tegar Prasetyo

package controls

import (
	"context"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/danang-id/server-hardening/internal/control"
)

const rpmVerifyID = "asr.rpm-verify-baseline"

type rpmVerifyBaseline struct{ control.Base }

func init() {
	System.Add(&rpmVerifyBaseline{control.Base{M: control.Meta{
		ID:       rpmVerifyID,
		Category: control.ASR,
		Number:   3,
		Title:    "Check installed files against package checksums",
		Default:  true,
		Tags:     []control.Tag{control.TagReadonly},
	}}})
}

// verifyLine is one line of "rpm -Va": nine flags (or the word "missing"),
// an optional kind of file (c config, d documentation, g ghost, l license,
// r readme), and the path.
var verifyLine = regexp.MustCompile(`^(missing|[.A-Za-z0-9?]{9})\s+(?:([cdglr])\s+)?(/.*)$`)

// leftOutPrefixes are the places where images and containers commonly leave
// package files out on purpose (the "nodocs" and "tsflags" settings of dnf):
// documentation and translations. A missing file there is not a finding.
var leftOutPrefixes = []string{
	"/usr/share/man/", "/usr/share/doc/", "/usr/share/info/",
	"/usr/share/locale/", "/usr/share/licenses/",
}

func leftOut(path string) bool {
	for _, p := range leftOutPrefixes {
		if strings.HasPrefix(path, p) {
			return true
		}
	}
	return false
}

// changedFiles runs rpm -Va and returns the files whose content differs from
// their package or that are gone, sorted. Three kinds are not returned:
// configuration files (people change them), ghost files (the package does not
// own their content), and documentation that the system leaves out. The
// last kind is counted in absent.
//
// rpm exits with an error when it finds a difference, so the output counts
// even when the command reports failure.
func changedFiles(ctx context.Context, env *control.Env) (found []string, absent int, err error) {
	out, runErr := env.Run.Run(ctx, "rpm", "-Va", "--nomtime")
	seen := 0
	for l := range strings.SplitSeq(string(out), "\n") {
		m := verifyLine.FindStringSubmatch(strings.TrimRight(l, " \t\r"))
		if m == nil {
			continue
		}
		seen++
		flags, kind, path := m[1], m[2], m[3]
		switch {
		case kind == "c" || kind == "g":
			continue
		case flags == "missing" && (kind != "" || leftOut(path)):
			absent++
		case flags == "missing":
			found = append(found, path)
		case strings.Contains(flags, "5"):
			found = append(found, path) // the content (digest) differs
		}
	}
	if runErr != nil && seen == 0 {
		return nil, 0, fmt.Errorf("rpm -Va failed: %w: %s", runErr, strings.TrimSpace(string(out)))
	}
	sort.Strings(found)
	return found, absent, nil
}

func (d *rpmVerifyBaseline) Check(_ context.Context, env *control.Env) (control.State, error) {
	if !env.Rec.Has(rpmVerifyID) {
		return control.NotApplied, nil
	}
	if v, _, _ := env.Rec.Get(rpmVerifyID, "changed"); strings.TrimSpace(v) != "" {
		return control.Partial, nil
	}
	return control.Applied, nil
}

func (d *rpmVerifyBaseline) Apply(ctx context.Context, env *control.Env, _ control.Values) error {
	now, absent, err := changedFiles(ctx, env)
	if err != nil {
		return err
	}
	if absent > 0 {
		env.Log.Infof("%d documentation or optional files that packages list are not installed on this system. They are not counted", absent)
	}
	prev, had, _ := env.Rec.Get(rpmVerifyID, "changed")
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
	return env.Rec.Put(rpmVerifyID, "changed", strings.Join(now, "\n"))
}

func (d *rpmVerifyBaseline) Revert(context.Context, *control.Env) error { return control.ErrNoRevert }
