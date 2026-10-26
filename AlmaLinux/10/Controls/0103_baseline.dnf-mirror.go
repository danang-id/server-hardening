// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Danang Galuh Tegar Prasetyo

package controls

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/danang-id/server-hardening/internal/control"
	"github.com/danang-id/server-hardening/internal/dnf"
	"github.com/danang-id/server-hardening/internal/files"
	"github.com/danang-id/server-hardening/internal/kit"
)

const (
	mirrorID      = "baseline.dnf-mirror"
	repoDir       = "/etc/yum.repos.d/"
	almaRepoGlob  = "almalinux*.repo"
	defaultMirror = "https://repo.almalinux.org/almalinux"
)

// almaRepos maps the id of an AlmaLinux repository to its folder on a mirror.
// A repository that is not in the list is left alone.
var almaRepos = map[string]string{
	"baseos":           "BaseOS",
	"appstream":        "AppStream",
	"crb":              "CRB",
	"extras":           "extras",
	"plus":             "plus",
	"devel":            "devel",
	"highavailability": "HighAvailability",
	"resilientstorage": "ResilientStorage",
	"nfv":              "NFV",
	"rt":               "RT",
	"sap":              "SAP",
	"saphana":          "SAPHANA",
}

type dnfMirror struct{ control.Base }

func init() {
	System.Add(&dnfMirror{control.Base{M: control.Meta{
		ID:           mirrorID,
		Category:     control.Baseline,
		Number:       3,
		Title:        "Configure the AlmaLinux package mirror",
		Tags:         []control.Tag{control.TagInput},
		RevertLimits: "Packages that were installed from the mirror stay installed.",
	}}})
}

func validMirror(s string) error {
	if !strings.HasPrefix(s, "https://") || strings.ContainsAny(s, " \t\n$") {
		return fmt.Errorf("enter an https:// address without spaces")
	}
	return nil
}

func (a *dnfMirror) Inputs(context.Context, *control.Env) ([]control.Input, error) {
	return []control.Input{{
		Key:   "mirror",
		Label: "Mirror base URL",
		Help: "The folder that holds the AlmaLinux release folders (10/BaseOS and so on). " +
			"It replaces the mirror list, so every download comes from here over HTTPS. " +
			"Packages stay verified against the AlmaLinux signing key.",
		Default:  defaultMirror,
		Validate: validMirror,
	}}, nil
}

// repoFiles lists the AlmaLinux repository files on this server.
func repoFiles(env *control.Env) ([]string, error) {
	m, err := filepath.Glob(env.Path(repoDir + almaRepoGlob))
	if err != nil {
		return nil, err
	}
	var out []string
	for _, f := range m {
		out = append(out, repoDir+filepath.Base(f))
	}
	return out, nil
}

// pointAtMirror rewrites one repository file: in each known section the
// mirror list and the base URL are commented out and a base URL for the chosen
// mirror is added. The text of other sections is kept. It reports whether
// anything changed.
func pointAtMirror(content, mirror string) (string, bool) {
	var out []string
	changed := false
	section := ""
	dir := ""
	for l := range strings.SplitSeq(strings.TrimSuffix(content, "\n"), "\n") {
		t := strings.TrimSpace(l)
		if strings.HasPrefix(t, "[") && strings.HasSuffix(t, "]") {
			section = strings.Trim(t, "[]")
			dir = almaRepos[section]
			out = append(out, l)
			if dir != "" {
				out = append(out, "baseurl="+strings.TrimRight(mirror, "/")+"/$releasever/"+dir+"/$basearch/os/")
				changed = true
			}
			continue
		}
		if dir != "" {
			key, _, _ := strings.Cut(t, "=")
			switch strings.TrimSpace(key) {
			case "mirrorlist", "metalink", "baseurl":
				out = append(out, "# retired by server-hardening: "+l)
				continue
			}
		}
		out = append(out, l)
	}
	if !changed {
		return content, false
	}
	return kit.Marker(mirrorID) + "\n" + strings.Join(out, "\n") + "\n", true
}

func (a *dnfMirror) Check(_ context.Context, env *control.Env) (control.State, error) {
	if _, ok, err := env.Rec.Get(mirrorID, "applied"); err != nil || !ok {
		return control.NotApplied, err
	}
	fs, err := repoFiles(env)
	if err != nil {
		return control.NotApplied, err
	}
	n := 0
	for _, f := range fs {
		if kit.HasMarker(env, f, mirrorID) {
			n++
		}
	}
	switch {
	case n == 0:
		return control.NotApplied, nil
	case n < len(fs):
		return control.Partial, nil
	}
	return control.Applied, nil
}

func (a *dnfMirror) Apply(ctx context.Context, env *control.Env, in control.Values) error {
	mirror := in.String("mirror")
	if err := validMirror(mirror); err != nil {
		return err
	}
	fs, err := repoFiles(env)
	if err != nil {
		return err
	}
	if len(fs) == 0 {
		return fmt.Errorf("found no AlmaLinux repository file in %s", repoDir)
	}
	var changedFiles []string
	for _, f := range fs {
		b, err := files.ReadOptional(env.Path(f))
		if err != nil {
			return err
		}
		if kit.HasMarker(env, f, mirrorID) {
			// Already ours: work from what the file was before.
			if _, err := env.Rec.Restore(mirrorID, env.Path(f)); err != nil {
				return err
			}
			if b, err = files.ReadOptional(env.Path(f)); err != nil {
				return err
			}
		}
		next, changed := pointAtMirror(string(b), mirror)
		if !changed {
			continue
		}
		if err := env.Rec.Backup(mirrorID, env.Path(f)); err != nil {
			return err
		}
		if err := files.WriteAtomic(env.Path(f), []byte(next), 0o644); err != nil {
			return err
		}
		changedFiles = append(changedFiles, f)
	}
	if len(changedFiles) == 0 {
		return fmt.Errorf("none of the repository files has a repository this control knows")
	}
	if err := env.Rec.Put(mirrorID, "files", strings.Join(changedFiles, "\n")); err != nil {
		return err
	}
	if err := dnf.CleanAll(ctx, env); err != nil {
		_ = a.restore(env)
		return err
	}
	if err := dnf.MakeCache(ctx, env); err != nil {
		env.Log.Warnf("the package metadata could not be read from %s, putting the previous repository files back", mirror)
		_ = a.restore(env)
		_ = dnf.CleanAll(ctx, env)
		return err
	}
	env.Log.Infof("AlmaLinux packages come from %s", mirror)
	return env.Rec.Put(mirrorID, "applied", mirror)
}

func (a *dnfMirror) restore(env *control.Env) error {
	v, _, err := env.Rec.Get(mirrorID, "files")
	if err != nil {
		return err
	}
	for _, f := range kit.Lines(v) {
		if _, err := env.Rec.Restore(mirrorID, env.Path(f)); err != nil {
			return err
		}
	}
	return nil
}

func (a *dnfMirror) Revert(ctx context.Context, env *control.Env) error {
	if !env.Rec.Has(mirrorID) {
		env.Log.Warnf("%s: no record of the previous repository files, leaving them alone", mirrorID)
		return nil
	}
	if err := a.restore(env); err != nil {
		return err
	}
	if err := dnf.CleanAll(ctx, env); err != nil {
		return err
	}
	return env.Rec.Delete(mirrorID)
}
