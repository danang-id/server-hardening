// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Danang Galuh Tegar Prasetyo

package controls

import (
	"context"
	"fmt"
	"strings"

	"github.com/danang-id/server-hardening/internal/apt"
	"github.com/danang-id/server-hardening/internal/control"
	"github.com/danang-id/server-hardening/internal/files"
	"github.com/danang-id/server-hardening/internal/sysdetect"
)

const (
	mirrorID      = "baseline.apt-mirror"
	sourcesFile   = "/etc/apt/sources.list.d/debian.sources"
	legacySources = "/etc/apt/sources.list"
	mirrorMarker  = "# Managed by github.com/danang-id/server-hardening (baseline.apt-mirror)"
	keyring       = "/usr/share/keyrings/debian-archive-keyring.pgp"
	securityURL   = "https://deb.debian.org/debian-security"
)

var allComponents = []string{"main", "contrib", "non-free", "non-free-firmware"}

type aptMirror struct{ control.Base }

func init() {
	System.Add(&aptMirror{control.Base{M: control.Meta{
		ID:           mirrorID,
		Category:     control.Baseline,
		Number:       3,
		Title:        "Configure package sources (main contrib non-free, no deb-src)",
		Weight:       0,
		Tags:         []control.Tag{control.TagInput},
		RevertLimits: "Packages already installed from the added components stay installed.",
	}}})
}

func (a *aptMirror) Inputs(context.Context, *control.Env) ([]control.Input, error) {
	opts := make([]control.Option, len(allComponents))
	for i, c := range allComponents {
		opts[i] = control.Option{Value: c, Label: c}
	}
	return []control.Input{
		{
			Key:      "mirror",
			Label:    "Mirror URL",
			Help:     "Package updates are fetched over HTTPS from here",
			Default:  "https://deb.debian.org/debian",
			Validate: validMirror,
		},
		{
			Key:          "components",
			Label:        "Components",
			Help:         "main is required. non-free-firmware is a separate component.",
			Kind:         control.MultiChoice,
			Options:      opts,
			DefaultMulti: []string{"main", "contrib", "non-free"},
		},
	}, nil
}

func validMirror(s string) error {
	if !strings.HasPrefix(s, "https://") || strings.ContainsAny(s, " \t\n") {
		return fmt.Errorf("enter an https:// address without spaces")
	}
	return nil
}

func codename(env *control.Env) string {
	b, err := files.ReadOptional(env.Path("/etc/os-release"))
	if err == nil {
		if c := sysdetect.ParseOSRelease(strings.NewReader(string(b)))["VERSION_CODENAME"]; c != "" {
			return c
		}
	}
	return "trixie"
}

// sourcesContent renders the deb822 file: the chosen mirror for the release
// and its updates, and the security archive.
func sourcesContent(mirror, suite string, comps []string) string {
	c := strings.Join(comps, " ")
	return fmt.Sprintf(`%s
Types: deb
URIs: %s
Suites: %s %s-updates
Components: %s
Signed-By: %s

Types: deb
URIs: %s
Suites: %s-security
Components: %s
Signed-By: %s
`, mirrorMarker, strings.TrimRight(mirror, "/"), suite, suite, c, keyring, securityURL, suite, c, keyring)
}

func orderedComponents(chosen []string) ([]string, error) {
	have := map[string]bool{}
	for _, c := range chosen {
		have[c] = true
	}
	if !have["main"] {
		return nil, fmt.Errorf("the main component is required")
	}
	var out []string
	for _, c := range allComponents {
		if have[c] {
			out = append(out, c)
		}
	}
	return out, nil
}

func (a *aptMirror) Check(_ context.Context, env *control.Env) (control.State, error) {
	if _, ok, err := env.Rec.Get(mirrorID, "applied"); err != nil || !ok {
		return control.NotApplied, err
	}
	b, err := files.ReadOptional(env.Path(sourcesFile))
	if err != nil {
		return control.NotApplied, err
	}
	if strings.Contains(string(b), mirrorMarker) {
		return control.Applied, nil
	}
	return control.NotApplied, nil
}

func (a *aptMirror) Apply(ctx context.Context, env *control.Env, in control.Values) error {
	mirror := in.String("mirror")
	if err := validMirror(mirror); err != nil {
		return err
	}
	comps, err := orderedComponents(in.List("components"))
	if err != nil {
		return err
	}
	if err := apt.Install(ctx, env, "ca-certificates"); err != nil {
		return err
	}

	for _, p := range []string{sourcesFile, legacySources} {
		if err := env.Rec.Backup(mirrorID, env.Path(p)); err != nil {
			return err
		}
	}
	content := sourcesContent(mirror, codename(env), comps)
	if err := files.WriteAtomic(env.Path(sourcesFile), []byte(content), 0o644); err != nil {
		return err
	}
	// Retire legacy one-line entries so no source is listed twice.
	if b, err := files.ReadOptional(env.Path(legacySources)); err != nil {
		return err
	} else if retired, changed := retireLegacy(string(b)); changed {
		if err := files.WriteAtomic(env.Path(legacySources), []byte(retired), 0o644); err != nil {
			return err
		}
	}

	if err := apt.Update(ctx, env); err != nil {
		env.Log.Warnf("package list update failed, putting the previous sources back")
		_ = a.restore(env)
		return err
	}
	env.Log.Infof("package sources use %s (%s)", mirror, strings.Join(comps, " "))
	return env.Rec.Put(mirrorID, "applied", mirror)
}

func (a *aptMirror) restore(env *control.Env) error {
	for _, p := range []string{sourcesFile, legacySources} {
		if _, err := env.Rec.Restore(mirrorID, env.Path(p)); err != nil {
			return err
		}
	}
	return nil
}

func (a *aptMirror) Revert(ctx context.Context, env *control.Env) error {
	if !env.Rec.Has(mirrorID) {
		env.Log.Warnf("%s: no record of the previous sources, leaving them alone", mirrorID)
		return nil
	}
	if err := a.restore(env); err != nil {
		return err
	}
	if err := apt.Update(ctx, env); err != nil {
		return err
	}
	return env.Rec.Delete(mirrorID)
}

// retireLegacy comments out active lines of the old sources.list.
func retireLegacy(s string) (string, bool) {
	changed := false
	lines := strings.Split(s, "\n")
	for i, l := range lines {
		t := strings.TrimSpace(l)
		if t != "" && !strings.HasPrefix(t, "#") {
			lines[i] = "# retired by server-hardening: " + l
			changed = true
		}
	}
	return strings.Join(lines, "\n"), changed
}
