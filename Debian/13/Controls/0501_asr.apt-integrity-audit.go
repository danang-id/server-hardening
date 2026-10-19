// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Danang Galuh Tegar Prasetyo

package controls

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/danang-id/server-hardening/internal/control"
	"github.com/danang-id/server-hardening/internal/files"
)

const aptAuditID = "asr.apt-integrity-audit"

type aptIntegrityAudit struct{ control.Base }

func init() {
	System.Add(&aptIntegrityAudit{control.Base{M: control.Meta{
		ID:       aptAuditID,
		Category: control.ASR,
		Number:   1,
		Title:    "Audit the trust of package sources",
		Default:  true,
		Tags:     []control.Tag{control.TagReadonly},
	}}})
}

var (
	insecureOption = regexp.MustCompile(`(?im)^\s*Acquire::(AllowInsecureRepositories|AllowDowngradeToInsecureRepositories|AllowUnauthenticated)\b[^;\n]*"?\s*(true|1|yes)`)
	trustedYes     = regexp.MustCompile(`(?i)\btrusted\s*=\s*yes\b`)
	trustedField   = regexp.MustCompile(`(?im)^\s*Trusted:\s*yes\b`)
	debLine        = regexp.MustCompile(`^\s*deb(-src)?\s+(?:\[[^\]]*\]\s+)?(\S+)`)
	uriField       = regexp.MustCompile(`(?im)^\s*URIs:\s*(.+)$`)
	debianHost     = regexp.MustCompile(`^https?://([a-z0-9.-]*\.)?(debian\.org|debian\.net)(/|$)`)
)

// auditAPT reads the package source files and the apt configuration and lists
// what looks unsafe or unusual. It reads files only.
func auditAPT(env *control.Env) ([]string, error) {
	var findings []string
	add := func(f string, a ...any) { findings = append(findings, fmt.Sprintf(f, a...)) }

	glob := func(pat string) []string {
		m, _ := filepath.Glob(env.Path(pat))
		return m
	}
	rel := func(p string) string { r, _ := filepath.Rel(env.Root, p); return "/" + filepath.ToSlash(r) }

	// Package sources, in the one-line and the deb822 format.
	check := func(path, uri string) {
		uri = strings.TrimSpace(uri)
		switch {
		case strings.HasPrefix(uri, "http://"):
			add("%s fetches packages over plain HTTP: %s", rel(path), uri)
		}
		if !debianHost.MatchString(uri) && !strings.HasPrefix(uri, "file:") && !strings.HasPrefix(uri, "cdrom:") {
			add("%s uses a repository that is not Debian's: %s", rel(path), uri)
		}
	}
	sources := append(glob("/etc/apt/sources.list"), glob("/etc/apt/sources.list.d/*.list")...)
	for _, p := range sources {
		b, err := os.ReadFile(p)
		if err != nil {
			return nil, err
		}
		for l := range strings.SplitSeq(string(b), "\n") {
			if m := debLine.FindStringSubmatch(l); m != nil {
				check(p, m[2])
				if trustedYes.MatchString(l) {
					add("%s marks a source as trusted without a signature: %s", rel(p), strings.TrimSpace(l))
				}
			}
		}
	}
	for _, p := range glob("/etc/apt/sources.list.d/*.sources") {
		b, err := os.ReadFile(p)
		if err != nil {
			return nil, err
		}
		for _, m := range uriField.FindAllStringSubmatch(string(b), -1) {
			for _, u := range strings.Fields(m[1]) {
				check(p, u)
			}
		}
		if trustedField.Match(b) {
			add("%s marks a source as trusted without a signature (Trusted: yes)", rel(p))
		}
	}

	// Options that switch signature checks off.
	for _, p := range append(glob("/etc/apt/apt.conf"), glob("/etc/apt/apt.conf.d/*")...) {
		b, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		if m := insecureOption.FindStringSubmatch(string(b)); m != nil {
			add("%s allows insecure downloads (%s)", rel(p), m[1])
		}
	}

	// Keys that every repository trusts.
	if fi, err := os.Stat(env.Path("/etc/apt/trusted.gpg")); err == nil && fi.Size() > 0 {
		add("/etc/apt/trusted.gpg holds keys that are trusted for every repository. Move them to /etc/apt/keyrings and name them in the source with Signed-By")
	}
	for _, p := range glob("/etc/apt/trusted.gpg.d/*") {
		if n := filepath.Base(p); !strings.HasPrefix(n, "debian-archive-") && !strings.HasPrefix(n, "debian-ports-archive-") {
			add("%s is a key trusted for every repository. Tie it to one repository with Signed-By", rel(p))
		}
	}
	return findings, nil
}

func (a *aptIntegrityAudit) Check(_ context.Context, env *control.Env) (control.State, error) {
	f, err := auditAPT(env)
	if err != nil {
		return control.NotApplied, err
	}
	if len(f) > 0 {
		return control.Partial, nil
	}
	if !files.Exists(env.Path("/etc/apt")) {
		return control.NotApplied, nil
	}
	return control.Applied, nil
}

func (a *aptIntegrityAudit) Apply(_ context.Context, env *control.Env, _ control.Values) error {
	f, err := auditAPT(env)
	if err != nil {
		return err
	}
	if len(f) == 0 {
		env.Log.Infof("package sources look safe: signed, over a trusted connection, and from Debian")
		return nil
	}
	for _, x := range f {
		env.Log.Warnf("%s", x)
	}
	env.Log.Infof("%d finding(s). This control changes nothing: review the sources yourself", len(f))
	return nil
}

func (a *aptIntegrityAudit) Revert(context.Context, *control.Env) error { return control.ErrNoRevert }
