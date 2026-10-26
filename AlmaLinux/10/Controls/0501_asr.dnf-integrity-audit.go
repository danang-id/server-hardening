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

const dnfAuditID = "asr.dnf-integrity-audit"

type dnfIntegrityAudit struct{ control.Base }

func init() {
	System.Add(&dnfIntegrityAudit{control.Base{M: control.Meta{
		ID:       dnfAuditID,
		Category: control.ASR,
		Number:   1,
		Title:    "Audit the trust of package sources",
		Default:  true,
		Tags:     []control.Tag{control.TagReadonly},
	}}})
}

var (
	repoURL = regexp.MustCompile(`(?i)\b(https?|ftp)://([^/\s$]+)\S*`)
	// Hosts of the distribution and of its extra packages (EPEL).
	trustedHost = regexp.MustCompile(`(?i)(^|\.)(almalinux\.org|fedoraproject\.org)$`)
)

func isOff(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "0", "false", "no":
		return true
	}
	return false
}

// repoSection is one [section] of a .repo file, with its active settings.
type repoSection struct {
	id   string
	set  map[string]string
	urls []string // every address named in the section, except key addresses
	keys []string // the addresses of the signing keys
}

// readRepos reads the sections of a .repo file or of dnf.conf.
func readRepos(content string) []repoSection {
	var out []repoSection
	var cur *repoSection
	lastKey := ""
	for l := range strings.SplitSeq(content, "\n") {
		t := strings.TrimSpace(l)
		switch {
		case t == "" || strings.HasPrefix(t, "#") || strings.HasPrefix(t, ";"):
			continue
		case strings.HasPrefix(t, "[") && strings.HasSuffix(t, "]"):
			out = append(out, repoSection{id: t[1 : len(t)-1], set: map[string]string{}})
			cur = &out[len(out)-1]
			lastKey = ""
			continue
		case cur == nil:
			continue
		}
		key, val, ok := strings.Cut(t, "=")
		if ok && !strings.ContainsAny(strings.TrimSpace(key), " \t") {
			lastKey = strings.ToLower(strings.TrimSpace(key))
			cur.set[lastKey] = strings.TrimSpace(val)
			t = val
		} else if lastKey == "" || (l[0] != ' ' && l[0] != '\t') {
			continue // a line that continues no list
		}
		for _, m := range repoURL.FindAllString(t, -1) {
			if lastKey == "gpgkey" {
				cur.keys = append(cur.keys, m)
			} else {
				cur.urls = append(cur.urls, m)
			}
		}
	}
	return out
}

// auditDNF reads the dnf configuration and the repository files and lists what
// looks unsafe or unusual. It reads files only.
func auditDNF(env *control.Env) ([]string, error) {
	var findings []string
	add := func(f string, a ...any) { findings = append(findings, fmt.Sprintf(f, a...)) }

	mainConf, err := files.ReadOptional(env.Path("/etc/dnf/dnf.conf"))
	if err != nil {
		return nil, err
	}
	mainSet := map[string]string{}
	for _, s := range readRepos(string(mainConf)) {
		if s.id == "main" {
			mainSet = s.set
		}
	}
	if isOff(mainSet["gpgcheck"]) {
		add("/etc/dnf/dnf.conf switches signature checks off for every repository (gpgcheck=0)")
	}
	if isOff(mainSet["sslverify"]) {
		add("/etc/dnf/dnf.conf switches the check of server certificates off for every repository (sslverify=0)")
	}

	paths, _ := filepath.Glob(env.Path("/etc/yum.repos.d/*.repo"))
	for _, p := range paths {
		b, err := os.ReadFile(p)
		if err != nil {
			return nil, err
		}
		rel, _ := filepath.Rel(env.Root, p)
		rel = "/" + filepath.ToSlash(rel)
		for _, s := range readRepos(string(b)) {
			if v, ok := s.set["enabled"]; ok && isOff(v) {
				continue
			}
			gpg, ok := s.set["gpgcheck"]
			if !ok {
				gpg = mainSet["gpgcheck"]
			}
			if isOff(gpg) {
				add("%s: the repository %s does not check package signatures (gpgcheck=0)", rel, s.id)
			}
			if isOff(s.set["sslverify"]) {
				add("%s: the repository %s does not check the server certificate (sslverify=0)", rel, s.id)
			}
			seen := map[string]bool{}
			for _, u := range s.urls {
				m := repoURL.FindStringSubmatch(u)
				if seen[u] {
					continue
				}
				seen[u] = true
				if strings.EqualFold(m[1], "http") || strings.EqualFold(m[1], "ftp") {
					add("%s: the repository %s fetches over an unencrypted connection: %s", rel, s.id, u)
				}
				if !trustedHost.MatchString(m[2]) {
					add("%s: the repository %s is not AlmaLinux's or EPEL's: %s", rel, s.id, u)
				}
			}
			for _, k := range s.keys {
				if !strings.HasPrefix(strings.ToLower(k), "https://") {
					add("%s: the signing key of %s is fetched over an unencrypted connection: %s", rel, s.id, k)
				}
			}
		}
	}
	return findings, nil
}

func (a *dnfIntegrityAudit) Check(_ context.Context, env *control.Env) (control.State, error) {
	f, err := auditDNF(env)
	if err != nil {
		return control.NotApplied, err
	}
	if len(f) > 0 {
		return control.Partial, nil
	}
	if !files.Exists(env.Path("/etc/yum.repos.d")) {
		return control.NotApplied, nil
	}
	return control.Applied, nil
}

func (a *dnfIntegrityAudit) Apply(_ context.Context, env *control.Env, _ control.Values) error {
	f, err := auditDNF(env)
	if err != nil {
		return err
	}
	if len(f) == 0 {
		env.Log.Infof("package sources look safe: signed, over an encrypted connection, and from AlmaLinux or EPEL")
		return nil
	}
	for _, x := range f {
		env.Log.Warnf("%s", x)
	}
	env.Log.Infof("%d finding(s). This control changes nothing: review the sources yourself", len(f))
	return nil
}

func (a *dnfIntegrityAudit) Revert(context.Context, *control.Env) error { return control.ErrNoRevert }
