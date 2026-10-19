// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Danang Galuh Tegar Prasetyo

package controls

import (
	"context"
	"strings"
	"testing"

	"github.com/danang-id/server-hardening/internal/control"
)

func aptAuditControl() *aptIntegrityAudit {
	return &aptIntegrityAudit{control.Base{M: control.Meta{ID: aptAuditID}}}
}

func cleanAPT(t *testing.T) *control.Env {
	env, _ := testEnv(t)
	writeFile(t, env, "/etc/apt/sources.list", "# see /etc/apt/sources.list.d/\n")
	writeFile(t, env, "/etc/apt/sources.list.d/debian.sources",
		"Types: deb\nURIs: https://deb.debian.org/debian\nSuites: trixie\nComponents: main\nSigned-By: /usr/share/keyrings/debian-archive-keyring.pgp\n")
	writeFile(t, env, "/etc/apt/trusted.gpg.d/debian-archive-trixie-automatic.pgp", "k")
	return env
}

func TestAPTAuditCleanSystem(t *testing.T) {
	env := cleanAPT(t)
	f, err := auditAPT(env)
	must(t, err)
	if len(f) != 0 {
		t.Fatalf("unexpected findings: %v", f)
	}
	if state(t, aptAuditControl(), env) != control.Applied {
		t.Fatal("a clean system should be applied")
	}
	must(t, aptAuditControl().Apply(context.Background(), env, nil))
}

func TestAPTAuditFindings(t *testing.T) {
	env := cleanAPT(t)
	writeFile(t, env, "/etc/apt/sources.list", "deb http://deb.debian.org/debian trixie main\n")
	writeFile(t, env, "/etc/apt/sources.list.d/extra.list", "deb [trusted=yes] https://repo.example.com/apt stable main\n")
	writeFile(t, env, "/etc/apt/sources.list.d/other.sources", "Types: deb\nURIs: https://ppa.example.org/x\nTrusted: yes\n")
	writeFile(t, env, "/etc/apt/apt.conf.d/99insecure", "Acquire::AllowInsecureRepositories \"true\";\n")
	writeFile(t, env, "/etc/apt/trusted.gpg", "legacy key ring")
	writeFile(t, env, "/etc/apt/trusted.gpg.d/vendor.gpg", "k")
	f, err := auditAPT(env)
	must(t, err)
	all := strings.Join(f, "\n")
	wantContains(t, all,
		"/etc/apt/sources.list fetches packages over plain HTTP",
		"/etc/apt/sources.list.d/extra.list marks a source as trusted without a signature",
		"/etc/apt/sources.list.d/extra.list uses a repository that is not Debian's",
		"/etc/apt/sources.list.d/other.sources marks a source as trusted",
		"/etc/apt/apt.conf.d/99insecure allows insecure downloads",
		"/etc/apt/trusted.gpg holds keys",
		"/etc/apt/trusted.gpg.d/vendor.gpg is a key trusted for every repository")
	if state(t, aptAuditControl(), env) != control.Partial {
		t.Fatal("findings make the state partial")
	}
	if strings.Contains(all, "debian-archive") {
		t.Fatalf("Debian's own key is fine: %s", all)
	}
}

func TestAPTAuditIsReadOnly(t *testing.T) {
	env := cleanAPT(t)
	writeFile(t, env, "/etc/apt/apt.conf.d/10ok", "Acquire::AllowInsecureRepositories \"false\";\n")
	if f, _ := auditAPT(env); len(f) != 0 {
		t.Fatalf("false must not count: %v", f)
	}
	if err := aptAuditControl().Revert(context.Background(), env); err != control.ErrNoRevert {
		t.Fatalf("want ErrNoRevert, got %v", err)
	}
}
