// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Danang Galuh Tegar Prasetyo

package controls

import (
	"context"
	"strings"
	"testing"

	"github.com/danang-id/server-hardening/internal/control"
)

func dnfAuditControl() *dnfIntegrityAudit {
	return &dnfIntegrityAudit{control.Base{M: control.Meta{ID: dnfAuditID}}}
}

func TestDNFAuditCleanSystem(t *testing.T) {
	env, _ := testEnv(t)
	f, err := auditDNF(env)
	must(t, err)
	if len(f) != 0 {
		t.Fatalf("findings on a clean system: %v", f)
	}
	if state(t, dnfAuditControl(), env) != control.Applied {
		t.Fatal("a clean system is applied")
	}
	must(t, dnfAuditControl().Apply(context.Background(), env, nil))
}

func TestDNFAuditFindsUnsafeSources(t *testing.T) {
	env, _ := testEnv(t)
	writeFile(t, env, "/etc/dnf/dnf.conf", "[main]\ngpgcheck=0\nsslverify=False\n")
	writeFile(t, env, "/etc/yum.repos.d/other.repo", ""+
		"[third]\nname=Third\nbaseurl=http://packages.example.com/el10/\ngpgcheck=0\nsslverify=0\ngpgkey=http://packages.example.com/key\nenabled=1\n\n"+
		"[off]\nname=Off\nbaseurl=http://packages.example.com/off/\ngpgcheck=0\nenabled=0\n\n"+
		"[epel]\nname=EPEL\nmetalink=https://mirrors.fedoraproject.org/metalink?repo=epel-10&arch=$basearch\ngpgcheck=1\nenabled=1\n")
	f, err := auditDNF(env)
	must(t, err)
	all := strings.Join(f, "\n")
	wantContains(t, all,
		"/etc/dnf/dnf.conf switches signature checks off",
		"/etc/dnf/dnf.conf switches the check of server certificates off",
		"the repository third does not check package signatures",
		"the repository third does not check the server certificate",
		"unencrypted connection: http://packages.example.com",
		"is not AlmaLinux's or EPEL's: http://packages.example.com",
		"signing key of third is fetched over an unencrypted connection")
	if strings.Contains(all, "repository off") || strings.Contains(all, "epel") {
		t.Fatalf("a disabled repository and EPEL are no finding:\n%s", all)
	}
	if state(t, dnfAuditControl(), env) != control.Partial {
		t.Fatal("findings make it partial")
	}
	// Apply only reports.
	before := read(t, env, "/etc/yum.repos.d/other.repo")
	must(t, dnfAuditControl().Apply(context.Background(), env, nil))
	if read(t, env, "/etc/yum.repos.d/other.repo") != before {
		t.Fatal("the audit must not change anything")
	}
}

func TestDNFAuditInheritsGPGCheckFromMain(t *testing.T) {
	env, _ := testEnv(t)
	writeFile(t, env, "/etc/dnf/dnf.conf", "[main]\ngpgcheck=0\n")
	writeFile(t, env, "/etc/yum.repos.d/almalinux-baseos.repo", "[baseos]\nbaseurl=https://repo.almalinux.org/almalinux/$releasever/BaseOS/$basearch/os/\nenabled=1\n")
	f, _ := auditDNF(env)
	if !strings.Contains(strings.Join(f, "\n"), "the repository baseos does not check package signatures") {
		t.Fatalf("findings: %v", f)
	}
}

func TestDNFAuditReadsListsOfAddresses(t *testing.T) {
	env, _ := testEnv(t)
	writeFile(t, env, "/etc/yum.repos.d/lists.repo", "[mirror]\nbaseurl=https://repo.almalinux.org/a/\n    http://evil.example.com/b/\ngpgcheck=1\ngpgkey=file:///etc/pki/rpm-gpg/RPM-GPG-KEY-AlmaLinux-10\n")
	f, _ := auditDNF(env)
	all := strings.Join(f, "\n")
	wantContains(t, all, "http://evil.example.com")
	if strings.Contains(all, "file:") {
		t.Fatalf("a local key file is fine:\n%s", all)
	}
}

func TestDNFAuditRevert(t *testing.T) {
	env, _ := testEnv(t)
	if err := dnfAuditControl().Revert(context.Background(), env); err != control.ErrNoRevert {
		t.Fatalf("want ErrNoRevert, got %v", err)
	}
}
