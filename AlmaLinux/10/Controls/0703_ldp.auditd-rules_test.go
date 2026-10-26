// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Danang Galuh Tegar Prasetyo

package controls

import (
	"context"
	"strings"
	"testing"

	"github.com/danang-id/server-hardening/internal/control"
)

func rulesControl() *auditdRules {
	return &auditdRules{control.Base{M: control.Meta{ID: auditRulesID}}}
}

func TestAuditRulesContent(t *testing.T) {
	r := auditRules("amd64", false)
	wantContains(t, r, managed(auditRulesID),
		"-w /etc/passwd -p wa -k identity", "-w /etc/shadow -p wa -k identity",
		"-w /etc/sudoers.d/ -p wa -k sudoers", "-w /etc/ssh/sshd_config.d/ -p wa -k sshd",
		"-w /var/log/btmp -p wa -k logins", "-w /usr/bin/sudo -p x -k privileged-exec",
		"arch=b64 -S init_module,finit_module,delete_module", "arch=b32 -S init_module",
		"-w /etc/audit/ -p wa -k auditconfig")
	if strings.Contains(r, "-e 2") {
		t.Fatal("no lock unless asked")
	}
	if strings.Contains(auditRules("arm64", false), "arch=b32") {
		t.Fatal("only x86-64 has the 32-bit rules")
	}
	if !strings.HasSuffix(strings.TrimSpace(auditRules("amd64", true)), "-e 2") {
		t.Fatal("the lock must be the last rule")
	}
}

func TestAuditRulesApplyAndRevert(t *testing.T) {
	ctx := context.Background()
	env, run, _ := sysEnv(t)
	c := rulesControl()
	if state(t, c, env) != control.NotApplied {
		t.Fatal("should start not applied")
	}
	must(t, c.Apply(ctx, env, control.Values{"lock": {"no"}}))
	wantContains(t, read(t, env, auditRulesFile), "-k identity")
	if !run.did("augenrules --load") {
		t.Fatal("the rules must be loaded")
	}
	if state(t, c, env) != control.Partial {
		t.Fatal("rules in the file that auditctl does not list are partial")
	}
	run.out["auditctl -l"] = "-w /etc/passwd -p wa -k identity\n"
	if state(t, c, env) != control.Applied {
		t.Fatal("should be applied")
	}
	must(t, c.Revert(ctx, env))
	noFile(t, env, auditRulesFile)
	if env.Rec.Has(auditRulesID) {
		t.Fatal("record should be gone")
	}
}

func TestAuditRulesLoadFailureRemovesFile(t *testing.T) {
	env, run, _ := sysEnv(t)
	run.fail["augenrules --load"] = true
	run.out["augenrules --load"] = "Error sending add rule data request"
	err := rulesControl().Apply(context.Background(), env, control.Values{"lock": {"no"}})
	if err == nil || !strings.Contains(err.Error(), "Error sending add rule") {
		t.Fatalf("want the tool's message in the error, got %v", err)
	}
	noFile(t, env, auditRulesFile)
}

func TestAuditRulesLockedRevertOnlyWarns(t *testing.T) {
	env, run, _ := sysEnv(t)
	c := rulesControl()
	must(t, c.Apply(context.Background(), env, control.Values{"lock": {"yes"}}))
	wantContains(t, read(t, env, auditRulesFile), "-e 2")
	run.fail["augenrules --load"] = true // the kernel refuses changes while locked
	var warned []string
	env.Log = &memLog{warns: &warned}
	must(t, c.Revert(context.Background(), env))
	noFile(t, env, auditRulesFile)
	if !strings.Contains(strings.Join(warned, "\n"), "after the next reboot") {
		t.Fatalf("warnings: %v", warned)
	}
}

func TestAuditRulesUnlockedRevertFailureIsAnError(t *testing.T) {
	env, run, _ := sysEnv(t)
	c := rulesControl()
	must(t, c.Apply(context.Background(), env, control.Values{"lock": {"no"}}))
	run.fail["augenrules --load"] = true
	if err := c.Revert(context.Background(), env); err == nil {
		t.Fatal("a failed reload without a lock is an error")
	}
}

func TestAuditRulesWatchSELinuxPolicy(t *testing.T) {
	got := auditRules("amd64", false)
	wantContains(t, got, "-w /etc/selinux/ -p wa -k selinux", "-w /usr/share/selinux/ -p wa -k selinux")
}
