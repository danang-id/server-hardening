// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Danang Galuh Tegar Prasetyo

package controls

import (
	"context"
	"testing"

	"github.com/danang-id/server-hardening/internal/control"
)

func auditdControl() *auditd { return &auditd{control.Base{M: control.Meta{ID: auditdID}}} }

const stockAuditd = "log_file = /var/log/audit/audit.log\nmax_log_file = 8\nnum_logs = 5\nmax_log_file_action = ROTATE\n"

func TestAuditdInstallsAndConfigures(t *testing.T) {
	ctx := context.Background()
	env, _, s := sysEnv(t)
	writeFile(t, env, auditdConf, stockAuditd)
	c := auditdControl()
	if state(t, c, env) != control.NotApplied {
		t.Fatal("should start not applied")
	}
	must(t, c.Apply(ctx, env, control.Values{"size": {"50"}, "files": {"7"}}))
	conf := read(t, env, auditdConf)
	wantContains(t, conf, "max_log_file = 50", "num_logs = 7", "log_file = /var/log/audit/audit.log", "max_log_file_action = ROTATE")
	if !s.installed["auditd"] || !s.enabled[auditdUnit] || !s.active[auditdUnit] {
		t.Fatalf("auditd should be installed, enabled and running: %v %v", s.installed, s.enabled)
	}
	if state(t, c, env) != control.Applied {
		t.Fatal("should be applied")
	}

	writeFile(t, env, auditdConf, stockAuditd)
	if state(t, c, env) != control.Partial {
		t.Fatal("a changed configuration is partial")
	}

	must(t, c.Revert(ctx, env))
	if read(t, env, auditdConf) != stockAuditd {
		t.Fatalf("configuration not restored: %q", read(t, env, auditdConf))
	}
	if s.enabled[auditdUnit] || s.active[auditdUnit] {
		t.Fatal("the service was off before")
	}
	if env.Rec.Has(auditdID) {
		t.Fatal("record should be gone")
	}
}

func TestAuditdRunningIsReloaded(t *testing.T) {
	env, run, s := sysEnv(t)
	writeFile(t, env, auditdConf, stockAuditd)
	s.installed["auditd"], s.enabled[auditdUnit], s.active[auditdUnit] = true, true, true
	must(t, auditdControl().Apply(context.Background(), env, control.Values{"size": {"20"}, "files": {"3"}}))
	if !run.did("systemctl reload auditd.service") {
		t.Fatalf("a running daemon must reload: %v", run.calls)
	}
	if run.did("enable --now") {
		t.Fatal("no need to start it again")
	}
}

func TestAuditdRevertKeepsServiceThatWasRunning(t *testing.T) {
	env, _, s := sysEnv(t)
	writeFile(t, env, auditdConf, stockAuditd)
	s.installed["auditd"], s.enabled[auditdUnit], s.active[auditdUnit] = true, true, true
	c := auditdControl()
	must(t, c.Apply(context.Background(), env, control.Values{"size": {"20"}, "files": {"3"}}))
	must(t, c.Revert(context.Background(), env))
	if !s.enabled[auditdUnit] || !s.active[auditdUnit] {
		t.Fatal("it was running before, so it keeps running")
	}
}

func TestAuditdRejectsBadNumbers(t *testing.T) {
	env, _, _ := sysEnv(t)
	writeFile(t, env, auditdConf, stockAuditd)
	for _, v := range []control.Values{
		{"size": {"0"}, "files": {"5"}},
		{"size": {"50"}, "files": {"1"}},
		{"size": {"x"}, "files": {"5"}},
	} {
		if err := auditdControl().Apply(context.Background(), env, v); err == nil {
			t.Fatalf("%v must be refused", v)
		}
	}
	if read(t, env, auditdConf) != stockAuditd {
		t.Fatal("the configuration must stay as it was")
	}
}
