// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Danang Galuh Tegar Prasetyo

package controls

import (
	"context"
	"fmt"
	"runtime"
	"strings"

	"github.com/danang-id/server-hardening/internal/control"
)

const (
	auditRulesID   = "ldp.auditd-rules"
	auditRulesFile = "/etc/audit/rules.d/99-server-hardening.rules"
)

type auditdRules struct{ control.Base }

func init() {
	System.Add(&auditdRules{control.Base{M: control.Meta{
		ID:           auditRulesID,
		Category:     control.LDP,
		Number:       3,
		Title:        "Add audit rules for sensitive files and actions",
		Default:      true,
		Requires:     []string{auditdID},
		Tags:         []control.Tag{control.TagInput},
		RevertLimits: "If the rules were locked, the removal only takes effect after a reboot.",
	}}})
}

func (a *auditdRules) Inputs(context.Context, *control.Env) ([]control.Input, error) {
	return []control.Input{{
		Key: "lock", Label: "Lock the audit rules until the next reboot?", Kind: control.Choice, Default: "no",
		Help: "Locked rules cannot be changed or removed until the server reboots, not even by root.",
		Options: []control.Option{
			{Value: "no", Label: "No (recommended)"},
			{Value: "yes", Label: "Yes, lock them"},
		},
	}}, nil
}

// auditRules renders the rules. arch is the Go name of the CPU architecture:
// only x86-64 has a 32-bit system call table that needs its own rules.
func auditRules(arch string, lock bool) string {
	var b strings.Builder
	w := func(f string, a ...any) { fmt.Fprintf(&b, f+"\n", a...) }
	w("%s", managed(auditRulesID))
	w("# A short set of rules for the changes an attacker usually makes.")
	w("")
	w("## Accounts and passwords")
	for _, f := range []string{"/etc/passwd", "/etc/group", "/etc/shadow", "/etc/gshadow", "/etc/security/opasswd"} {
		w("-w %s -p wa -k identity", f)
	}
	w("")
	w("## sudo configuration")
	w("-w /etc/sudoers -p wa -k sudoers")
	w("-w /etc/sudoers.d/ -p wa -k sudoers")
	w("")
	w("## SSH configuration")
	w("-w /etc/ssh/sshd_config -p wa -k sshd")
	w("-w /etc/ssh/sshd_config.d/ -p wa -k sshd")
	w("")
	w("## Logins and failed logins")
	for _, f := range []string{"/var/log/lastlog", "/var/log/wtmp", "/var/log/btmp", "/run/faillock/"} {
		w("-w %s -p wa -k logins", f)
	}
	w("")
	w("## Use of sudo and su")
	w("-w /usr/bin/sudo -p x -k privileged-exec")
	w("-w /usr/bin/su -p x -k privileged-exec")
	w("")
	w("## Kernel modules")
	for _, f := range []string{"/usr/sbin/insmod", "/usr/sbin/rmmod", "/usr/sbin/modprobe"} {
		w("-w %s -p x -k modules", f)
	}
	w("-a always,exit -F arch=b64 -S init_module,finit_module,delete_module -k modules")
	if arch == "amd64" {
		w("-a always,exit -F arch=b32 -S init_module,finit_module,delete_module -k modules")
	}
	w("")
	w("## The audit configuration itself")
	w("-w /etc/audit/ -p wa -k auditconfig")
	w("-w /etc/libaudit.conf -p wa -k auditconfig")
	if lock {
		w("")
		w("## Lock the rules until the next reboot")
		w("-e 2")
	}
	return b.String()
}

func (a *auditdRules) Check(ctx context.Context, env *control.Env) (control.State, error) {
	if !hasMarker(env, auditRulesFile, auditRulesID) {
		return control.NotApplied, nil
	}
	out, err := env.Run.Run(ctx, "auditctl", "-l")
	if err != nil || !strings.Contains(string(out), "-k identity") {
		return control.Partial, nil
	}
	return control.Applied, nil
}

func (a *auditdRules) Apply(ctx context.Context, env *control.Env, in control.Values) error {
	lock := in.String("lock") == "yes"
	if err := putFile(env, auditRulesID, auditRulesFile, auditRules(runtime.GOARCH, lock), 0o640); err != nil {
		return err
	}
	if out, err := env.Run.Run(ctx, "augenrules", "--load"); err != nil {
		_ = restoreFile(env, auditRulesID, auditRulesFile)
		_, _ = env.Run.Run(ctx, "augenrules", "--load")
		return fmt.Errorf("the audit rules did not load: %w: %s", err, strings.TrimSpace(string(out)))
	}
	if err := env.Rec.Put(auditRulesID, "locked", yesNo(lock)); err != nil {
		return err
	}
	if lock {
		env.Log.Warnf("the audit rules are locked until the next reboot")
	}
	return nil
}

func (a *auditdRules) Revert(ctx context.Context, env *control.Env) error {
	if !env.Rec.Has(auditRulesID) {
		env.Log.Warnf("%s: no record, leaving the audit rules alone", auditRulesID)
		return nil
	}
	if err := restoreFile(env, auditRulesID, auditRulesFile); err != nil {
		return err
	}
	locked, _, _ := env.Rec.Get(auditRulesID, "locked")
	if _, err := env.Run.Run(ctx, "augenrules", "--load"); err != nil {
		if locked != "yes" {
			return fmt.Errorf("the audit rules did not reload: %w", err)
		}
		env.Log.Warnf("the rules were locked, so the removal takes effect after the next reboot")
	}
	return env.Rec.Delete(auditRulesID)
}
