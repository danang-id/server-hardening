// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Danang Galuh Tegar Prasetyo

package controls

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/danang-id/server-hardening/internal/apt"
	"github.com/danang-id/server-hardening/internal/control"
	"github.com/danang-id/server-hardening/internal/files"
	"github.com/danang-id/server-hardening/internal/systemd"
)

const (
	auditdID   = "ldp.auditd"
	auditdConf = "/etc/audit/auditd.conf"
	auditdUnit = "auditd.service"
)

type auditd struct{ control.Base }

func init() {
	System.Add(&auditd{control.Base{M: control.Meta{
		ID:           auditdID,
		Category:     control.LDP,
		Number:       2,
		Title:        "Install and enable the audit daemon",
		Default:      true,
		Tags:         []control.Tag{control.TagInput},
		RevertLimits: "The auditd package stays installed. Audit logs already written stay.",
	}}})
}

func numberInput(key, label, def string, min, max int) control.Input {
	return control.Input{
		Key: key, Label: label, Default: def,
		Validate: func(s string) error {
			n, err := strconv.Atoi(strings.TrimSpace(s))
			if err != nil || n < min || n > max {
				return fmt.Errorf("enter a number from %d to %d", min, max)
			}
			return nil
		},
	}
}

func (a *auditd) Inputs(context.Context, *control.Env) ([]control.Input, error) {
	return []control.Input{
		numberInput("size", "Size of each audit log file in megabytes", "50", 1, 4096),
		numberInput("files", "Number of audit log files to keep", "5", 2, 99),
	}, nil
}

func (a *auditd) Check(ctx context.Context, env *control.Env) (control.State, error) {
	if !env.Rec.Has(auditdID) {
		return control.NotApplied, nil
	}
	b, err := files.ReadOptional(env.Path(auditdConf))
	if err != nil {
		return control.NotApplied, err
	}
	size, _, _ := env.Rec.Get(auditdID, "size")
	num, _, _ := env.Rec.Get(auditdID, "files")
	gotSize, _ := getKeyValue(string(b), "max_log_file")
	gotNum, _ := getKeyValue(string(b), "num_logs")
	if gotSize != size || gotNum != num || !systemd.IsEnabled(ctx, env, auditdUnit) || !systemd.IsActive(ctx, env, auditdUnit) {
		return control.Partial, nil
	}
	return control.Applied, nil
}

func (a *auditd) Apply(ctx context.Context, env *control.Env, in control.Values) error {
	size, files_ := strings.TrimSpace(in.String("size")), strings.TrimSpace(in.String("files"))
	if n, err := strconv.Atoi(size); err != nil || n < 1 || n > 4096 {
		return fmt.Errorf("the log file size %q is not a number from 1 to 4096", size)
	}
	if n, err := strconv.Atoi(files_); err != nil || n < 2 || n > 99 {
		return fmt.Errorf("the number of log files %q is not a number from 2 to 99", files_)
	}
	if err := apt.Install(ctx, env, "auditd"); err != nil {
		return err
	}
	if err := recordUnit(ctx, env, auditdID, auditdUnit); err != nil {
		return err
	}
	b, err := files.ReadOptional(env.Path(auditdConf))
	if err != nil {
		return err
	}
	conf := setKeyValue(string(b), "max_log_file", size)
	conf = setKeyValue(conf, "num_logs", files_)
	conf = setKeyValue(conf, "max_log_file_action", "ROTATE")
	if err := putFile(env, auditdID, auditdConf, conf, 0o640); err != nil {
		return err
	}
	if err := env.Rec.Put(auditdID, "size", size); err != nil {
		return err
	}
	if err := env.Rec.Put(auditdID, "files", files_); err != nil {
		return err
	}
	return startOrReloadAuditd(ctx, env)
}

// startOrReloadAuditd starts the daemon, or makes a running one read its
// configuration again.
func startOrReloadAuditd(ctx context.Context, env *control.Env) error {
	if systemd.IsActive(ctx, env, auditdUnit) {
		if _, err := env.Run.Run(ctx, "systemctl", "reload", auditdUnit); err != nil {
			env.Log.Warnf("auditd could not reload its configuration (%v). It uses the new values after its next restart", err)
		}
		return systemd.Enable(ctx, env, auditdUnit)
	}
	if err := systemd.EnableNow(ctx, env, auditdUnit); err != nil {
		return fmt.Errorf("cannot start the audit daemon: %w", err)
	}
	return nil
}

func (a *auditd) Revert(ctx context.Context, env *control.Env) error {
	if !env.Rec.Has(auditdID) {
		env.Log.Warnf("%s: no record, leaving auditd alone", auditdID)
		return nil
	}
	if err := restoreFile(env, auditdID, auditdConf); err != nil {
		return err
	}
	if err := restoreUnit(ctx, env, auditdID, auditdUnit); err != nil {
		return err
	}
	return env.Rec.Delete(auditdID)
}
