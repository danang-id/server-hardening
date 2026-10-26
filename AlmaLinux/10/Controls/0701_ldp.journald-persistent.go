// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Danang Galuh Tegar Prasetyo

package controls

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/danang-id/server-hardening/internal/control"
	"github.com/danang-id/server-hardening/internal/files"
	"github.com/danang-id/server-hardening/internal/systemd"
)

const (
	journaldID   = "ldp.journald-persistent"
	journaldFile = "/etc/systemd/journald.conf.d/00-server-hardening.conf"
	journalDir   = "/var/log/journal"
)

type journaldPersistent struct{ control.Base }

func init() {
	System.Add(&journaldPersistent{control.Base{M: control.Meta{
		ID:           journaldID,
		Category:     control.LDP,
		Number:       1,
		Title:        "Keep system logs across reboots",
		Default:      true,
		Tags:         []control.Tag{control.TagInput},
		RevertLimits: "Logs already written to disk stay there.",
	}}})
}

var journalSize = regexp.MustCompile(`^[1-9][0-9]{0,5}[KMGT]?$`)

func (j *journaldPersistent) Inputs(context.Context, *control.Env) ([]control.Input, error) {
	return []control.Input{
		{
			Key: "max", Label: "Most disk space the logs may use", Default: "500M",
			Help: "A number with K, M, G or T, for example 500M or 2G",
			Validate: func(s string) error {
				if !journalSize.MatchString(strings.TrimSpace(s)) {
					return fmt.Errorf("use a number with K, M, G or T, for example 500M")
				}
				return nil
			},
		},
		{
			Key: "days", Label: "Days to keep logs", Default: "90",
			Validate: func(s string) error {
				n, err := strconv.Atoi(strings.TrimSpace(s))
				if err != nil || n < 1 || n > 3650 {
					return fmt.Errorf("enter a number of days from 1 to 3650")
				}
				return nil
			},
		},
	}, nil
}

func journaldContent(max string, days int) string {
	return managed(journaldID) + "\n[Journal]\nStorage=persistent\n" +
		"SystemMaxUse=" + max + "\n" +
		fmt.Sprintf("MaxRetentionSec=%dday\n", days)
}

// otherJournalStorage finds another journald setting that may override ours.
func otherJournalStorage(env *control.Env) []string {
	var found []string
	paths := []string{env.Path("/etc/systemd/journald.conf")}
	for _, d := range []string{"/etc/systemd/journald.conf.d", "/usr/lib/systemd/journald.conf.d"} {
		m, _ := filepath.Glob(env.Path(d + "/*.conf"))
		paths = append(paths, m...)
	}
	re := regexp.MustCompile(`(?m)^\s*Storage\s*=\s*(\S+)`)
	for _, p := range paths {
		if p == env.Path(journaldFile) {
			continue
		}
		b, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		if m := re.FindStringSubmatch(string(b)); m != nil && m[1] != "persistent" {
			r, _ := filepath.Rel(env.Root, p)
			found = append(found, fmt.Sprintf("/%s sets Storage=%s", filepath.ToSlash(r), m[1]))
		}
	}
	return found
}

func (j *journaldPersistent) Check(_ context.Context, env *control.Env) (control.State, error) {
	if !hasMarker(env, journaldFile, journaldID) {
		return control.NotApplied, nil
	}
	if !files.Exists(env.Path(journalDir)) {
		return control.Partial, nil
	}
	return control.Applied, nil
}

func (j *journaldPersistent) Apply(ctx context.Context, env *control.Env, in control.Values) error {
	max := strings.TrimSpace(in.String("max"))
	if !journalSize.MatchString(max) {
		return fmt.Errorf("the log size %q is not a number with K, M, G or T", max)
	}
	days, err := strconv.Atoi(strings.TrimSpace(in.String("days")))
	if err != nil || days < 1 || days > 3650 {
		return fmt.Errorf("the days %q are not a number from 1 to 3650", in.String("days"))
	}
	if !env.Rec.Has(journaldID) {
		if err := env.Rec.Put(journaldID, "dir-existed", yesNo(files.Exists(env.Path(journalDir)))); err != nil {
			return err
		}
	}
	if err := putFile(env, journaldID, journaldFile, journaldContent(max, days), 0o644); err != nil {
		return err
	}
	if err := os.MkdirAll(env.Path(journalDir), 0o755); err != nil {
		return err
	}
	// systemd-tmpfiles sets the owner, group and access rights of the directory.
	if _, err := env.Run.Run(ctx, "systemd-tmpfiles", "--create", "--prefix", journalDir); err != nil {
		env.Log.Warnf("systemd-tmpfiles could not set up %s: %v", journalDir, err)
	}
	if err := systemd.Restart(ctx, env, "systemd-journald"); err != nil {
		_ = restoreFile(env, journaldID, journaldFile)
		return fmt.Errorf("the journal service did not restart: %w", err)
	}
	for _, w := range otherJournalStorage(env) {
		env.Log.Warnf("%s, which may override this control", w)
	}
	return nil
}

func (j *journaldPersistent) Revert(ctx context.Context, env *control.Env) error {
	if !env.Rec.Has(journaldID) {
		env.Log.Warnf("%s: no record, leaving the journal alone", journaldID)
		return nil
	}
	if err := restoreFile(env, journaldID, journaldFile); err != nil {
		return err
	}
	if err := systemd.Restart(ctx, env, "systemd-journald"); err != nil {
		return err
	}
	return env.Rec.Delete(journaldID)
}
