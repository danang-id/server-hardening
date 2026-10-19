// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Danang Galuh Tegar Prasetyo

package controls

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/danang-id/server-hardening/internal/control"
	"github.com/danang-id/server-hardening/internal/files"
	"github.com/danang-id/server-hardening/internal/systemd"
)

const (
	aideSchedID   = "ldp.aide-scheduled-check"
	aideSchedUnit = "server-hardening-aide-check"
	aideService   = "/etc/systemd/system/" + aideSchedUnit + ".service"
	aideTimer     = "/etc/systemd/system/" + aideSchedUnit + ".timer"
	aidePkgTimer  = "dailyaidecheck.timer"
	aideDefault   = "/etc/default/aide"
)

type aideScheduledCheck struct{ control.Base }

func init() {
	System.Add(&aideScheduledCheck{control.Base{M: control.Meta{
		ID:       aideSchedID,
		Category: control.LDP,
		Number:   7,
		Title:    "Run a scheduled AIDE check",
		Default:  true,
		Weight:   950,
		Requires: []string{aideID},
		Tags:     []control.Tag{control.TagInput},
	}}})
}

var clockTime = regexp.MustCompile(`^([01][0-9]|2[0-3]):[0-5][0-9]$`)

func (a *aideScheduledCheck) Inputs(context.Context, *control.Env) ([]control.Input, error) {
	return []control.Input{
		{
			Key: "every", Label: "How often to check", Kind: control.Choice, Default: "weekly",
			Options: []control.Option{
				{Value: "weekly", Label: "Weekly, on Sunday (recommended)"},
				{Value: "daily", Label: "Daily"},
			},
		},
		{
			Key: "at", Label: "At what time (24-hour, server time)", Default: "03:00",
			Validate: func(s string) error {
				if !clockTime.MatchString(strings.TrimSpace(s)) {
					return fmt.Errorf("use the form HH:MM, for example 03:00")
				}
				return nil
			},
		},
	}, nil
}

func aideServiceContent() string {
	return managed(aideSchedID) + "\n[Unit]\nDescription=AIDE file integrity check\n\n" +
		"[Service]\nType=oneshot\nNice=19\nIOSchedulingClass=idle\nExecStart=" + aideRunPath + " check\n"
}

func aideTimerContent(every, at string) string {
	day := ""
	if every == "weekly" {
		day = "Sun "
	}
	return managed(aideSchedID) + "\n[Unit]\nDescription=Run the AIDE file integrity check\n\n" +
		"[Timer]\nOnCalendar=" + day + "*-*-* " + at + ":00\nPersistent=true\n\n" +
		"[Install]\nWantedBy=timers.target\n"
}

func (a *aideScheduledCheck) Check(ctx context.Context, env *control.Env) (control.State, error) {
	if !hasMarker(env, aideTimer, aideSchedID) {
		return control.NotApplied, nil
	}
	if !files.Exists(env.Path(aideRunPath)) || !hasMarker(env, aideService, aideSchedID) ||
		!systemd.IsEnabled(ctx, env, aideSchedUnit+".timer") || !systemd.IsActive(ctx, env, aideSchedUnit+".timer") {
		return control.Partial, nil
	}
	return control.Applied, nil
}

func (a *aideScheduledCheck) Apply(ctx context.Context, env *control.Env, in control.Values) error {
	every, at := in.String("every"), strings.TrimSpace(in.String("at"))
	if every != "daily" && every != "weekly" {
		return fmt.Errorf("the schedule %q is not daily or weekly", every)
	}
	if !clockTime.MatchString(at) {
		return fmt.Errorf("the time %q is not of the form HH:MM", at)
	}
	if !files.Exists(env.Path(aideRunPath)) {
		return errMissing(aideID, aideRunPath)
	}

	// The package has its own daily check. Turn it off so there is only one.
	if _, err := env.Run.Run(ctx, "systemctl", "cat", aidePkgTimer); err == nil {
		if err := recordUnit(ctx, env, aideSchedID, aidePkgTimer); err != nil {
			return err
		}
		if err := env.Rec.Put(aideSchedID, "pkg-timer", "yes"); err != nil {
			return err
		}
		if err := systemd.DisableNow(ctx, env, aidePkgTimer); err != nil {
			return fmt.Errorf("cannot turn off the package's own check: %w", err)
		}
	}
	if b, err := files.ReadOptional(env.Path(aideDefault)); err == nil && b != nil {
		re := regexp.MustCompile(`(?m)^\s*CRON_DAILY_RUN\s*=.*$`)
		if re.Match(b) {
			if err := putFile(env, aideSchedID, aideDefault, re.ReplaceAllString(string(b), "CRON_DAILY_RUN=no"), 0o644); err != nil {
				return err
			}
		}
	}

	if err := putFile(env, aideSchedID, aideService, aideServiceContent(), 0o644); err != nil {
		return err
	}
	if err := putFile(env, aideSchedID, aideTimer, aideTimerContent(every, at), 0o644); err != nil {
		return err
	}
	if _, err := env.Run.Run(ctx, "systemctl", "daemon-reload"); err != nil {
		return err
	}
	if err := systemd.EnableNow(ctx, env, aideSchedUnit+".timer"); err != nil {
		return fmt.Errorf("cannot start the timer: %w", err)
	}
	return nil
}

func (a *aideScheduledCheck) Revert(ctx context.Context, env *control.Env) error {
	if !env.Rec.Has(aideSchedID) {
		env.Log.Warnf("%s: no record, leaving the timers alone", aideSchedID)
		return nil
	}
	if err := systemd.DisableNow(ctx, env, aideSchedUnit+".timer"); err != nil {
		env.Log.Warnf("cannot stop %s.timer: %v", aideSchedUnit, err)
	}
	for _, f := range []string{aideTimer, aideService, aideDefault} {
		if err := restoreFile(env, aideSchedID, f); err != nil {
			return err
		}
	}
	if _, err := env.Run.Run(ctx, "systemctl", "daemon-reload"); err != nil {
		return err
	}
	if v, _, _ := env.Rec.Get(aideSchedID, "pkg-timer"); v == "yes" {
		if err := restoreUnit(ctx, env, aideSchedID, aidePkgTimer); err != nil {
			return err
		}
	}
	return env.Rec.Delete(aideSchedID)
}
