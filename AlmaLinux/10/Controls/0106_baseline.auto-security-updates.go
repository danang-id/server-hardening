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
	"github.com/danang-id/server-hardening/internal/dnf"
	"github.com/danang-id/server-hardening/internal/files"
	"github.com/danang-id/server-hardening/internal/kit"
	"github.com/danang-id/server-hardening/internal/systemd"
)

const (
	autoID      = "baseline.auto-security-updates"
	autoConf    = "/etc/dnf/automatic.conf"
	autoTimer   = "dnf-automatic-install.timer"
	autoDropIn  = "/etc/systemd/system/dnf-automatic-install.timer.d/99-server-hardening.conf"
	autoPackage = "dnf-automatic"
)

type autoUpdates struct{ control.Base }

func init() {
	System.Add(&autoUpdates{control.Base{M: control.Meta{
		ID:           autoID,
		Category:     control.Baseline,
		Number:       6,
		Title:        "Install security updates automatically",
		Default:      true,
		Tags:         []control.Tag{control.TagInput},
		RevertLimits: "The dnf-automatic package stays installed.",
	}}})
}

var hhmm = regexp.MustCompile(`^([01]\d|2[0-3]):[0-5]\d$`)

func (a *autoUpdates) Inputs(context.Context, *control.Env) ([]control.Input, error) {
	return []control.Input{
		{
			Key:      "time",
			Label:    "Time of the daily run (24-hour, server time zone)",
			Help:     "The timer adds a random delay of up to an hour",
			Default:  "03:00",
			Validate: validClock,
		},
		{
			Key:   "reboot",
			Label: "Reboot automatically when an update needs it?",
			Kind:  control.Choice,
			Options: []control.Option{
				{Value: "no", Label: "No, I will reboot myself"},
				{Value: "yes", Label: "Yes, right after the updates are installed"},
			},
			Default: "no",
		},
	}, nil
}

func validClock(s string) error {
	if !hhmm.MatchString(s) {
		return fmt.Errorf("use the form HH:MM, for example 03:00")
	}
	return nil
}

// autoSettings are the values of automatic.conf that this control owns.
func autoSettings(reboot bool) [][3]string {
	r := "never"
	if reboot {
		r = "when-needed"
	}
	return [][3]string{
		{"commands", "upgrade_type", "security"},
		{"commands", "download_updates", "yes"},
		{"commands", "apply_updates", "yes"},
		{"commands", "reboot", r},
		{"emitters", "emit_via", "stdio"},
	}
}

func autoDropInContent(at string) string {
	return kit.Marker(autoID) + "\n[Timer]\nOnCalendar=\nOnCalendar=*-*-* " + at + "\n"
}

func (a *autoUpdates) Check(ctx context.Context, env *control.Env) (control.State, error) {
	b, err := files.ReadOptional(env.Path(autoConf))
	if err != nil || !strings.Contains(string(b), kit.Marker(autoID)) {
		return control.NotApplied, err
	}
	reboot, _ := kit.GetINI(string(b), "commands", "reboot")
	for _, s := range autoSettings(reboot == "when-needed") {
		if v, ok := kit.GetINI(string(b), s[0], s[1]); !ok || v != s[2] {
			return control.Partial, nil
		}
	}
	if !kit.HasMarker(env, autoDropIn, autoID) || !systemd.IsEnabled(ctx, env, autoTimer) {
		return control.Partial, nil
	}
	return control.Applied, nil
}

func (a *autoUpdates) Apply(ctx context.Context, env *control.Env, in control.Values) error {
	at := in.String("time")
	if err := validClock(at); err != nil {
		return fmt.Errorf("run time %q: %w", at, err)
	}
	if err := dnf.Install(ctx, env, autoPackage); err != nil {
		return err
	}
	for _, p := range []string{autoConf, autoDropIn} {
		if err := env.Rec.Backup(autoID, env.Path(p)); err != nil {
			return err
		}
	}
	if err := kit.RecordUnit(ctx, env, autoID, autoTimer); err != nil {
		return err
	}
	b, err := files.ReadOptional(env.Path(autoConf))
	if err != nil {
		return err
	}
	conf := string(b)
	for _, s := range autoSettings(in.String("reboot") == "yes") {
		conf = kit.SetINI(conf, s[0], s[1], s[2])
	}
	if !strings.Contains(conf, kit.Marker(autoID)) {
		conf = kit.Marker(autoID) + "\n" + conf
	}
	if err := files.WriteAtomic(env.Path(autoConf), []byte(conf), 0o644); err != nil {
		return err
	}
	if err := kit.PutFile(env, autoID, autoDropIn, autoDropInContent(at), 0o644); err != nil {
		return err
	}
	if _, err := env.Run.Run(ctx, "systemctl", "daemon-reload"); err != nil {
		return err
	}
	if err := systemd.EnableNow(ctx, env, autoTimer); err != nil {
		return err
	}
	env.Log.Infof("security updates install automatically every day")
	return env.Rec.Put(autoID, "applied", "yes")
}

func (a *autoUpdates) Revert(ctx context.Context, env *control.Env) error {
	if !env.Rec.Has(autoID) {
		env.Log.Warnf("%s: no record, leaving automatic updates alone", autoID)
		return nil
	}
	if _, err := env.Rec.Restore(autoID, env.Path(autoConf)); err != nil {
		return err
	}
	if err := kit.RestoreFile(env, autoID, autoDropIn); err != nil {
		return err
	}
	_ = os.Remove(env.Path(filepath.Dir(autoDropIn))) // only when empty
	if _, err := env.Run.Run(ctx, "systemctl", "daemon-reload"); err != nil {
		return err
	}
	if err := kit.RestoreUnit(ctx, env, autoID, autoTimer); err != nil {
		return err
	}
	return env.Rec.Delete(autoID)
}
