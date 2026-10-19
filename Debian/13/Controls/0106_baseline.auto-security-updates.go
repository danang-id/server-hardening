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

	"github.com/danang-id/server-hardening/internal/apt"
	"github.com/danang-id/server-hardening/internal/control"
	"github.com/danang-id/server-hardening/internal/files"
	"github.com/danang-id/server-hardening/internal/systemd"
)

const (
	autoID     = "baseline.auto-security-updates"
	autoFile   = "/etc/apt/apt.conf.d/52server-hardening-auto-updates"
	autoMarker = "// Managed by github.com/danang-id/server-hardening (baseline.auto-security-updates)"
)

var autoTimers = []string{"apt-daily.timer", "apt-daily-upgrade.timer"}

const (
	autoHook   = libexecDir + "/upgrade-notify"
	autoDropIn = "/etc/systemd/system/apt-daily-upgrade.service.d/99-server-hardening-notify.conf"
)

// autoHookScript runs after every unattended upgrade (ExecStopPost). It only
// reports through the notify helper, and does nothing when that helper does
// not exist. A reboot reminder is sent once per boot.
const autoHookScript = `#!/bin/sh
# Managed by github.com/danang-id/server-hardening (baseline.auto-security-updates)
N="${HOOK_NOTIFY:-` + notifyPath + `}"
FLAG="${HOOK_FLAG:-/var/run/reboot-required}"
SEEN="${HOOK_SEEN:-/run/server-hardening-reboot-notified}"
[ -x "$N" ] || exit 0
if [ "${SERVICE_RESULT:-success}" != success ]; then
    "$N" baseline.auto-security-updates.failed warning "Automatic security updates failed" \
        "apt-daily-upgrade.service ended with ${SERVICE_RESULT} (exit status ${EXIT_STATUS:-unknown}). Look at: journalctl -u apt-daily-upgrade.service"
    exit 0
fi
if [ -e "$FLAG" ] && [ ! -e "$SEEN" ]; then
    : > "$SEEN"
    pkgs=$(sort -u "$FLAG.pkgs" 2>/dev/null | head -n 20 | tr '\n' ' ')
    "$N" baseline.auto-security-updates.reboot-required info "A reboot is needed after updates" "Packages: ${pkgs:-unknown}"
fi
exit 0
`

const autoDropInContent = "# Managed by github.com/danang-id/server-hardening (baseline.auto-security-updates)\n[Service]\nExecStopPost=-" + autoHook + "\n"

type autoUpdates struct{ control.Base }

func init() {
	System.Add(&autoUpdates{control.Base{M: control.Meta{
		ID:           autoID,
		Category:     control.Baseline,
		Number:       6,
		Title:        "Install security updates automatically",
		Default:      true,
		Tags:         []control.Tag{control.TagInput},
		RevertLimits: "The unattended-upgrades package stays installed.",
	}}})
}

var hhmm = regexp.MustCompile(`^([01]\d|2[0-3]):[0-5]\d$`)

func (a *autoUpdates) Inputs(context.Context, *control.Env) ([]control.Input, error) {
	return []control.Input{
		{
			Key:   "reboot",
			Label: "Reboot automatically when an update needs it?",
			Kind:  control.Choice,
			Options: []control.Option{
				{Value: "no", Label: "No, I will reboot myself"},
				{Value: "yes", Label: "Yes, at the time below"},
			},
			Default: "no",
		},
		{
			Key:     "reboot-time",
			Label:   "Reboot time (24-hour, server time zone). Used only if automatic reboot is on.",
			Default: "03:00",
			Validate: func(s string) error {
				if !hhmm.MatchString(s) {
					return fmt.Errorf("use the form HH:MM, for example 03:00")
				}
				return nil
			},
		},
	}, nil
}

func (a *autoUpdates) Check(ctx context.Context, env *control.Env) (control.State, error) {
	b, err := files.ReadOptional(env.Path(autoFile))
	if err != nil || !strings.Contains(string(b), autoMarker) {
		return control.NotApplied, err
	}
	if !hasMarker(env, autoHook, autoID) || !hasMarker(env, autoDropIn, autoID) {
		return control.Partial, nil
	}
	for _, t := range autoTimers {
		if !systemd.IsEnabled(ctx, env, t) {
			return control.Partial, nil
		}
	}
	return control.Applied, nil
}

func autoContent(reboot bool, at string) string {
	var b strings.Builder
	b.WriteString(autoMarker)
	b.WriteString("\n")
	b.WriteString("APT::Periodic::Update-Package-Lists \"1\";\n")
	b.WriteString("APT::Periodic::Unattended-Upgrade \"1\";\n")
	// Security updates only: replace the package's own list of origins.
	b.WriteString("#clear Unattended-Upgrade::Origins-Pattern;\n")
	b.WriteString("Unattended-Upgrade::Origins-Pattern {\n")
	b.WriteString("\t\"origin=Debian,codename=${distro_codename}-security,label=Debian-Security\";\n")
	b.WriteString("};\n")
	if reboot {
		b.WriteString("Unattended-Upgrade::Automatic-Reboot \"true\";\n")
		fmt.Fprintf(&b, "Unattended-Upgrade::Automatic-Reboot-Time \"%s\";\n", at)
	}
	return b.String()
}

func (a *autoUpdates) Apply(ctx context.Context, env *control.Env, in control.Values) error {
	reboot := in.String("reboot") == "yes"
	at := in.String("reboot-time")
	if reboot && !hhmm.MatchString(at) {
		return fmt.Errorf("reboot time %q must look like 03:00", at)
	}
	if err := apt.Install(ctx, env, "unattended-upgrades"); err != nil {
		return err
	}
	if err := env.Rec.Backup(autoID, env.Path(autoFile)); err != nil {
		return err
	}
	for _, t := range autoTimers {
		if systemd.IsEnabled(ctx, env, t) {
			if err := env.Rec.Put(autoID, "was-enabled-"+t, "yes"); err != nil {
				return err
			}
		}
	}
	if err := files.WriteAtomic(env.Path(autoFile), []byte(autoContent(reboot, at)), 0o644); err != nil {
		return err
	}
	if err := os.MkdirAll(env.Path(libexecDir), 0o755); err != nil {
		return err
	}
	if err := putFile(env, autoID, autoHook, autoHookScript, 0o755); err != nil {
		return err
	}
	if err := putFile(env, autoID, autoDropIn, autoDropInContent, 0o644); err != nil {
		return err
	}
	if _, err := env.Run.Run(ctx, "systemctl", "daemon-reload"); err != nil {
		return err
	}
	if err := systemd.EnableNow(ctx, env, autoTimers...); err != nil {
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
	if _, err := env.Rec.Restore(autoID, env.Path(autoFile)); err != nil {
		return err
	}
	for _, f := range []string{autoDropIn, autoHook} {
		if err := restoreFile(env, autoID, f); err != nil {
			return err
		}
	}
	_ = os.Remove(env.Path(filepath.Dir(autoDropIn))) // only when empty
	if _, err := env.Run.Run(ctx, "systemctl", "daemon-reload"); err != nil {
		return err
	}
	// Put the timers back the way they were before this control.
	for _, t := range autoTimers {
		if _, was, err := env.Rec.Get(autoID, "was-enabled-"+t); err != nil {
			return err
		} else if !was {
			if err := systemd.DisableNow(ctx, env, t); err != nil {
				return err
			}
		}
	}
	return env.Rec.Delete(autoID)
}
