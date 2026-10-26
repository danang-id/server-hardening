// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Danang Galuh Tegar Prasetyo

package controls

import (
	"context"
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/danang-id/server-hardening/internal/control"
	"github.com/danang-id/server-hardening/internal/dnf"
	"github.com/danang-id/server-hardening/internal/files"
	"github.com/danang-id/server-hardening/internal/kit"
	"github.com/danang-id/server-hardening/internal/systemd"
)

const (
	syncID       = "baseline.time-sync"
	chronyUnit   = "chronyd"
	chronyConf   = "/etc/chrony.conf"
	chronyDir    = "/etc/chrony.d"
	chronyDropIn = chronyDir + "/server-hardening.conf"
	chronyInc    = "confdir " + chronyDir
)

// Time services that must not run next to chrony. AlmaLinux ships chrony and
// ntpd's replacement only, but a server may have been set up with another one.
var timeServices = []string{"systemd-timesyncd", "ntpd", "ntpsec", "openntpd"}

type timeSync struct{ control.Base }

func init() {
	System.Add(&timeSync{control.Base{M: control.Meta{
		ID:           syncID,
		Category:     control.Baseline,
		Number:       5,
		Title:        "Enable time synchronization (chrony)",
		Default:      true,
		Tags:         []control.Tag{control.TagInput},
		RevertLimits: "The chrony package stays installed, disabled.",
	}}})
}

var host = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9.:-]{0,251}[A-Za-z0-9])?$`)

func validServers(s string) error {
	for _, f := range strings.Fields(s) {
		if !host.MatchString(f) {
			return fmt.Errorf("%q is not a host name or address", f)
		}
	}
	return nil
}

func (t *timeSync) Inputs(context.Context, *control.Env) ([]control.Input, error) {
	return []control.Input{{
		Key:      "servers",
		Label:    "Extra time servers, separated by spaces",
		Help:     "Leave empty to use the AlmaLinux pool that chrony already lists",
		Optional: true,
		Validate: validServers,
	}}, nil
}

func (t *timeSync) Check(ctx context.Context, env *control.Env) (control.State, error) {
	if _, ok, err := env.Rec.Get(syncID, "applied"); err != nil || !ok {
		return control.NotApplied, err
	}
	if !systemd.IsActive(ctx, env, chronyUnit) {
		return control.NotApplied, nil
	}
	out, err := env.Run.Run(ctx, "timedatectl", "show", "-p", "NTPSynchronized", "--value")
	if err == nil && strings.TrimSpace(string(out)) == "yes" {
		return control.Applied, nil
	}
	return control.Pending, nil // running, but the clock is not synchronized yet
}

func (t *timeSync) Apply(ctx context.Context, env *control.Env, in control.Values) error {
	servers := strings.Fields(in.String("servers"))
	if err := validServers(strings.Join(servers, " ")); err != nil {
		return err
	}

	// Stop every other time service, and remember what it was doing.
	for _, other := range timeServices {
		active, enabled := systemd.IsActive(ctx, env, other), systemd.IsEnabled(ctx, env, other)
		if !active && !enabled {
			continue
		}
		state := ""
		if active {
			state += "active,"
		}
		if enabled {
			state += "enabled"
		}
		if err := env.Rec.Put(syncID, "was-"+other, state); err != nil {
			return err
		}
		env.Log.Infof("stopping %s, it would fight with chrony", other)
		if err := systemd.DisableNow(ctx, env, other); err != nil {
			return err
		}
	}

	if err := dnf.Install(ctx, env, "chrony"); err != nil {
		return err
	}

	// The drop-in is only read when chrony.conf includes its folder.
	for _, p := range []string{chronyConf, chronyDropIn} {
		if err := env.Rec.Backup(syncID, env.Path(p)); err != nil {
			return err
		}
	}
	if len(servers) > 0 {
		var content strings.Builder
		content.WriteString(kit.Marker(syncID))
		content.WriteString("\n")
		for _, s := range servers {
			content.WriteString("server ")
			content.WriteString(s)
			content.WriteString(" iburst\n")
		}
		if err := os.MkdirAll(env.Path(chronyDir), 0o755); err != nil {
			return err
		}
		if err := files.WriteAtomic(env.Path(chronyDropIn), []byte(content.String()), 0o644); err != nil {
			return err
		}
		conf, err := files.ReadOptional(env.Path(chronyConf))
		if err != nil {
			return err
		}
		if !hasChronyDir(string(conf)) {
			c := string(conf)
			if c != "" && !strings.HasSuffix(c, "\n") {
				c += "\n"
			}
			c += "\n" + kit.Marker(syncID) + "\n" + chronyInc + "\n"
			if err := files.WriteAtomic(env.Path(chronyConf), []byte(c), 0o644); err != nil {
				return err
			}
		}
	}

	if err := systemd.EnableNow(ctx, env, chronyUnit); err != nil {
		return err
	}
	if err := systemd.Restart(ctx, env, chronyUnit); err != nil { // pick up the drop-in
		return err
	}
	env.Log.Infof("chrony is running")
	return env.Rec.Put(syncID, "applied", "yes")
}

// hasChronyDir reports whether chrony.conf already reads the drop-in folder,
// with confdir or with sourcedir.
func hasChronyDir(conf string) bool {
	for l := range strings.SplitSeq(conf, "\n") {
		f := strings.Fields(l)
		if len(f) == 2 && (f[0] == "confdir" || f[0] == "include") && strings.HasPrefix(f[1], chronyDir) {
			return true
		}
	}
	return false
}

func (t *timeSync) Revert(ctx context.Context, env *control.Env) error {
	if !env.Rec.Has(syncID) {
		env.Log.Warnf("%s: no record of the time service, leaving it alone", syncID)
		return nil
	}
	for _, p := range []string{chronyConf, chronyDropIn} {
		if _, err := env.Rec.Restore(syncID, env.Path(p)); err != nil {
			return err
		}
	}
	if err := systemd.DisableNow(ctx, env, chronyUnit); err != nil {
		return err
	}
	for _, other := range timeServices {
		state, had, err := env.Rec.Get(syncID, "was-"+other)
		if err != nil {
			return err
		}
		if !had {
			continue
		}
		if strings.Contains(state, "enabled") {
			if err := systemd.Enable(ctx, env, other); err != nil {
				return err
			}
		}
		if strings.Contains(state, "active") {
			if err := systemd.Start(ctx, env, other); err != nil {
				return err
			}
		}
	}
	return env.Rec.Delete(syncID)
}
