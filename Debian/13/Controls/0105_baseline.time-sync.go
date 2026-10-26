// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Danang Galuh Tegar Prasetyo

package controls

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/danang-id/server-hardening/internal/apt"
	"github.com/danang-id/server-hardening/internal/control"
	"github.com/danang-id/server-hardening/internal/files"
	"github.com/danang-id/server-hardening/internal/systemd"
)

const (
	syncID         = "baseline.time-sync"
	chronyDropIn   = "/etc/chrony/conf.d/server-hardening.conf"
	timesyncDropIn = "/etc/systemd/timesyncd.conf.d/server-hardening.conf"
)

// Time services that must not run next to the chosen one.
var timeServices = []string{"chrony", "systemd-timesyncd", "ntp", "ntpsec", "openntpd"}

type timeSync struct{ control.Base }

func init() {
	System.Add(&timeSync{control.Base{M: control.Meta{
		ID:           syncID,
		Category:     control.Baseline,
		Number:       5,
		Title:        "Enable time synchronization",
		Default:      true,
		Tags:         []control.Tag{control.TagInput},
		RevertLimits: "The installed time service package stays installed, disabled.",
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
	return []control.Input{
		{
			Key:   "service",
			Label: "Time service",
			Kind:  control.Choice,
			Options: []control.Option{
				{Value: "chrony", Label: "chrony (recommended)"},
				{Value: "systemd-timesyncd", Label: "systemd-timesyncd (simple client)"},
			},
			Default: "chrony",
		},
		{
			Key:      "servers",
			Label:    "Time servers, separated by spaces",
			Help:     "Leave empty to use the Debian pool",
			Optional: true,
			Validate: validServers,
		},
	}, nil
}

func (t *timeSync) Check(ctx context.Context, env *control.Env) (control.State, error) {
	svc, ok, err := env.Rec.Get(syncID, "service")
	if err != nil || !ok {
		return control.NotApplied, err
	}
	if !systemd.IsActive(ctx, env, svc) {
		return control.NotApplied, nil
	}
	out, err := env.Run.Run(ctx, "timedatectl", "show", "-p", "NTPSynchronized", "--value")
	if err == nil && strings.TrimSpace(string(out)) == "yes" {
		return control.Applied, nil
	}
	return control.Pending, nil // running, but the clock is not synchronized yet
}

func (t *timeSync) Apply(ctx context.Context, env *control.Env, in control.Values) error {
	svc := in.String("service")
	if svc != "chrony" && svc != "systemd-timesyncd" {
		return fmt.Errorf("unknown time service %q", svc)
	}
	servers := strings.Fields(in.String("servers"))
	if err := validServers(strings.Join(servers, " ")); err != nil {
		return err
	}

	// Stop every other time service, and remember what it was doing.
	for _, other := range timeServices {
		if other == svc {
			continue
		}
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
		env.Log.Infof("stopping %s, it would fight with %s", other, svc)
		if err := systemd.DisableNow(ctx, env, other); err != nil {
			return err
		}
	}

	if err := apt.Install(ctx, env, svc); err != nil {
		return err
	}

	dropIn, content := chronyDropIn, ""
	if svc == "systemd-timesyncd" {
		dropIn = timesyncDropIn
	}
	if err := env.Rec.Backup(syncID, env.Path(dropIn)); err != nil {
		return err
	}
	if len(servers) > 0 {
		if svc == "chrony" {
			for _, s := range servers {
				content += "server " + s + " iburst\n"
			}
		} else {
			content = "[Time]\nNTP=" + strings.Join(servers, " ") + "\n"
		}
		if err := files.WriteAtomic(env.Path(dropIn), []byte(content), 0o644); err != nil {
			return err
		}
	}

	if err := systemd.EnableNow(ctx, env, svc); err != nil {
		return err
	}
	if err := systemd.Restart(ctx, env, svc); err != nil { // pick up the drop-in
		return err
	}
	env.Log.Infof("%s is running", svc)
	return env.Rec.Put(syncID, "service", svc)
}

func (t *timeSync) Revert(ctx context.Context, env *control.Env) error {
	svc, ok, err := env.Rec.Get(syncID, "service")
	if err != nil {
		return err
	}
	if !ok {
		env.Log.Warnf("%s: no record of the time service, leaving it alone", syncID)
		return nil
	}
	if err := systemd.DisableNow(ctx, env, svc); err != nil {
		return err
	}
	for _, p := range []string{chronyDropIn, timesyncDropIn} {
		if _, err := env.Rec.Restore(syncID, env.Path(p)); err != nil {
			return err
		}
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
