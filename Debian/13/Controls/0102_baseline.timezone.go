// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Danang Galuh Tegar Prasetyo

package controls

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/danang-id/server-hardening/internal/control"
	"github.com/danang-id/server-hardening/internal/files"
)

const (
	tzID      = "baseline.timezone"
	tzFile    = "/etc/timezone"
	tzDefault = "Etc/UTC"
	zoneinfo  = "/usr/share/zoneinfo/"
)

type timezone struct{ control.Base }

func init() {
	System.Add(&timezone{control.Base{M: control.Meta{
		ID:       tzID,
		Category: control.Baseline,
		Number:   2,
		Title:    "Set the time zone",
		Default:  true,
		Tags:     []control.Tag{control.TagInput},
	}}})
}

func validTimezone(env *control.Env, name string) error {
	if name == "" || strings.HasPrefix(name, "/") || strings.Contains(name, "..") {
		return fmt.Errorf("enter a time zone name such as Etc/UTC or Asia/Jakarta")
	}
	st, err := os.Stat(env.Path(zoneinfo + name))
	if err != nil || !st.Mode().IsRegular() {
		return fmt.Errorf("%q is not a known time zone", name)
	}
	return nil
}

func currentTimezone(ctx context.Context, env *control.Env) string {
	out, err := env.Run.Run(ctx, "timedatectl", "show", "-p", "Timezone", "--value")
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

func (t *timezone) Inputs(_ context.Context, env *control.Env) ([]control.Input, error) {
	return []control.Input{{
		Key:      "timezone",
		Label:    "Time zone",
		Help:     "A name from the standard list, for example Etc/UTC or Asia/Jakarta",
		Default:  tzDefault,
		Validate: func(s string) error { return validTimezone(env, s) },
	}}, nil
}

func (t *timezone) Check(ctx context.Context, env *control.Env) (control.State, error) {
	want, ok, err := env.Rec.Get(tzID, "applied")
	if err != nil || !ok {
		return control.NotApplied, err
	}
	if currentTimezone(ctx, env) == want {
		return control.Applied, nil
	}
	return control.NotApplied, nil
}

func (t *timezone) Apply(ctx context.Context, env *control.Env, in control.Values) error {
	name := in.String("timezone")
	if err := validTimezone(env, name); err != nil {
		return err
	}
	if err := env.Rec.Put(tzID, "previous", currentTimezone(ctx, env)); err != nil {
		return err
	}
	if err := env.Rec.Backup(tzID, env.Path(tzFile)); err != nil {
		return err
	}
	if _, err := env.Run.Run(ctx, "timedatectl", "set-timezone", name); err != nil {
		return err
	}
	// Debian keeps the name in /etc/timezone too, when the file exists.
	if files.Exists(env.Path(tzFile)) {
		if err := files.WriteAtomic(env.Path(tzFile), []byte(name+"\n"), 0o644); err != nil {
			return err
		}
	}
	env.Log.Infof("time zone set to %s", name)
	return env.Rec.Put(tzID, "applied", name)
}

func (t *timezone) Revert(ctx context.Context, env *control.Env) error {
	prev, ok, err := env.Rec.Get(tzID, "previous")
	if err != nil {
		return err
	}
	if !ok {
		env.Log.Warnf("%s: no record of the previous time zone, leaving it alone", tzID)
		return nil
	}
	if prev != "" {
		if _, err := env.Run.Run(ctx, "timedatectl", "set-timezone", prev); err != nil {
			return err
		}
	}
	if _, err := env.Rec.Restore(tzID, env.Path(tzFile)); err != nil {
		return err
	}
	return env.Rec.Delete(tzID)
}
