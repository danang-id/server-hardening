// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Danang Galuh Tegar Prasetyo

package controls

import (
	"context"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/danang-id/server-hardening/internal/control"
)

const limitsID = "remote-access.ssh-login-limits"

type sshLoginLimits struct{ control.Base }

func init() {
	System.Add(&sshLoginLimits{control.Base{M: control.Meta{
		ID:       limitsID,
		Category: control.RemoteAccess,
		Number:   4,
		Title:    "Limit login attempts and idle time",
		Default:  true,
		Tags:     []control.Tag{control.TagInput},
	}}})
}

var maxStartupsForm = regexp.MustCompile(`^(\d+):(\d+):(\d+)$`)

// validMaxStartups accepts start:rate:full where start <= full, as sshd does.
func validMaxStartups(s string) error {
	m := maxStartupsForm.FindStringSubmatch(s)
	if m == nil {
		return fmt.Errorf("use the form start:rate:full, for example 10:30:60")
	}
	start, _ := strconv.Atoi(m[1])
	rate, _ := strconv.Atoi(m[2])
	full, _ := strconv.Atoi(m[3])
	if start < 1 || full < start || rate < 1 || rate > 100 {
		return fmt.Errorf("start must be at least 1, not above full, and the rate must be from 1 to 100")
	}
	return nil
}

func (l *sshLoginLimits) Inputs(context.Context, *control.Env) ([]control.Input, error) {
	return []control.Input{
		{Key: "tries", Label: "Authentication attempts per connection", Default: "3", Validate: intInRange(1, 10)},
		{Key: "grace", Label: "Seconds allowed to log in", Default: "30", Validate: intInRange(5, 600)},
		{
			Key:     "startups",
			Label:   "Simultaneous unauthenticated connections (start:rate:full)",
			Help:    "Random drops start at the first number and become certain at the last.",
			Default: "10:30:60", Validate: validMaxStartups,
		},
		{
			Key:     "alive",
			Label:   "Keep-alive check interval in seconds",
			Help:    "A client that misses two checks in a row is disconnected.",
			Default: "300", Validate: intInRange(10, 3600),
		},
	}, nil
}

func (l *sshLoginLimits) Check(ctx context.Context, env *control.Env) (control.State, error) {
	return sshdCheck(ctx, env, limitsID, "login-limits")
}

func (l *sshLoginLimits) Apply(ctx context.Context, env *control.Env, in control.Values) error {
	for key, rng := range map[string][2]int{"tries": {1, 10}, "grace": {5, 600}, "alive": {10, 3600}} {
		if err := intInRange(rng[0], rng[1])(in.String(key)); err != nil {
			return fmt.Errorf("%s: %w", key, err)
		}
	}
	if err := validMaxStartups(in.String("startups")); err != nil {
		return fmt.Errorf("startups: %w", err)
	}
	ds := []directive{
		{"MaxAuthTries", strings.TrimSpace(in.String("tries"))},
		{"LoginGraceTime", strings.TrimSpace(in.String("grace"))},
		{"MaxStartups", in.String("startups")},
		{"ClientAliveInterval", strings.TrimSpace(in.String("alive"))},
		{"ClientAliveCountMax", "2"},
	}
	if err := sshdApply(ctx, env, limitsID, "login-limits", ds); err != nil {
		return err
	}
	env.Log.Infof("login limits are set")
	return nil
}

func (l *sshLoginLimits) Revert(ctx context.Context, env *control.Env) error {
	return sshdRevert(ctx, env, limitsID, "login-limits")
}
