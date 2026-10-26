// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Danang Galuh Tegar Prasetyo

package controls

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/danang-id/server-hardening/internal/apt"
	"github.com/danang-id/server-hardening/internal/control"
)

const enforceID = "mac.apparmor-enforce-profiles"

type apparmorEnforce struct{ control.Base }

func init() {
	System.Add(&apparmorEnforce{control.Base{M: control.Meta{
		ID:       enforceID,
		Category: control.MAC,
		Number:   2,
		Title:    "Put AppArmor profiles in enforce mode",
		Default:  true,
		Requires: []string{apparmorID},
		Tags:     []control.Tag{control.TagInput},
	}}})
}

// profileModes returns the mode of every loaded profile.
func profileModes(ctx context.Context, env *control.Env) (map[string]string, error) {
	out, err := env.Run.Run(ctx, "aa-status", "--json")
	if err != nil {
		return nil, fmt.Errorf("cannot read the AppArmor status: %w", err)
	}
	var st struct {
		Profiles map[string]string `json:"profiles"`
	}
	if err := json.Unmarshal(out, &st); err != nil {
		return nil, fmt.Errorf("cannot read the AppArmor status: %w", err)
	}
	return st.Profiles, nil
}

func complainProfiles(ctx context.Context, env *control.Env) ([]string, error) {
	modes, err := profileModes(ctx, env)
	if err != nil {
		return nil, err
	}
	var l []string
	for name, m := range modes {
		if m == "complain" {
			l = append(l, name)
		}
	}
	sort.Strings(l)
	return l, nil
}

func (a *apparmorEnforce) Inputs(ctx context.Context, env *control.Env) ([]control.Input, error) {
	l, err := complainProfiles(ctx, env)
	if err != nil || len(l) == 0 {
		return nil, nil
	}
	var opts []control.Option
	for _, p := range l {
		opts = append(opts, control.Option{Value: p, Label: p})
	}
	return []control.Input{{
		Key: "profiles", Label: "Which profiles do you want to enforce?",
		Help: "These profiles only log what they would block. In enforce mode they block it.",
		Kind: control.MultiChoice, Options: opts, DefaultMulti: l,
	}}, nil
}

func (a *apparmorEnforce) Check(ctx context.Context, env *control.Env) (control.State, error) {
	l, err := complainProfiles(ctx, env)
	if err != nil {
		return control.NotApplied, nil
	}
	if !env.Rec.Has(enforceID) {
		if len(l) == 0 {
			return control.Applied, nil
		}
		return control.NotApplied, nil
	}
	rec, _, _ := env.Rec.Get(enforceID, "profiles")
	for _, p := range lines(rec) {
		for _, c := range l {
			if p == c {
				return control.Partial, nil
			}
		}
	}
	return control.Applied, nil
}

func (a *apparmorEnforce) Apply(ctx context.Context, env *control.Env, in control.Values) error {
	// aa-enforce comes from apparmor-utils. A server can run AppArmor without
	// it, and the engine does not run the control above again for that.
	if len(in.List("profiles")) > 0 {
		if err := apt.Install(ctx, env, "apparmor-utils"); err != nil {
			return err
		}
	}
	complain, err := complainProfiles(ctx, env)
	if err != nil {
		return err
	}
	is := map[string]bool{}
	for _, c := range complain {
		is[c] = true
	}
	prev, _, _ := env.Rec.Get(enforceID, "profiles")
	all := lines(prev)
	var done []string
	rollback := func() {
		for _, p := range done {
			_, _ = env.Run.Run(ctx, "aa-complain", p)
		}
	}
	for _, p := range in.List("profiles") {
		if !is[p] {
			rollback()
			return fmt.Errorf("%q is not a profile in complain mode", p)
		}
		if _, err := env.Run.Run(ctx, "aa-enforce", p); err != nil {
			rollback()
			return fmt.Errorf("cannot enforce %s: %w", p, err)
		}
		done = append(done, p)
		if !contains(all, p) {
			all = append(all, p)
		}
		env.Log.Infof("enforcing %s", p)
	}
	if len(done) == 0 {
		env.Log.Infof("no profile chosen, nothing changed")
	}
	return env.Rec.Put(enforceID, "profiles", strings.Join(all, "\n"))
}

func (a *apparmorEnforce) Revert(ctx context.Context, env *control.Env) error {
	if !env.Rec.Has(enforceID) {
		env.Log.Warnf("%s: no record, leaving profiles alone", enforceID)
		return nil
	}
	rec, _, _ := env.Rec.Get(enforceID, "profiles")
	for _, p := range lines(rec) {
		if _, err := env.Run.Run(ctx, "aa-complain", p); err != nil {
			return fmt.Errorf("cannot put %s back in complain mode: %w", p, err)
		}
	}
	return env.Rec.Delete(enforceID)
}
