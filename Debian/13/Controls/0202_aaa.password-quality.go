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
)

const (
	pwqID      = "aaa.password-quality"
	pwqFile    = "/etc/security/pwquality.conf.d/99-server-hardening.conf"
	pwqMarker  = "# Managed by github.com/danang-id/server-hardening (aaa.password-quality)"
	pwqProfile = "pwquality" // the pam-auth-update profile of libpam-pwquality
	pwqPAM     = "/etc/pam.d/common-password"
)

type passwordQuality struct{ control.Base }

func init() {
	System.Add(&passwordQuality{control.Base{M: control.Meta{
		ID:           pwqID,
		Category:     control.AAA,
		Number:       2,
		Title:        "Require strong local passwords",
		Default:      true,
		Tags:         []control.Tag{control.TagInput},
		RevertLimits: "The package stays installed, unused. Passwords that were already changed stay changed.",
	}}})
}

func intInRange(lo, hi int) func(string) error {
	return func(s string) error {
		n, err := strconv.Atoi(strings.TrimSpace(s))
		if err != nil || n < lo || n > hi {
			return fmt.Errorf("enter a whole number from %d to %d", lo, hi)
		}
		return nil
	}
}

func (p *passwordQuality) Inputs(context.Context, *control.Env) ([]control.Input, error) {
	return []control.Input{
		{
			Key: "minlen", Label: "Minimum password length",
			Default: "14", Validate: intInRange(8, 128),
		},
		{
			Key:   "minclass",
			Label: "How many kinds of characters are required (lowercase, uppercase, digits, symbols)?",
			Kind:  control.Choice, Default: "3",
			Options: []control.Option{
				{Value: "1", Label: "1 kind"},
				{Value: "2", Label: "2 kinds"},
				{Value: "3", Label: "3 kinds"},
				{Value: "4", Label: "All 4 kinds"},
			},
		},
	}, nil
}

// pamHasPwquality reports whether the PAM password stack uses pam_pwquality.
func pamHasPwquality(env *control.Env) (bool, error) {
	b, err := files.ReadOptional(env.Path(pwqPAM))
	if err != nil {
		return false, err
	}
	for l := range strings.SplitSeq(string(b), "\n") {
		l = strings.TrimSpace(l)
		if !strings.HasPrefix(l, "#") && strings.Contains(l, "pam_pwquality.so") {
			return true, nil
		}
	}
	return false, nil
}

func (p *passwordQuality) Check(_ context.Context, env *control.Env) (control.State, error) {
	b, err := files.ReadOptional(env.Path(pwqFile))
	if err != nil {
		return control.NotApplied, err
	}
	hasFile := strings.Contains(string(b), pwqMarker)
	inPAM, err := pamHasPwquality(env)
	if err != nil {
		return control.NotApplied, err
	}
	switch {
	case hasFile && inPAM:
		return control.Applied, nil
	case hasFile:
		return control.Partial, nil
	}
	return control.NotApplied, nil
}

func pwqContent(minlen, minclass int) string {
	var b strings.Builder
	b.WriteString(pwqMarker)
	b.WriteString("\n")
	fmt.Fprintf(&b, "minlen = %d\n", minlen)
	fmt.Fprintf(&b, "minclass = %d\n", minclass)
	b.WriteString("dictcheck = 1\n")
	b.WriteString("usercheck = 1\n")
	// The rules also apply when root sets a password.
	b.WriteString("enforce_for_root\n")
	return b.String()
}

func (p *passwordQuality) Apply(ctx context.Context, env *control.Env, in control.Values) error {
	if err := intInRange(8, 128)(in.String("minlen")); err != nil {
		return fmt.Errorf("minimum length: %w", err)
	}
	if err := intInRange(1, 4)(in.String("minclass")); err != nil {
		return fmt.Errorf("character kinds: %w", err)
	}
	minlen, _ := strconv.Atoi(in.String("minlen"))
	minclass, _ := strconv.Atoi(in.String("minclass"))

	// Remember what was there, so that a revert removes only what this control
	// added. This is done only the first time: on later runs the module may be
	// there because of this control.
	if _, recorded, err := env.Rec.Get(pwqID, "was-in-pam"); err != nil {
		return err
	} else if !recorded {
		wasInPAM, err := pamHasPwquality(env)
		if err != nil {
			return err
		}
		if err := env.Rec.Put(pwqID, "was-in-pam", yesNo(wasInPAM)); err != nil {
			return err
		}
	}
	if err := env.Rec.Backup(pwqID, env.Path(pwqFile)); err != nil {
		return err
	}
	if err := apt.Install(ctx, env, "libpam-pwquality"); err != nil {
		return err
	}
	// The package registers itself, but a profile that was switched off by hand
	// stays off. Make sure it is on.
	if _, err := env.Run.Run(ctx, "pam-auth-update", "--package", "--enable", pwqProfile); err != nil {
		return err
	}
	if err := files.WriteAtomic(env.Path(pwqFile), []byte(pwqContent(minlen, minclass)), 0o644); err != nil {
		return err
	}
	env.Log.Infof("new passwords need at least %d characters and %d kinds of characters", minlen, minclass)
	return env.Rec.Put(pwqID, "applied", "yes")
}

func (p *passwordQuality) Revert(ctx context.Context, env *control.Env) error {
	if !env.Rec.Has(pwqID) {
		env.Log.Warnf("%s: no record, leaving the password rules alone", pwqID)
		return nil
	}
	if _, err := env.Rec.Restore(pwqID, env.Path(pwqFile)); err != nil {
		return err
	}
	was, _, err := env.Rec.Get(pwqID, "was-in-pam")
	if err != nil {
		return err
	}
	if was != "yes" {
		if _, err := env.Run.Run(ctx, "pam-auth-update", "--package", "--remove", pwqProfile); err != nil {
			return err
		}
	}
	return env.Rec.Delete(pwqID)
}

func yesNo(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}
