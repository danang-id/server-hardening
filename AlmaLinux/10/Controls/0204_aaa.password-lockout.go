// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Danang Galuh Tegar Prasetyo

package controls

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/danang-id/server-hardening/internal/control"
	"github.com/danang-id/server-hardening/internal/files"
)

const (
	lockID      = "aaa.password-lockout"
	lockConf    = "/etc/security/faillock.conf"
	lockMarker  = "# Managed by github.com/danang-id/server-hardening (aaa.password-lockout)"
	lockFeature = "with-faillock" // the authselect feature that puts pam_faillock into the stack
)

type passwordLockout struct{ control.Base }

func init() {
	System.Add(&passwordLockout{control.Base{M: control.Meta{
		ID:       lockID,
		Category: control.AAA,
		Number:   4,
		Title:    "Lock accounts after failed password attempts",
		Default:  true,
		Tags:     []control.Tag{control.TagLockout, control.TagInput},
	}}})
}

func (p *passwordLockout) Inputs(context.Context, *control.Env) ([]control.Input, error) {
	return []control.Input{
		{Key: "attempts", Label: "Failed attempts before the account is locked", Default: "5", Validate: intInRange(1, 99)},
		{Key: "minutes", Label: "Lock time in minutes (failures are counted over the same time)", Default: "15", Validate: intInRange(1, 1440)},
	}, nil
}

// authselectFeatures lists the features that the current authselect profile
// has switched on. It fails when authselect does not manage the PAM files.
func authselectFeatures(ctx context.Context, env *control.Env) ([]string, error) {
	out, err := env.Run.Run(ctx, "authselect", "current", "--raw")
	if err != nil {
		return nil, fmt.Errorf("authselect does not manage the PAM files of this system, so the lockout cannot be set up safely: %w", err)
	}
	f := strings.Fields(string(out))
	if len(f) == 0 {
		return nil, nil
	}
	return f[1:], nil // the first word is the profile
}

func hasFeature(features []string, name string) bool {
	for _, f := range features {
		if f == name {
			return true
		}
	}
	return false
}

func (p *passwordLockout) Check(ctx context.Context, env *control.Env) (control.State, error) {
	b, err := files.ReadOptional(env.Path(lockConf))
	if err != nil {
		return control.NotApplied, err
	}
	if !strings.Contains(string(b), lockMarker) {
		return control.NotApplied, nil
	}
	features, err := authselectFeatures(ctx, env)
	if err != nil || !hasFeature(features, lockFeature) {
		return control.Partial, nil
	}
	return control.Applied, nil
}

// lockKeys are the settings this control owns in faillock.conf.
var lockKeys = []string{"deny", "fail_interval", "unlock_time", "even_deny_root", "root_unlock_time"}

// lockConfContent keeps the existing file and replaces only the settings this
// control owns, so the admin's other settings (such as "dir") survive.
func lockConfContent(old string, attempts, minutes int) string {
	var keep []string
	for l := range strings.SplitSeq(strings.TrimRight(old, "\n"), "\n") {
		t := strings.TrimSpace(l)
		if t == lockMarker || strings.HasPrefix(t, "# even_deny_root is not set") {
			continue
		}
		key := strings.TrimSpace(strings.SplitN(strings.SplitN(t, "=", 2)[0], " ", 2)[0])
		owned := false
		for _, k := range lockKeys {
			if key == k && !strings.HasPrefix(t, "#") {
				owned = true
			}
		}
		if !owned {
			keep = append(keep, l)
		}
	}
	for len(keep) > 0 && strings.TrimSpace(keep[len(keep)-1]) == "" {
		keep = keep[:len(keep)-1]
	}
	var b strings.Builder
	if len(keep) > 0 {
		b.WriteString(strings.Join(keep, "\n"))
		b.WriteString("\n\n")
	}
	b.WriteString(lockMarker)
	b.WriteString("\n")
	fmt.Fprintf(&b, "deny = %d\n", attempts)
	fmt.Fprintf(&b, "fail_interval = %d\n", minutes*60)
	fmt.Fprintf(&b, "unlock_time = %d\n", minutes*60)
	b.WriteString("# even_deny_root is not set, so root is never locked and the console stays usable.\n")
	return b.String()
}

func (p *passwordLockout) Apply(ctx context.Context, env *control.Env, in control.Values) error {
	if err := intInRange(1, 99)(in.String("attempts")); err != nil {
		return fmt.Errorf("attempts: %w", err)
	}
	if err := intInRange(1, 1440)(in.String("minutes")); err != nil {
		return fmt.Errorf("lock time: %w", err)
	}
	attempts, _ := strconv.Atoi(in.String("attempts"))
	minutes, _ := strconv.Atoi(in.String("minutes"))

	features, err := authselectFeatures(ctx, env)
	if err != nil {
		return err
	}
	// Remember whether the feature was on before this tool, the first time only.
	// Applying again must not turn "was there before" into "added by this tool".
	if _, recorded, err := env.Rec.Get(lockID, "feature-was-on"); err != nil {
		return err
	} else if !recorded {
		if err := env.Rec.Put(lockID, "feature-was-on", yesNo(hasFeature(features, lockFeature))); err != nil {
			return err
		}
	}
	old, err := files.ReadOptional(env.Path(lockConf))
	if err != nil {
		return err
	}
	if err := env.Rec.Backup(lockID, env.Path(lockConf)); err != nil {
		return err
	}
	if err := files.WriteAtomic(env.Path(lockConf), []byte(lockConfContent(string(old), attempts, minutes)), 0o644); err != nil {
		return err
	}
	if !hasFeature(features, lockFeature) {
		if _, err := env.Run.Run(ctx, "authselect", "enable-feature", lockFeature); err != nil {
			// Do not leave a half-built setup behind.
			_, _ = env.Rec.Restore(lockID, env.Path(lockConf))
			return fmt.Errorf("adding pam_faillock to the PAM stack: %w", err)
		}
	}
	env.Log.Infof("accounts lock for %d minutes after %d failed attempts (root is never locked)", minutes, attempts)
	return env.Rec.Put(lockID, "applied", "yes")
}

func (p *passwordLockout) Revert(ctx context.Context, env *control.Env) error {
	if !env.Rec.Has(lockID) {
		env.Log.Warnf("%s: no record, leaving the account lockout alone", lockID)
		return nil
	}
	if was, _, err := env.Rec.Get(lockID, "feature-was-on"); err != nil {
		return err
	} else if was != "yes" {
		features, err := authselectFeatures(ctx, env)
		if err != nil {
			return err
		}
		if hasFeature(features, lockFeature) {
			if _, err := env.Run.Run(ctx, "authselect", "disable-feature", lockFeature); err != nil {
				return fmt.Errorf("taking pam_faillock out of the PAM stack: %w", err)
			}
		}
	}
	if _, err := env.Rec.Restore(lockID, env.Path(lockConf)); err != nil {
		return err
	}
	return env.Rec.Delete(lockID)
}
