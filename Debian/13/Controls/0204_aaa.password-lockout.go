// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Danang Galuh Tegar Prasetyo

package controls

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/danang-id/server-hardening/internal/control"
	"github.com/danang-id/server-hardening/internal/files"
)

const (
	lockID     = "aaa.password-lockout"
	lockConf   = "/etc/security/faillock.conf"
	lockMarker = "# Managed by github.com/danang-id/server-hardening (aaa.password-lockout)"
	lockPAM    = "/etc/pam.d/common-auth"

	// Debian 13 has no pam-auth-update profile for pam_faillock, so this control
	// brings its own. pam_faillock needs one line before pam_unix (preauth) and
	// one after it (authfail), and pam-auth-update places a profile at a single
	// position. That is why there are two profiles.
	lockProfilePre  = "server-hardening-faillock-preauth"
	lockProfileMain = "server-hardening-faillock"
	lockProfileDir  = "/usr/share/pam-configs/"
)

const lockPreauth = `Name: Count failed logins, check before authentication (server-hardening)
Default: no
Priority: 1024
Auth-Type: Primary
Auth:
	required	pam_faillock.so preauth
`

const lockMain = `Name: Count failed logins, lock the account (server-hardening)
Default: no
Priority: 16
Auth-Type: Primary
Auth:
	[default=die]	pam_faillock.so authfail
Account-Type: Additional
Account:
	required	pam_faillock.so
`

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

func pamHasFaillock(env *control.Env) (bool, error) {
	b, err := files.ReadOptional(env.Path(lockPAM))
	if err != nil {
		return false, err
	}
	for l := range strings.SplitSeq(string(b), "\n") {
		l = strings.TrimSpace(l)
		if !strings.HasPrefix(l, "#") && strings.Contains(l, "pam_faillock.so") {
			return true, nil
		}
	}
	return false, nil
}

func (p *passwordLockout) Check(_ context.Context, env *control.Env) (control.State, error) {
	b, err := files.ReadOptional(env.Path(lockConf))
	if err != nil {
		return control.NotApplied, err
	}
	if !strings.Contains(string(b), lockMarker) {
		return control.NotApplied, nil
	}
	inPAM, err := pamHasFaillock(env)
	if err != nil {
		return control.NotApplied, err
	}
	if !inPAM {
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

	// If pam_faillock is already in the stack and it is not ours (a manual edit,
	// for example), adding it again would count every failure twice.
	inPAM, err := pamHasFaillock(env)
	if err != nil {
		return err
	}
	ours := files.Exists(env.Path(lockProfileDir + lockProfileMain))
	if inPAM && !ours {
		return fmt.Errorf("pam_faillock is already in %s and was not added by this tool. Remove it first, or leave this control out", lockPAM)
	}
	old, err := files.ReadOptional(env.Path(lockConf))
	if err != nil {
		return err
	}
	if err := env.Rec.Backup(lockID, env.Path(lockConf)); err != nil {
		return err
	}
	for name, body := range map[string]string{lockProfilePre: lockPreauth, lockProfileMain: lockMain} {
		if err := files.WriteAtomic(env.Path(lockProfileDir+name), []byte(body), 0o644); err != nil {
			return err
		}
	}
	if err := files.WriteAtomic(env.Path(lockConf), []byte(lockConfContent(string(old), attempts, minutes)), 0o644); err != nil {
		return err
	}
	if _, err := env.Run.Run(ctx, "pam-auth-update", "--package", "--enable", lockProfilePre, lockProfileMain); err != nil {
		// Do not leave a half-built setup behind.
		_, _ = env.Rec.Restore(lockID, env.Path(lockConf))
		_ = os.Remove(env.Path(lockProfileDir + lockProfilePre))
		_ = os.Remove(env.Path(lockProfileDir + lockProfileMain))
		return fmt.Errorf("adding pam_faillock to the PAM stack: %w", err)
	}
	env.Log.Infof("accounts lock for %d minutes after %d failed attempts (root is never locked)", minutes, attempts)
	return env.Rec.Put(lockID, "applied", "yes")
}

func (p *passwordLockout) Revert(ctx context.Context, env *control.Env) error {
	if !env.Rec.Has(lockID) {
		env.Log.Warnf("%s: no record, leaving the account lockout alone", lockID)
		return nil
	}
	if _, err := env.Run.Run(ctx, "pam-auth-update", "--package", "--remove", lockProfilePre, lockProfileMain); err != nil {
		return err
	}
	for _, n := range []string{lockProfilePre, lockProfileMain} {
		if err := os.Remove(env.Path(lockProfileDir + n)); err != nil && !os.IsNotExist(err) {
			return err
		}
	}
	if _, err := env.Rec.Restore(lockID, env.Path(lockConf)); err != nil {
		return err
	}
	return env.Rec.Delete(lockID)
}
