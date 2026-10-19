// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Danang Galuh Tegar Prasetyo

package controls

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/danang-id/server-hardening/internal/apt"
	"github.com/danang-id/server-hardening/internal/control"
	"github.com/danang-id/server-hardening/internal/files"
)

const (
	sudoID     = "aaa.sudo-policy"
	sudoFile   = "/etc/sudoers.d/99-server-hardening"
	sudoMarker = "# Managed by github.com/danang-id/server-hardening (aaa.sudo-policy)"
	// sudo skips files in sudoers.d whose name contains a dot. That makes it
	// safe to keep a file there until visudo has checked it.
	sudoTemp = sudoFile + ".tmp"
)

type sudoPolicy struct{ control.Base }

func init() {
	System.Add(&sudoPolicy{control.Base{M: control.Meta{
		ID:           sudoID,
		Category:     control.AAA,
		Number:       3,
		Title:        "Set how administrators gain root",
		Default:      true,
		Requires:     []string{adminUserID},
		Tags:         []control.Tag{control.TagInput},
		RevertLimits: "The sudo package stays installed.",
	}}})
}

const (
	policyOwn  = "own"
	policyNone = "none"
	policyRoot = "root"
)

func (s *sudoPolicy) Inputs(context.Context, *control.Env) ([]control.Input, error) {
	return []control.Input{
		{
			Key:   "policy",
			Label: "How should administrators gain root with sudo?",
			Kind:  control.Choice, Default: policyOwn,
			Options: []control.Option{
				{Value: policyOwn, Label: "With their own password", Help: "The account needs a password (set in the administrator account step)."},
				{Value: policyNone, Label: "With no password", Help: "Anyone with a shell on the admin account gets root."},
				{Value: policyRoot, Label: "With root's password", Help: "sudo asks for root's password. Root must have one."},
			},
		},
		{
			Key:   "root-password",
			Label: "Root's password (only for the root password policy)",
			Help:  "Leave empty to keep root's current password, or if you chose another policy.",
			Kind:  control.Secret, Confirm: true, Optional: true,
			Validate: func(s string) error {
				if strings.ContainsAny(s, "\r\n") {
					return fmt.Errorf("a password cannot contain a line break")
				}
				return nil
			},
		},
	}, nil
}

func sudoContent(policy string) (string, error) {
	var b strings.Builder
	b.WriteString(sudoMarker)
	b.WriteString("\n")
	b.WriteString("# sudo runs commands in their own pseudo-terminal and remembers a password for\n")
	b.WriteString("# five minutes. Every use is logged to the system log (the journal).\n")
	b.WriteString("Defaults use_pty\n")
	b.WriteString("Defaults timestamp_timeout=5\n")
	switch policy {
	case policyOwn:
		// Explicit PASSWD: this file sorts last, so it also overrides an earlier
		// NOPASSWD rule such as the one cloud-init writes.
		b.WriteString("%sudo ALL=(ALL:ALL) PASSWD: ALL\n")
	case policyNone:
		b.WriteString("%sudo ALL=(ALL:ALL) NOPASSWD: ALL\n")
	case policyRoot:
		b.WriteString("Defaults:%sudo rootpw\n")
		b.WriteString("%sudo ALL=(ALL:ALL) PASSWD: ALL\n")
	default:
		return "", fmt.Errorf("unknown policy %q", policy)
	}
	return b.String(), nil
}

func (s *sudoPolicy) Check(ctx context.Context, env *control.Env) (control.State, error) {
	b, err := files.ReadOptional(env.Path(sudoFile))
	if err != nil || !strings.Contains(string(b), sudoMarker) {
		return control.NotApplied, err
	}
	if _, err := env.Run.Run(ctx, "visudo", "-c"); err != nil {
		return control.Partial, nil
	}
	return control.Applied, nil
}

// checkPolicyCanWork stops before any change when the chosen policy would
// leave nobody able to use sudo.
func checkPolicyCanWork(env *control.Env, policy, rootPW string) error {
	switch policy {
	case policyOwn:
		admins, err := adminAccounts(env)
		if err != nil {
			return err
		}
		for _, a := range admins {
			if h, ok, err := shadowHash(env, a); err != nil {
				return err
			} else if ok && usablePassword(h) {
				return nil
			}
		}
		return fmt.Errorf("no administrator account has a password, so sudo with the account's own password would never work. " +
			"Set a password in the administrator account step, or choose another policy")
	case policyRoot:
		if rootPW != "" {
			return nil
		}
		h, _, err := shadowHash(env, "root")
		if err != nil {
			return err
		}
		if !usablePassword(h) {
			return fmt.Errorf("root has no usable password (it is locked), so sudo would reject every attempt. " +
				"Enter a password for root, or choose another policy")
		}
	}
	return nil
}

func (s *sudoPolicy) Apply(ctx context.Context, env *control.Env, in control.Values) error {
	policy, rootPW := in.String("policy"), in.String("root-password")
	content, err := sudoContent(policy)
	if err != nil {
		return err
	}
	if strings.ContainsAny(rootPW, "\r\n") {
		return fmt.Errorf("a password cannot contain a line break")
	}
	if policy != policyRoot && rootPW != "" {
		env.Log.Warnf("a root password was given but the policy is not \"root password\", so root's password is left alone")
		rootPW = ""
	}
	if err := checkPolicyCanWork(env, policy, rootPW); err != nil {
		return err
	}
	if err := apt.Install(ctx, env, "sudo"); err != nil {
		return err
	}

	// Write beside the final file, let visudo check it, and only then activate.
	tmp := env.Path(sudoTemp)
	if err := files.WriteAtomic(tmp, []byte(content), 0o440); err != nil {
		return err
	}
	if _, err := env.Run.Run(ctx, "visudo", "-cf", tmp); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("the sudo policy did not pass the syntax check, nothing was changed: %w", err)
	}

	if rootPW != "" {
		if err := setRootPassword(ctx, env, rootPW); err != nil {
			_ = os.Remove(tmp)
			return err
		}
	}
	if err := env.Rec.Backup(sudoID, env.Path(sudoFile)); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, env.Path(sudoFile)); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err := os.Chmod(env.Path(sudoFile), 0o440); err != nil {
		return err
	}

	env.Log.Infof("sudo policy is set: %s", map[string]string{
		policyOwn: "administrators use their own password", policyNone: "administrators need no password",
		policyRoot: "administrators use root's password",
	}[policy])
	return env.Rec.Put(sudoID, "policy", policy)
}

// setRootPassword sets root's password and remembers the old password field,
// the first time only, so that a revert can put it back.
func setRootPassword(ctx context.Context, env *control.Env, pw string) error {
	if _, recorded, err := env.Rec.Get(sudoID, "root-shadow"); err != nil {
		return err
	} else if !recorded {
		h, _, err := shadowHash(env, "root")
		if err != nil {
			return err
		}
		if err := env.Rec.Put(sudoID, "root-shadow", h); err != nil {
			return err
		}
	}
	if _, err := env.Run.RunStdin(ctx, "root:"+pw+"\n", "chpasswd"); err != nil {
		return fmt.Errorf("setting root's password: %w", err)
	}
	env.Log.Infof("root's password is set")
	return nil
}

func (s *sudoPolicy) Revert(ctx context.Context, env *control.Env) error {
	if !env.Rec.Has(sudoID) {
		env.Log.Warnf("%s: no record, leaving the sudo policy alone", sudoID)
		return nil
	}
	// Take the drop-in out, then make sure sudo still reads a valid
	// configuration. If not, put the drop-in back and stop.
	cur, err := files.ReadOptional(env.Path(sudoFile))
	if err != nil {
		return err
	}
	if _, err := env.Rec.Restore(sudoID, env.Path(sudoFile)); err != nil {
		return err
	}
	if _, err := env.Run.Run(ctx, "visudo", "-c"); err != nil {
		if cur != nil {
			_ = files.WriteAtomic(env.Path(sudoFile), cur, 0o440)
		}
		return fmt.Errorf("sudo does not accept its configuration without the policy, the policy was put back: %w", err)
	}
	if h, ok, err := env.Rec.Get(sudoID, "root-shadow"); err != nil {
		return err
	} else if ok {
		if h == "" {
			_, err = env.Run.Run(ctx, "passwd", "-d", "root")
		} else {
			// chpasswd -e takes the stored hash, which also keeps it off the
			// command line.
			_, err = env.Run.RunStdin(ctx, "root:"+h+"\n", "chpasswd", "-e")
		}
		if err != nil {
			return fmt.Errorf("restoring root's password: %w", err)
		}
		env.Log.Infof("root's previous password is back")
	}
	return env.Rec.Delete(sudoID)
}
