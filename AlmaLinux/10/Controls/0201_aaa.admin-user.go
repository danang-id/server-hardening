// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Danang Galuh Tegar Prasetyo

package controls

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/danang-id/server-hardening/internal/accounts"
	"github.com/danang-id/server-hardening/internal/control"
	"github.com/danang-id/server-hardening/internal/dnf"
)

const (
	adminUserID = accounts.AdminUserID
	// homeMode is the mode of the home directory of an account this control creates.
	homeMode os.FileMode = 0o700
)

type adminUser struct{ control.Base }

func init() {
	System.Add(&adminUser{control.Base{M: control.Meta{
		ID:             adminUserID,
		Category:       control.AAA,
		Number:         1,
		Title:          "Create a named administrator account",
		Default:        true,
		Tags:           []control.Tag{control.TagInput, control.TagIrreversible},
		NoRevertReason: "Deleting an account automatically could strand the server or destroy data. Remove it by hand if you need to.",
	}}})
}

func validUserName(s string) error { return accounts.ValidUserName(s) }

func (a *adminUser) Inputs(context.Context, *control.Env) ([]control.Input, error) {
	// The user who started the tool, when it was started with sudo.
	def := os.Getenv("SUDO_USER")
	if def == "root" || validUserName(def) != nil {
		def = ""
	}
	return []control.Input{
		{
			Key:      "username",
			Label:    "Administrator username",
			Help:     "The account you will work with from now on.",
			Default:  def,
			Validate: validUserName,
		},
		{
			Key:   "password",
			Label: "Password for this account",
			Help:  "Leave empty to create the account with a locked password. That only works with a sudo policy that does not ask for a password.",
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

func (a *adminUser) Check(_ context.Context, env *control.Env) (control.State, error) {
	admins, err := adminAccounts(env)
	if err != nil || len(admins) == 0 {
		return control.NotApplied, err
	}
	return control.Applied, nil
}

func (a *adminUser) Apply(ctx context.Context, env *control.Env, in control.Values) error {
	name, pw := in.String("username"), in.String("password")
	if err := validUserName(name); err != nil {
		return err
	}
	if strings.ContainsAny(pw, "\r\n") {
		return fmt.Errorf("a password cannot contain a line break")
	}
	acc, exists, err := findAccount(env, name)
	if err != nil {
		return err
	}
	if exists && acc.UID < firstHumanUID {
		return fmt.Errorf("%s is a system account (user ID %d). Pick another name", name, acc.UID)
	}
	// Installing sudo first makes sure sudo is there for the wheel group.
	if err := dnf.Install(ctx, env, "sudo"); err != nil {
		return err
	}
	if exists {
		member, err := inGroup(env, adminGroup, name)
		if err != nil {
			return err
		}
		if member {
			env.Log.Infof("%s already exists and is in the %s group", name, adminGroup)
		} else {
			env.Log.Infof("%s already exists, adding it to the %s group", name, adminGroup)
			if _, err := env.Run.Run(ctx, "usermod", "-aG", adminGroup, name); err != nil {
				return err
			}
		}
	} else {
		env.Log.Infof("creating the account %s", name)
		if _, err := env.Run.Run(ctx, "useradd", "--create-home", "--shell", "/bin/bash", "--groups", adminGroup, name); err != nil {
			return err
		}
		// Only the owner may enter the home directory, whatever the system default.
		if acc, ok, err := findAccount(env, name); err != nil {
			return err
		} else if ok {
			if err := os.Chmod(env.Path(acc.Home), homeMode); err != nil {
				return fmt.Errorf("setting the mode of the home directory: %w", err)
			}
		}
	}
	switch {
	case pw != "":
		// The password goes in on standard input, never in the arguments.
		if _, err := env.Run.RunStdin(ctx, name+":"+pw+"\n", "chpasswd"); err != nil {
			return fmt.Errorf("setting the password of %s: %w", name, err)
		}
		env.Log.Infof("password of %s is set", name)
	case exists:
		env.Log.Infof("the password of %s is unchanged", name)
	default:
		env.Log.Warnf("%s has a locked password: use SSH keys, and a sudo policy that does not ask for a password", name)
	}
	// Later controls (SSH keys, sudo policy) need to know which account it is.
	if err := env.Rec.Put(adminUserID, "user", name); err != nil {
		return err
	}
	created := "no"
	if !exists {
		created = "yes"
	}
	return env.Rec.Put(adminUserID, "created", created)
}

func (a *adminUser) Revert(context.Context, *control.Env) error { return control.ErrNoRevert }
