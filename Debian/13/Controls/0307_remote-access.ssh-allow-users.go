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
)

const allowUsersID = "remote-access.ssh-allow-users"

type sshAllowUsers struct{ control.Base }

func init() {
	System.Add(&sshAllowUsers{control.Base{M: control.Meta{
		ID:       allowUsersID,
		Category: control.RemoteAccess,
		Number:   7,
		Title:    "Allow only listed users to use SSH",
		Default:  true,
		Requires: []string{adminUserID},
		Tags:     []control.Tag{control.TagInput, control.TagLockout},
	}}})
}

// An account name as the system allows it. Patterns (* ? @) are not accepted,
// so a name always means exactly one account.
var plainUserName = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9._-]{0,31}$`)

func parseUserList(s string) []string {
	var out []string
	seen := map[string]bool{}
	for _, n := range strings.Fields(strings.ReplaceAll(s, ",", " ")) {
		if !seen[n] {
			seen[n] = true
			out = append(out, n)
		}
	}
	return out
}

func (a *sshAllowUsers) Inputs(_ context.Context, env *control.Env) ([]control.Input, error) {
	// Suggest the administrator account, or the one that started the tool.
	def := ""
	if admins, err := adminAccounts(env); err == nil && len(admins) > 0 {
		def = strings.Join(admins, " ")
	} else if u := os.Getenv("SUDO_USER"); u != "" && u != "root" {
		def = u
	}
	return []control.Input{{
		Key:     "users",
		Label:   "Users allowed to log in over SSH (names separated by spaces)",
		Help:    "Leave empty to allow only the administrator account. Everyone else, including root, is refused unless listed.",
		Default: def, Optional: true,
		Validate: func(s string) error {
			for _, n := range parseUserList(s) {
				if !plainUserName.MatchString(n) {
					return fmt.Errorf("%q is not a plain account name", n)
				}
			}
			return nil
		},
	}}, nil
}

func (a *sshAllowUsers) Check(ctx context.Context, env *control.Env) (control.State, error) {
	return sshdCheck(ctx, env, allowUsersID, "allow-users")
}

func (a *sshAllowUsers) Apply(ctx context.Context, env *control.Env, in control.Values) error {
	admins, err := adminAccounts(env)
	if err != nil {
		return err
	}
	names := parseUserList(in.String("users"))
	if len(names) == 0 {
		names = admins
	}
	if len(names) == 0 {
		return fmt.Errorf("there is no user to allow. Apply %s first, or list the users", adminUserID)
	}
	for _, n := range names {
		if !plainUserName.MatchString(n) {
			return fmt.Errorf("%q is not a plain account name", n)
		}
		if _, ok, err := findAccount(env, n); err != nil {
			return err
		} else if !ok {
			return fmt.Errorf("the account %q does not exist", n)
		}
	}
	// The list must keep the way back in: an administrator account, and the
	// account the user is logged in with now.
	listed := map[string]bool{}
	for _, n := range names {
		listed[n] = true
	}
	hasAdmin := false
	for _, a := range admins {
		if listed[a] {
			hasAdmin = true
		}
	}
	if !hasAdmin {
		return fmt.Errorf("the list leaves out the administrator account (%s)", strings.Join(admins, ", "))
	}
	if u := os.Getenv("SUDO_USER"); u != "" && u != "root" && !listed[u] {
		return fmt.Errorf("the list leaves out %s, the account that started this tool", u)
	}
	if err := sshdApply(ctx, env, allowUsersID, "allow-users", []directive{{"AllowUsers", strings.Join(names, " ")}}); err != nil {
		return err
	}
	env.Log.Infof("only %s can log in over SSH", strings.Join(names, ", "))
	return nil
}

func (a *sshAllowUsers) Revert(ctx context.Context, env *control.Env) error {
	return sshdRevert(ctx, env, allowUsersID, "allow-users")
}
