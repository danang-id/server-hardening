// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Danang Galuh Tegar Prasetyo

package controls

import (
	"context"
	"fmt"
	"strings"

	"github.com/danang-id/server-hardening/internal/control"
)

const noRootID = "remote-access.ssh-no-root-login"

type sshNoRootLogin struct{ control.Base }

func init() {
	System.Add(&sshNoRootLogin{control.Base{M: control.Meta{
		ID:       noRootID,
		Category: control.RemoteAccess,
		Number:   8,
		Title:    "Disable root login over SSH",
		Default:  true,
		Requires: []string{adminUserID, sudoID, authKeyID},
		Tags:     []control.Tag{control.TagLockout},
	}}})
}

var noRootDirectives = []directive{{"PermitRootLogin", "no"}}

func (n *sshNoRootLogin) Check(ctx context.Context, env *control.Env) (control.State, error) {
	return sshdCheck(ctx, env, noRootID, "no-root-login")
}

func (n *sshNoRootLogin) Apply(ctx context.Context, env *control.Env, _ control.Values) error {
	// Root login is the way back in, so make sure one administrator account can
	// log in with a key and use sudo.
	admins, err := adminAccounts(env)
	if err != nil {
		return err
	}
	var reasons []string
	ready := false
	for _, a := range admins {
		if has, err := accountHasKey(env, a); err != nil {
			return err
		} else if !has {
			reasons = append(reasons, a+" has no SSH key")
			continue
		}
		if err := adminCanSudo(env, a); err != nil {
			reasons = append(reasons, a+": "+err.Error())
			continue
		}
		ready = true
		break
	}
	if !ready {
		if len(admins) == 0 {
			reasons = []string{"there is no administrator account"}
		}
		return fmt.Errorf("no administrator account can log in with a key and use sudo, so root login is still needed (%s). "+
			"Apply %s, %s and %s first", strings.Join(reasons, "; "), adminUserID, sudoID, authKeyID)
	}
	if err := sshdApply(ctx, env, noRootID, "no-root-login", noRootDirectives); err != nil {
		return err
	}
	env.Log.Infof("root cannot log in over SSH")
	return nil
}

func (n *sshNoRootLogin) Revert(ctx context.Context, env *control.Env) error {
	return sshdRevert(ctx, env, noRootID, "no-root-login")
}
