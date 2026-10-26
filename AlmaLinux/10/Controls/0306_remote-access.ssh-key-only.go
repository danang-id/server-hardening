// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Danang Galuh Tegar Prasetyo

package controls

import (
	"context"
	"fmt"

	"github.com/danang-id/server-hardening/internal/control"
)

const keyOnlyID = "remote-access.ssh-key-only"

type sshKeyOnly struct{ control.Base }

func init() {
	System.Add(&sshKeyOnly{control.Base{M: control.Meta{
		ID:           keyOnlyID,
		Category:     control.RemoteAccess,
		Number:       6,
		Title:        "Disable password login over SSH",
		Default:      true,
		Requires:     []string{adminUserID, authKeyID},
		Tags:         []control.Tag{control.TagLockout},
		RevertLimits: "If another file, such as a provider's, enables passwords, they work again.",
	}}})
}

var keyOnlyDirectives = []directive{
	{"PasswordAuthentication", "no"},
	{"KbdInteractiveAuthentication", "no"},
	{"PubkeyAuthentication", "yes"},
}

func (k *sshKeyOnly) Check(ctx context.Context, env *control.Env) (control.State, error) {
	return sshdCheck(ctx, env, keyOnlyID, "key-only")
}

func (k *sshKeyOnly) Apply(ctx context.Context, env *control.Env, _ control.Values) error {
	// Never switch passwords off when no key could log in.
	has, err := adminHasKey(env)
	if err != nil {
		return err
	}
	if !has {
		return fmt.Errorf("no administrator account has an SSH key, so switching passwords off would lock you out. Apply %s first", authKeyID)
	}
	if err := sshdApply(ctx, env, keyOnlyID, "key-only", keyOnlyDirectives); err != nil {
		return err
	}
	env.Log.Infof("SSH accepts keys only")
	return nil
}

func (k *sshKeyOnly) Revert(ctx context.Context, env *control.Env) error {
	return sshdRevert(ctx, env, keyOnlyID, "key-only")
}
