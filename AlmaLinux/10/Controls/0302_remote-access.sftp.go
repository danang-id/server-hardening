// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Danang Galuh Tegar Prasetyo

package controls

import (
	"context"

	"github.com/danang-id/server-hardening/internal/control"
)

const sftpID = "remote-access.sftp"

type sftp struct{ control.Base }

func init() {
	System.Add(&sftp{control.Base{M: control.Meta{
		ID:           sftpID,
		Category:     control.RemoteAccess,
		Number:       2,
		Title:        "Enable SFTP (and therefore `scp`)",
		Default:      true,
		RevertLimits: "openssh-server stays installed.",
	}}})
}

var sftpDirectives = []directive{{"Subsystem", "sftp internal-sftp"}}

func (s *sftp) Check(ctx context.Context, env *control.Env) (control.State, error) {
	return sshdCheck(ctx, env, sftpID, "sftp")
}

func (s *sftp) Apply(ctx context.Context, env *control.Env, _ control.Values) error {
	if err := sshdApply(ctx, env, sftpID, "sftp", sftpDirectives); err != nil {
		return err
	}
	env.Log.Infof("sftp and scp work")
	return nil
}

func (s *sftp) Revert(ctx context.Context, env *control.Env) error {
	return sshdRevert(ctx, env, sftpID, "sftp")
}
