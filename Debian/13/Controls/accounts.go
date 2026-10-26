// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Danang Galuh Tegar Prasetyo

package controls

import (
	"github.com/danang-id/server-hardening/internal/accounts"
	"github.com/danang-id/server-hardening/internal/control"
)

// Short names for internal/accounts, which every system shares. Debian lets
// the members of the sudo group use sudo.

const (
	adminGroup = "sudo"
	// firstHumanUID is the first user ID of a normal (non-system) account.
	firstHumanUID = accounts.FirstHumanUID
)

var admins = accounts.Admins{Group: adminGroup}

type account = accounts.Account

func readPasswd(env *control.Env) ([]account, error) { return accounts.ReadPasswd(env) }

func findAccount(env *control.Env, name string) (account, bool, error) {
	return accounts.Find(env, name)
}

func inGroup(env *control.Env, group, user string) (bool, error) {
	return accounts.InGroup(env, group, user)
}

func shadowHash(env *control.Env, user string) (string, bool, error) {
	return accounts.ShadowHash(env, user)
}

func usablePassword(hash string) bool { return accounts.UsablePassword(hash) }

func adminAccounts(env *control.Env) ([]string, error) { return admins.Accounts(env) }

func plannedAdmin(env *control.Env) string { return admins.Planned(env) }

func expectedAdmins(env *control.Env) ([]string, error) { return admins.Expected(env) }

func oneAdmin(env *control.Env) (account, error) { return admins.One(env) }

func adminCanSudo(env *control.Env, user string) error { return admins.CanSudo(env, user) }
