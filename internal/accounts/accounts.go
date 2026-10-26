// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Danang Galuh Tegar Prasetyo

// Package accounts reads the account files (/etc/passwd, /etc/group,
// /etc/shadow) and answers the questions the controls ask about the
// administrator. It reads the files under env.Root, so it works in tests.
package accounts

import (
	"bufio"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"

	"github.com/danang-id/server-hardening/internal/control"
	"github.com/danang-id/server-hardening/internal/files"
)

// The IDs and answers that other controls look up in the records.
const (
	AdminUserID = "aaa.admin-user"
	SudoID      = "aaa.sudo-policy"
	PolicyOwn   = "own"
	PolicyNone  = "none"
	PolicyRoot  = "root"
)

// FirstHumanUID is the first user ID of a normal (non-system) account.
const FirstHumanUID = 1000

// Account is one line of /etc/passwd.
type Account struct {
	Name  string
	UID   int
	GID   int
	Home  string
	Shell string
}

// colonLines returns the non-comment lines of a colon-separated file, split
// into fields. A missing file gives no lines.
func colonLines(path string) ([][]string, error) {
	f, err := os.Open(path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out [][]string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		l := strings.TrimSpace(sc.Text())
		if l == "" || strings.HasPrefix(l, "#") {
			continue
		}
		out = append(out, strings.Split(l, ":"))
	}
	return out, sc.Err()
}

// ReadPasswd reads every account.
func ReadPasswd(env *control.Env) ([]Account, error) {
	rows, err := colonLines(env.Path("/etc/passwd"))
	if err != nil {
		return nil, err
	}
	var out []Account
	for _, f := range rows {
		if len(f) < 7 {
			continue
		}
		uid, _ := strconv.Atoi(f[2])
		gid, _ := strconv.Atoi(f[3])
		out = append(out, Account{Name: f[0], UID: uid, GID: gid, Home: f[5], Shell: f[6]})
	}
	return out, nil
}

// Find looks an account up by name.
func Find(env *control.Env, name string) (Account, bool, error) {
	all, err := ReadPasswd(env)
	if err != nil {
		return Account{}, false, err
	}
	for _, a := range all {
		if a.Name == name {
			return a, true, nil
		}
	}
	return Account{}, false, nil
}

// GroupMembers lists the users named as members of a group.
func GroupMembers(env *control.Env, group string) ([]string, error) {
	rows, err := colonLines(env.Path("/etc/group"))
	if err != nil {
		return nil, err
	}
	for _, f := range rows {
		if len(f) >= 4 && f[0] == group {
			var out []string
			for m := range strings.SplitSeq(f[3], ",") {
				if m = strings.TrimSpace(m); m != "" {
					out = append(out, m)
				}
			}
			return out, nil
		}
	}
	return nil, nil
}

// InGroup reports whether a user is named as a member of a group.
func InGroup(env *control.Env, group, user string) (bool, error) {
	m, err := GroupMembers(env, group)
	if err != nil {
		return false, err
	}
	for _, x := range m {
		if x == user {
			return true, nil
		}
	}
	return false, nil
}

// ShadowHash returns the password field of an account.
func ShadowHash(env *control.Env, user string) (string, bool, error) {
	rows, err := colonLines(env.Path("/etc/shadow"))
	if err != nil {
		return "", false, err
	}
	for _, f := range rows {
		if len(f) >= 2 && f[0] == user {
			return f[1], true, nil
		}
	}
	return "", false, nil
}

// UsablePassword reports whether a password field holds a real password.
// An empty field, "!", "*" and anything starting with "!" or "*" do not.
func UsablePassword(hash string) bool {
	return hash != "" && !strings.HasPrefix(hash, "!") && !strings.HasPrefix(hash, "*")
}

// The rule for new names is a lowercase letter first, then letters, digits,
// "_" and "-". 32 characters is the limit of the system.
var userName = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,31}$`)

// ValidUserName says why a name cannot be used for a new account, or nil.
func ValidUserName(s string) error {
	if s == "root" {
		return fmt.Errorf("pick a name other than root")
	}
	if !userName.MatchString(s) {
		return fmt.Errorf("use lowercase letters, digits, - and _, starting with a letter (at most 32 characters)")
	}
	return nil
}

// Admins answers the questions about administrators for a system. Group is
// the group whose members may use sudo: "sudo" on Debian, "wheel" on the Red
// Hat family.
type Admins struct{ Group string }

// Accounts lists the accounts that can use sudo: the one this tool created or
// confirmed (if it still exists), otherwise the normal accounts in the admin
// group. Root is never listed.
func (a Admins) Accounts(env *control.Env) ([]string, error) {
	if u, ok, err := env.Rec.Get(AdminUserID, "user"); err != nil {
		return nil, err
	} else if ok {
		if _, exists, err := Find(env, u); err != nil {
			return nil, err
		} else if exists {
			return []string{u}, nil
		}
	}
	members, err := GroupMembers(env, a.Group)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, m := range members {
		acc, exists, err := Find(env, m)
		if err != nil {
			return nil, err
		}
		if exists && acc.UID >= FirstHumanUID {
			out = append(out, m)
		}
	}
	return out, nil
}

// Planned returns the name of the administrator account that this run is
// about to create, taken from the answer to aaa.admin-user, or "" when that
// control is not part of the run. The questions come before anything runs, so
// the account is not in /etc/passwd yet when they are built.
func (Admins) Planned(env *control.Env) string {
	name := strings.TrimSpace(env.Answered[AdminUserID].String("username"))
	if ValidUserName(name) != nil {
		return ""
	}
	return name
}

// Expected lists the administrator accounts that will exist once the run has
// finished: the one it is about to create, or else those that exist now.
func (a Admins) Expected(env *control.Env) ([]string, error) {
	if p := a.Planned(env); p != "" {
		return []string{p}, nil
	}
	return a.Accounts(env)
}

// One returns the single administrator account that later controls (SSH
// keys, SSH settings) work for.
func (a Admins) One(env *control.Env) (Account, error) {
	admins, err := a.Accounts(env)
	if err != nil {
		return Account{}, err
	}
	switch len(admins) {
	case 0:
		return Account{}, fmt.Errorf("there is no administrator account. Apply %s first", AdminUserID)
	case 1:
		acc, _, err := Find(env, admins[0])
		return acc, err
	}
	return Account{}, fmt.Errorf("there is more than one administrator account (%s). "+
		"Apply %s in this tool and choose the one to use", strings.Join(admins, ", "), AdminUserID)
}

// CanSudo reports why an account could not use sudo, or nil.
func (a Admins) CanSudo(env *control.Env, user string) error {
	if ok, err := InGroup(env, a.Group, user); err != nil {
		return err
	} else if !ok {
		return fmt.Errorf("%s is not in the %s group", user, a.Group)
	}
	if !files.Exists(env.Path("/usr/bin/sudo")) {
		return fmt.Errorf("sudo is not installed")
	}
	// If this tool set the policy, check that the policy can work.
	policy, _, err := env.Rec.Get(SudoID, "policy")
	if err != nil {
		return err
	}
	switch policy {
	case PolicyOwn:
		if h, _, err := ShadowHash(env, user); err != nil {
			return err
		} else if !UsablePassword(h) {
			return fmt.Errorf("%s has no password, but the sudo policy asks for the account's own password", user)
		}
	case PolicyRoot:
		if h, _, err := ShadowHash(env, "root"); err != nil {
			return err
		} else if !UsablePassword(h) {
			return fmt.Errorf("root has no usable password, but the sudo policy asks for root's password")
		}
	}
	return nil
}
