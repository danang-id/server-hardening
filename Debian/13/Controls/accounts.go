// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Danang Galuh Tegar Prasetyo

package controls

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/danang-id/server-hardening/internal/control"
	"github.com/danang-id/server-hardening/internal/files"
)

// Helpers for the account files (/etc/passwd, /etc/group, /etc/shadow).
// They read the files under env.Root, so they work in tests.

const (
	adminGroup = "sudo"
	// firstHumanUID is the first user ID of a normal (non-system) account.
	firstHumanUID = 1000
)

type account struct {
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

func readPasswd(env *control.Env) ([]account, error) {
	rows, err := colonLines(env.Path("/etc/passwd"))
	if err != nil {
		return nil, err
	}
	var out []account
	for _, f := range rows {
		if len(f) < 7 {
			continue
		}
		uid, _ := strconv.Atoi(f[2])
		gid, _ := strconv.Atoi(f[3])
		out = append(out, account{Name: f[0], UID: uid, GID: gid, Home: f[5], Shell: f[6]})
	}
	return out, nil
}

func findAccount(env *control.Env, name string) (account, bool, error) {
	all, err := readPasswd(env)
	if err != nil {
		return account{}, false, err
	}
	for _, a := range all {
		if a.Name == name {
			return a, true, nil
		}
	}
	return account{}, false, nil
}

// groupMembers lists the users named as members of a group.
func groupMembers(env *control.Env, group string) ([]string, error) {
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

func inGroup(env *control.Env, group, user string) (bool, error) {
	m, err := groupMembers(env, group)
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

// shadowHash returns the password field of an account.
func shadowHash(env *control.Env, user string) (string, bool, error) {
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

// usablePassword reports whether a password field holds a real password.
// An empty field, "!", "*" and anything starting with "!" or "*" do not.
func usablePassword(hash string) bool {
	return hash != "" && !strings.HasPrefix(hash, "!") && !strings.HasPrefix(hash, "*")
}

// adminAccounts lists the accounts that can use sudo: the one this tool
// created or confirmed (if it still exists), otherwise the normal accounts in
// the sudo group. Root is never listed.
func adminAccounts(env *control.Env) ([]string, error) {
	if u, ok, err := env.Rec.Get(adminUserID, "user"); err != nil {
		return nil, err
	} else if ok {
		if _, exists, err := findAccount(env, u); err != nil {
			return nil, err
		} else if exists {
			return []string{u}, nil
		}
	}
	members, err := groupMembers(env, adminGroup)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, m := range members {
		a, exists, err := findAccount(env, m)
		if err != nil {
			return nil, err
		}
		if exists && a.UID >= firstHumanUID {
			out = append(out, m)
		}
	}
	return out, nil
}

// oneAdmin returns the single administrator account that later controls (SSH
// keys, SSH settings) work for.
func oneAdmin(env *control.Env) (account, error) {
	admins, err := adminAccounts(env)
	if err != nil {
		return account{}, err
	}
	switch len(admins) {
	case 0:
		return account{}, fmt.Errorf("there is no administrator account. Apply %s first", adminUserID)
	case 1:
		a, _, err := findAccount(env, admins[0])
		return a, err
	}
	return account{}, fmt.Errorf("there is more than one administrator account (%s). "+
		"Apply %s in this tool and choose the one to use", strings.Join(admins, ", "), adminUserID)
}

// adminCanSudo reports why an account could not use sudo, or nil.
func adminCanSudo(env *control.Env, user string) error {
	if ok, err := inGroup(env, adminGroup, user); err != nil {
		return err
	} else if !ok {
		return fmt.Errorf("%s is not in the %s group", user, adminGroup)
	}
	if !files.Exists(env.Path("/usr/bin/sudo")) {
		return fmt.Errorf("sudo is not installed")
	}
	// If this tool set the policy, check that the policy can work.
	policy, _, err := env.Rec.Get(sudoID, "policy")
	if err != nil {
		return err
	}
	switch policy {
	case policyOwn:
		if h, _, err := shadowHash(env, user); err != nil {
			return err
		} else if !usablePassword(h) {
			return fmt.Errorf("%s has no password, but the sudo policy asks for the account's own password", user)
		}
	case policyRoot:
		if h, _, err := shadowHash(env, "root"); err != nil {
			return err
		} else if !usablePassword(h) {
			return fmt.Errorf("root has no usable password, but the sudo policy asks for root's password")
		}
	}
	return nil
}
