// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Danang Galuh Tegar Prasetyo

package controls

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/danang-id/server-hardening/internal/control"
	"github.com/danang-id/server-hardening/internal/files"
)

const authKeyID = "remote-access.authorized-key"

type authorizedKey struct{ control.Base }

func init() {
	System.Add(&authorizedKey{control.Base{M: control.Meta{
		ID:       authKeyID,
		Category: control.RemoteAccess,
		Number:   1,
		Title:    "Install the administrator's SSH public key",
		Default:  true,
		Requires: []string{adminUserID},
		Tags:     []control.Tag{control.TagInput},
	}}})
}

func authorizedKeysFile(a account) string { return filepath.Join(a.Home, ".ssh", "authorized_keys") }

// validateKeyLines checks the pasted text and returns the keys.
func validateKeyLines(text string) ([]pubKey, error) {
	if strings.Contains(text, "PRIVATE KEY") {
		return nil, fmt.Errorf("that is a private key. Never paste it. Paste the public key (the .pub file)")
	}
	var keys []pubKey
	for i, l := range strings.Split(text, "\n") {
		l = strings.TrimSpace(l)
		if l == "" || strings.HasPrefix(l, "#") {
			continue
		}
		k, err := parsePublicKey(l)
		if err != nil {
			return nil, fmt.Errorf("line %d: %w", i+1, err)
		}
		keys = append(keys, k)
	}
	if len(keys) == 0 {
		return nil, fmt.Errorf("enter at least one public key")
	}
	return keys, nil
}

// suggestedKeys finds the keys the user most likely logged in with: those of
// the account that started the tool, or else root's.
func suggestedKeys(env *control.Env) string {
	names := []string{"root"}
	if u := os.Getenv("SUDO_USER"); u != "" && u != "root" {
		names = []string{u, "root"}
	}
	for _, n := range names {
		a, ok, err := findAccount(env, n)
		if err != nil || !ok {
			continue
		}
		b, _ := files.ReadOptional(env.Path(authorizedKeysFile(a)))
		keys, _ := parseAuthorizedKeys(string(b))
		if len(keys) > 0 {
			var lines []string
			for _, k := range keys {
				lines = append(lines, k.Line())
			}
			return strings.Join(lines, "\n")
		}
	}
	return ""
}

func (a *authorizedKey) Inputs(_ context.Context, env *control.Env) ([]control.Input, error) {
	return []control.Input{{
		Key:   "keys",
		Label: "Public SSH keys for the administrator account (one per line)",
		Help:  "Paste the public key, the .pub file. Never paste a private key.",
		Kind:  control.TextArea, Default: suggestedKeys(env),
		Validate: func(s string) error { _, err := validateKeyLines(s); return err },
	}}, nil
}

// accountHasKey reports whether an account has at least one entry in its
// authorized_keys.
func accountHasKey(env *control.Env, name string) (bool, error) {
	a, ok, err := findAccount(env, name)
	if err != nil || !ok {
		return false, err
	}
	b, err := files.ReadOptional(env.Path(authorizedKeysFile(a)))
	if err != nil {
		return false, err
	}
	keys, other := parseAuthorizedKeys(string(b))
	return len(keys)+other > 0, nil
}

// adminHasKey reports whether an administrator account has an SSH key.
func adminHasKey(env *control.Env) (bool, error) {
	admins, err := adminAccounts(env)
	if err != nil {
		return false, err
	}
	for _, name := range admins {
		if ok, err := accountHasKey(env, name); err != nil || ok {
			return ok, err
		}
	}
	return false, nil
}

func (a *authorizedKey) Check(_ context.Context, env *control.Env) (control.State, error) {
	ok, err := adminHasKey(env)
	if err != nil || !ok {
		return control.NotApplied, err
	}
	return control.Applied, nil
}

func (a *authorizedKey) Apply(ctx context.Context, env *control.Env, in control.Values) error {
	keys, err := validateKeyLines(in.String("keys"))
	if err != nil {
		return err
	}
	acc, err := oneAdmin(env)
	if err != nil {
		return err
	}
	if !files.Exists(env.Path(acc.Home)) {
		return fmt.Errorf("the home directory %s of %s does not exist", acc.Home, acc.Name)
	}
	dir := env.Path(filepath.Join(acc.Home, ".ssh"))
	file := env.Path(authorizedKeysFile(acc))

	// Remember what existed, the first time only.
	if _, recorded, err := env.Rec.Get(authKeyID, "account"); err != nil {
		return err
	} else if !recorded {
		for k, v := range map[string]string{
			"account":      acc.Name,
			"dir-existed":  yesNo(files.Exists(dir)),
			"file-existed": yesNo(files.Exists(file)),
		} {
			if err := env.Rec.Put(authKeyID, k, v); err != nil {
				return err
			}
		}
	}

	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return err
	}
	old, err := files.ReadOptional(file)
	if err != nil {
		return err
	}
	have := map[string]bool{}
	oldKeys, _ := parseAuthorizedKeys(string(old))
	for _, k := range oldKeys {
		have[k.ID()] = true
	}
	content := string(old)
	if content != "" && !strings.HasSuffix(content, "\n") {
		content += "\n"
	}
	added, _, _ := env.Rec.Get(authKeyID, "added")
	var addedNow []string
	for _, k := range keys {
		if have[k.ID()] {
			env.Log.Infof("a key is already installed: %s", k.Comment)
			continue
		}
		have[k.ID()] = true
		content += k.Line() + "\n"
		addedNow = append(addedNow, k.ID())
	}
	if err := files.WriteAtomic(file, []byte(content), 0o600); err != nil {
		return err
	}
	owner := strconv.Itoa(acc.UID) + ":" + strconv.Itoa(acc.GID)
	if _, err := env.Run.Run(ctx, "chown", owner, dir, file); err != nil {
		return fmt.Errorf("setting the owner of the SSH key files: %w", err)
	}
	// Keep the list of keys this control added, for the revert.
	all := strings.TrimSpace(added + "\n" + strings.Join(addedNow, "\n"))
	if err := env.Rec.Put(authKeyID, "added", all); err != nil {
		return err
	}
	env.Log.Infof("%d key(s) installed for %s", len(addedNow), acc.Name)
	return nil
}

func (a *authorizedKey) Revert(_ context.Context, env *control.Env) error {
	if !env.Rec.Has(authKeyID) {
		env.Log.Warnf("%s: no record, leaving the keys alone", authKeyID)
		return nil
	}
	name, _, err := env.Rec.Get(authKeyID, "account")
	if err != nil {
		return err
	}
	acc, ok, err := findAccount(env, name)
	if err != nil {
		return err
	}
	if ok {
		if err := removeAddedKeys(env, acc); err != nil {
			return err
		}
	} else {
		env.Log.Warnf("%s: the account %s is gone, nothing to remove", authKeyID, name)
	}
	return env.Rec.Delete(authKeyID)
}

func removeAddedKeys(env *control.Env, acc account) error {
	added, _, err := env.Rec.Get(authKeyID, "added")
	if err != nil {
		return err
	}
	ours := map[string]bool{}
	for id := range strings.SplitSeq(added, "\n") {
		if id = strings.TrimSpace(id); id != "" {
			ours[id] = true
		}
	}
	file := env.Path(authorizedKeysFile(acc))
	old, err := files.ReadOptional(file)
	if err != nil || old == nil {
		return err
	}
	var keep []string
	for l := range strings.SplitSeq(strings.TrimRight(string(old), "\n"), "\n") {
		if k, err := parsePublicKey(strings.TrimSpace(l)); err == nil && ours[k.ID()] {
			continue
		}
		keep = append(keep, l)
	}
	left := strings.TrimSpace(strings.Join(keep, "\n"))
	fileExisted, _, _ := env.Rec.Get(authKeyID, "file-existed")
	dirExisted, _, _ := env.Rec.Get(authKeyID, "dir-existed")
	if left == "" && fileExisted != "yes" {
		if err := os.Remove(file); err != nil && !os.IsNotExist(err) {
			return err
		}
		if dirExisted != "yes" {
			_ = os.Remove(filepath.Dir(file)) // only if empty
		}
		return nil
	}
	if left != "" {
		left += "\n"
	}
	return files.WriteAtomic(file, []byte(left), 0o600)
}
