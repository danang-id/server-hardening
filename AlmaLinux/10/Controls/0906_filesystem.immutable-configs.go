// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Danang Galuh Tegar Prasetyo

package controls

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/danang-id/server-hardening/internal/control"
)

const immutableID = "filesystem.immutable-configs"

type immutableConfigs struct{ control.Base }

func init() {
	System.Add(&immutableConfigs{control.Base{M: control.Meta{
		ID:       immutableID,
		Category: control.Filesystem,
		Number:   6,
		Title:    "Mark key configuration files immutable",
		Default:  false,
		Weight:   960,
		Tags:     []control.Tag{control.TagInput},
	}}})
}

// Folders where this tool writes files. A file in one of them is offered when
// it carries the name of this project.
var managedDirs = []string{
	"/etc/ssh/sshd_config.d", "/etc/sudoers.d", "/etc/sysctl.d", "/etc/nftables", "/etc/audit/rules.d",
	"/etc/fail2ban/jail.d", "/etc/dnf/plugins/post-transaction-actions.d", "/etc/systemd/journald.conf.d",
	"/etc/systemd/system", "/etc/modprobe.d", "/etc/aide", "/etc/security/pwquality.conf.d",
	"/etc/server-hardening", "/usr/local/libexec/server-hardening",
}

// Files that must stay writable: the account files change with every user
// change, and the rest change with every package or log write.
var neverLock = map[string]bool{
	"/etc/passwd": true, "/etc/shadow": true, "/etc/group": true, "/etc/gshadow": true,
	"/etc/subuid": true, "/etc/subgid": true, "/etc/fstab": true, "/etc/hosts": true,
	"/etc/resolv.conf": true, "/etc/hostname": true, "/etc/machine-id": true,
}

var neverLockUnder = []string{"/var/lib/rpm", "/usr/lib/sysimage/rpm", "/var/lib/dnf", "/var/log", "/tmp", "/var/tmp", "/var/lib/aide", "/proc", "/sys", "/dev", "/run"}

func lockable(path string) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return fmt.Errorf("%q is not a clean absolute path", path)
	}
	if neverLock[path] {
		return fmt.Errorf("%s changes with ordinary system use and cannot be locked", path)
	}
	for _, d := range neverLockUnder {
		if path == d || strings.HasPrefix(path, d+"/") {
			return fmt.Errorf("%s is under %s, which must stay writable", path, d)
		}
	}
	return nil
}

// offered lists the files this tool wrote.
func (i *immutableConfigs) offered(env *control.Env) []string {
	var out []string
	for _, d := range managedDirs {
		entries, err := os.ReadDir(env.Path(d))
		if err != nil {
			continue
		}
		for _, e := range entries {
			p := filepath.Join(d, e.Name())
			fi, err := os.Lstat(env.Path(p))
			if err != nil || !fi.Mode().IsRegular() {
				continue
			}
			if b, err := os.ReadFile(env.Path(p)); err == nil && bytes.Contains(b, []byte("server-hardening")) && lockable(p) == nil {
				out = append(out, p)
			}
		}
	}
	sort.Strings(out)
	return out
}

func (i *immutableConfigs) Inputs(_ context.Context, env *control.Env) ([]control.Input, error) {
	var opts []control.Option
	offered := i.offered(env)
	for _, p := range offered {
		opts = append(opts, control.Option{Value: p, Label: p})
	}
	in := []control.Input{}
	if len(opts) > 0 {
		in = append(in, control.Input{
			Key: "files", Label: "Which files do you want to lock?",
			Help: "Nothing can change a locked file, not even root, not this tool, and not a package upgrade that replaces it. Revert this control first to change one.",
			Kind: control.MultiChoice, Options: opts, DefaultMulti: offered,
		})
	}
	return append(in, control.Input{
		Key: "extra", Label: "More files to lock", Optional: true,
		Help: "Absolute paths of regular files, separated by spaces. Account files and files under /var/log, /var/lib/rpm, /var/lib/dnf and /tmp are refused.",
		Validate: func(s string) error {
			for _, p := range listItems(s) {
				if err := lockable(p); err != nil {
					return err
				}
			}
			return nil
		},
	}), nil
}

func isImmutable(ctx context.Context, env *control.Env, path string) bool {
	out, err := env.Run.Run(ctx, "lsattr", "-d", path)
	f := strings.Fields(string(out))
	return err == nil && len(f) > 0 && strings.Contains(f[0], "i")
}

func (i *immutableConfigs) Check(ctx context.Context, env *control.Env) (control.State, error) {
	if !env.Rec.Has(immutableID) {
		return control.NotApplied, nil
	}
	v, _, _ := env.Rec.Get(immutableID, "files")
	for _, p := range lines(v) {
		if _, err := os.Stat(env.Path(p)); err == nil && !isImmutable(ctx, env, p) {
			return control.Partial, nil
		}
	}
	return control.Applied, nil
}

func (i *immutableConfigs) Apply(ctx context.Context, env *control.Env, in control.Values) error {
	offered := map[string]bool{}
	for _, p := range i.offered(env) {
		offered[p] = true
	}
	var want []string
	seen := map[string]bool{}
	add := func(p string) { // keeps the order, drops repeats
		if !seen[p] {
			seen[p] = true
			want = append(want, p)
		}
	}
	for _, p := range in.List("files") {
		if !offered[p] {
			return fmt.Errorf("%s is not a file this control offers", p)
		}
		add(p)
	}
	for _, p := range listItems(in.String("extra")) {
		if err := lockable(p); err != nil {
			return err
		}
		fi, err := os.Lstat(env.Path(p))
		if err != nil || !fi.Mode().IsRegular() {
			return fmt.Errorf("%s is not a regular file", p)
		}
		add(p)
	}
	prev, _, _ := env.Rec.Get(immutableID, "files")
	all := lines(prev)
	var locked []string
	for _, p := range want {
		if out, err := env.Run.Run(ctx, "chattr", "+i", p); err != nil {
			env.Log.Warnf("cannot lock %s (the filesystem may not support it): %v %s", p, err, strings.TrimSpace(string(out)))
			continue
		}
		if !isImmutable(ctx, env, p) {
			env.Log.Warnf("%s does not show the immutable flag after chattr. It is not locked", p)
			continue
		}
		locked = append(locked, p)
		if !contains(all, p) {
			all = append(all, p)
		}
	}
	if len(want) > 0 && len(locked) == 0 {
		return fmt.Errorf("none of the files could be locked")
	}
	if len(locked) == 0 {
		env.Log.Infof("no file chosen, nothing locked")
	}
	for _, p := range locked {
		env.Log.Infof("locked %s", p)
	}
	return env.Rec.Put(immutableID, "files", strings.Join(all, "\n"))
}

func (i *immutableConfigs) Revert(ctx context.Context, env *control.Env) error {
	if !env.Rec.Has(immutableID) {
		env.Log.Warnf("%s: no record, leaving files alone", immutableID)
		return nil
	}
	v, _, _ := env.Rec.Get(immutableID, "files")
	for _, p := range lines(v) {
		if _, err := os.Stat(env.Path(p)); err != nil {
			continue // the file is gone
		}
		if _, err := env.Run.Run(ctx, "chattr", "-i", p); err != nil {
			return fmt.Errorf("cannot unlock %s: %w", p, err)
		}
	}
	return env.Rec.Delete(immutableID)
}
