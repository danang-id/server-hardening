// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Danang Galuh Tegar Prasetyo

package controls

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"

	"github.com/danang-id/server-hardening/internal/control"
)

const permAuditID = "filesystem.permission-audit"

type permissionAudit struct{ control.Base }

func init() {
	System.Add(&permissionAudit{control.Base{M: control.Meta{
		ID:       permAuditID,
		Category: control.Filesystem,
		Number:   5,
		Title:    "Audit file permissions",
		Default:  true,
		Weight:   900,
		Tags:     []control.Tag{control.TagReadonly},
	}}})
}

// sensitive files: the most permissive mode they may have, and who owns them.
var sensitiveFiles = []struct {
	path string
	max  fs.FileMode
	why  string
}{
	{"/etc/passwd", 0o644, ""},
	{"/etc/group", 0o644, ""},
	{"/etc/shadow", 0o640, "holds password hashes"},
	{"/etc/gshadow", 0o640, "holds group password hashes"},
	{"/etc/sudoers", 0o440, ""},
	{"/etc/ssh/sshd_config", 0o644, ""},
	{"/etc/crontab", 0o644, ""},
	{"/boot/grub/grub.cfg", 0o644, ""},
}

// Set-user-ID and set-group-ID programs that Debian ships. Anything else on
// the list is worth a look.
var usualSetID = map[string]bool{
	"/usr/bin/passwd": true, "/usr/bin/chfn": true, "/usr/bin/chsh": true, "/usr/bin/gpasswd": true,
	"/usr/bin/newgrp": true, "/usr/bin/su": true, "/usr/bin/mount": true, "/usr/bin/umount": true,
	"/usr/bin/sudo": true, "/usr/bin/chage": true, "/usr/bin/expiry": true, "/usr/bin/wall": true,
	"/usr/bin/write.ul": true, "/usr/bin/crontab": true, "/usr/bin/dotlockfile": true,
	"/usr/bin/ssh-agent": true, "/usr/sbin/unix_chkpwd": true, "/usr/sbin/pam_extrausers_chkpwd": true,
	"/usr/lib/openssh/ssh-keysign": true, "/usr/bin/fusermount3": true, "/usr/bin/fusermount": true,
	"/usr/bin/at": true, "/usr/bin/mlocate": true, "/usr/bin/plocate": true, "/usr/bin/bsd-write": true,
	"/usr/lib/dbus-1.0/dbus-daemon-launch-helper": true, "/usr/bin/pkexec": true,
	"/usr/lib/polkit-1/polkit-agent-helper-1": true, "/usr/bin/ntfs-3g": true, "/usr/bin/mtr-packet": true,
}

// checkOwners switches the owner check off in tests, which do not run as root.
var checkOwners = true

// permFindings checks the sensitive files, the home directories and the SSH
// host keys, which are cheap to read.
func permFindings(env *control.Env) []string {
	var out []string
	add := func(f string, a ...any) { out = append(out, fmt.Sprintf(f, a...)) }

	for _, s := range sensitiveFiles {
		fi, err := os.Stat(env.Path(s.path))
		if err != nil {
			continue
		}
		if extra := fi.Mode().Perm() &^ s.max; extra != 0 {
			add("%s has mode %04o, more than %04o", s.path, fi.Mode().Perm(), s.max)
		}
		if uid, _, ok := ownerOf(fi); checkOwners && ok && uid != 0 {
			add("%s is owned by user %d, not root", s.path, uid)
		}
	}
	keys, _ := filepath.Glob(env.Path("/etc/ssh/ssh_host_*_key"))
	for _, k := range keys {
		if fi, err := os.Stat(k); err == nil && fi.Mode().Perm()&0o037 != 0 {
			r, _ := filepath.Rel(env.Root, k)
			add("/%s is a private key with mode %04o. It should be 0600", filepath.ToSlash(r), fi.Mode().Perm())
		}
	}
	if drops, _ := filepath.Glob(env.Path("/etc/sudoers.d/*")); len(drops) > 0 {
		for _, f := range drops {
			if fi, err := os.Stat(f); err == nil && fi.Mode().IsRegular() && fi.Mode().Perm()&^0o440 != 0 {
				r, _ := filepath.Rel(env.Root, f)
				add("/%s has mode %04o. sudo wants 0440", filepath.ToSlash(r), fi.Mode().Perm())
			}
		}
	}
	homes, _ := filepath.Glob(env.Path("/home/*"))
	homes = append(homes, env.Path("/root"))
	for _, h := range homes {
		if fi, err := os.Stat(h); err == nil && fi.IsDir() && fi.Mode().Perm()&0o007 != 0 {
			r, _ := filepath.Rel(env.Root, h)
			add("/%s can be read by every user (mode %04o)", filepath.ToSlash(r), fi.Mode().Perm())
		}
	}
	sort.Strings(out)
	return out
}

// mountTargets lists the local disk filesystems, so one scan does not cross
// into network or memory filesystems.
func mountTargets(ctx context.Context, env *control.Env) []string {
	out, err := env.Run.Run(ctx, "findmnt", "-rn", "-o", "TARGET", "-t", "ext2,ext3,ext4,xfs,btrfs,f2fs,jfs")
	var t []string
	if err == nil {
		t = lines(string(out))
	}
	if len(t) == 0 {
		t = []string{"/"}
	}
	return t
}

// scan runs find on each filesystem and returns the lines it prints.
func scan(ctx context.Context, env *control.Env, targets []string, expr ...string) []string {
	var all []string
	for _, t := range targets {
		args := append([]string{t, "-xdev"}, expr...)
		out, _ := env.Run.Run(ctx, "find", args...) // find exits with 1 on unreadable directories
		all = append(all, lines(string(out))...)
	}
	sort.Strings(all)
	return all
}

func (p *permissionAudit) Check(_ context.Context, env *control.Env) (control.State, error) {
	if !env.Rec.Has(permAuditID) {
		return control.NotApplied, nil
	}
	if v, _, _ := env.Rec.Get(permAuditID, "findings"); v != "0" {
		return control.Partial, nil
	}
	return control.Applied, nil
}

func (p *permissionAudit) Apply(ctx context.Context, env *control.Env, _ control.Values) error {
	findings := permFindings(env)
	targets := mountTargets(ctx, env)
	section := func(title string, l []string) {
		for _, x := range l {
			findings = append(findings, title+": "+x)
		}
	}
	section("world-writable file", scan(ctx, env, targets, "-type", "f", "-perm", "-0002", "-print"))
	section("world-writable directory without the sticky bit", scan(ctx, env, targets, "-type", "d", "-perm", "-0002", "!", "-perm", "-1000", "-print"))
	section("no owner or no group", scan(ctx, env, targets, "(", "-nouser", "-o", "-nogroup", ")", "-print"))

	setid := scan(ctx, env, targets, "-type", "f", "(", "-perm", "-4000", "-o", "-perm", "-2000", ")", "-print")
	usual := 0
	for _, f := range setid {
		if usualSetID[f] {
			usual++
		} else {
			findings = append(findings, "set-user-ID or set-group-ID program that Debian does not ship by default: "+f)
		}
	}
	env.Log.Infof("%d set-user-ID or set-group-ID programs, %d of them the usual ones", len(setid), usual)

	for _, f := range findings {
		env.Log.Warnf("%s", f)
	}
	if len(findings) == 0 {
		env.Log.Infof("no permission findings")
	} else {
		env.Log.Infof("%d finding(s). This control changes nothing: review them yourself", len(findings))
	}
	return env.Rec.Put(permAuditID, "findings", fmt.Sprint(len(findings)))
}

func (p *permissionAudit) Revert(context.Context, *control.Env) error { return control.ErrNoRevert }
