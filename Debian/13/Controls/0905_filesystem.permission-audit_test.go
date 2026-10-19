// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Danang Galuh Tegar Prasetyo

package controls

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/danang-id/server-hardening/internal/control"
)

func auditPermControl() *permissionAudit {
	return &permissionAudit{control.Base{M: control.Meta{ID: permAuditID}}}
}

func chmod(t *testing.T, env *control.Env, p string, m os.FileMode) {
	t.Helper()
	must(t, os.Chmod(env.Path(p), m))
}

func TestPermissionAuditFindsRiskyFiles(t *testing.T) {
	checkOwners = false
	t.Cleanup(func() { checkOwners = true })
	ctx := context.Background()
	env, run, _ := sysEnv(t)
	writeFile(t, env, "/etc/shadow", "x")
	chmod(t, env, "/etc/shadow", 0o644)
	writeFile(t, env, "/etc/passwd", "x")
	chmod(t, env, "/etc/passwd", 0o644)
	writeFile(t, env, "/etc/ssh/ssh_host_ed25519_key", "k")
	chmod(t, env, "/etc/ssh/ssh_host_ed25519_key", 0o644)
	writeFile(t, env, "/etc/ssh/ssh_host_ed25519_key.pub", "k")
	chmod(t, env, "/etc/ssh/ssh_host_ed25519_key.pub", 0o644)
	writeFile(t, env, "/etc/sudoers.d/mine", "x")
	chmod(t, env, "/etc/sudoers.d/mine", 0o644)
	writeFile(t, env, "/home/alice/.profile", "x")
	chmod(t, env, "/home/alice", 0o755)
	writeFile(t, env, "/home/bob/.profile", "x")
	chmod(t, env, "/home/bob", 0o700)

	run.out["find / -xdev -type f -perm -0002 -print"] = "/srv/open.txt\n"
	run.out["find / -xdev -type d -perm -0002 ! -perm -1000 -print"] = "/srv/dir\n"
	run.out["find / -xdev ( -nouser -o -nogroup ) -print"] = "/srv/orphan\n"
	run.out["find / -xdev -type f ( -perm -4000 -o -perm -2000 ) -print"] = "/usr/bin/sudo\n/usr/bin/passwd\n/opt/tool/rootme\n"
	var warned []string
	env.Log = &memLog{warns: &warned}

	c := auditPermControl()
	if state(t, c, env) != control.NotApplied {
		t.Fatal("should start not applied")
	}
	must(t, c.Apply(ctx, env, nil))
	all := strings.Join(warned, "\n")
	wantContains(t, all,
		"/etc/shadow has mode 0644, more than 0640",
		"/etc/ssh/ssh_host_ed25519_key is a private key with mode 0644",
		"/etc/sudoers.d/mine has mode 0644",
		"/home/alice can be read by every user (mode 0755)",
		"world-writable file: /srv/open.txt",
		"world-writable directory without the sticky bit: /srv/dir",
		"no owner or no group: /srv/orphan",
		"does not ship by default: /opt/tool/rootme")
	for _, not := range []string{"/etc/passwd has", "ssh_host_ed25519_key.pub", "/home/bob", "/usr/bin/sudo", "/usr/bin/passwd"} {
		if strings.Contains(all, not) {
			t.Fatalf("%q must not be reported:\n%s", not, all)
		}
	}
	if state(t, c, env) != control.Partial {
		t.Fatal("findings make it partial")
	}
	if err := c.Revert(ctx, env); err != control.ErrNoRevert {
		t.Fatalf("want ErrNoRevert, got %v", err)
	}
}

func TestPermissionAuditCleanSystem(t *testing.T) {
	checkOwners = false
	t.Cleanup(func() { checkOwners = true })
	env, _, _ := sysEnv(t)
	writeFile(t, env, "/etc/shadow", "x")
	chmod(t, env, "/etc/shadow", 0o640)
	c := auditPermControl()
	must(t, c.Apply(context.Background(), env, nil))
	if state(t, c, env) != control.Applied {
		t.Fatal("no findings is applied")
	}
}

func TestPermissionAuditScansEveryDiskFilesystem(t *testing.T) {
	checkOwners = false
	t.Cleanup(func() { checkOwners = true })
	env, run, _ := sysEnv(t)
	run.out["findmnt -rn -o TARGET -t ext2,ext3,ext4,xfs,btrfs,f2fs,jfs"] = "/\n/var\n"
	run.out["find /var -xdev -type f -perm -0002 -print"] = "/var/lib/x\n"
	var warned []string
	env.Log = &memLog{warns: &warned}
	must(t, auditPermControl().Apply(context.Background(), env, nil))
	if !run.did("find /var -xdev") || !strings.Contains(strings.Join(warned, "\n"), "/var/lib/x") {
		t.Fatalf("calls %v warnings %v", run.calls, warned)
	}
}
