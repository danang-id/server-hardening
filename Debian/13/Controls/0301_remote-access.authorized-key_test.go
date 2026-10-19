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

func keyControl() *authorizedKey {
	return &authorizedKey{control.Base{M: control.Meta{ID: authKeyID}}}
}

func TestAuthorizedKeyInstallAndRevert(t *testing.T) {
	ctx := context.Background()
	env, run, _ := sshEnv(t)
	c := keyControl()
	if state(t, c, env) != control.NotApplied {
		t.Fatal("should start not applied")
	}
	key := ed25519Key(1, "alice@laptop")
	must(t, c.Apply(ctx, env, control.Values{"keys": {key}}))

	if got := read(t, env, "/home/alice/.ssh/authorized_keys"); got != key+"\n" {
		t.Fatalf("authorized_keys:\n%s", got)
	}
	if fi, _ := os.Stat(env.Path("/home/alice/.ssh")); fi.Mode().Perm() != 0o700 {
		t.Errorf(".ssh mode %v", fi.Mode())
	}
	if fi, _ := os.Stat(env.Path("/home/alice/.ssh/authorized_keys")); fi.Mode().Perm() != 0o600 {
		t.Errorf("authorized_keys mode %v", fi.Mode())
	}
	if !run.did("chown 1000:1000 " + env.Path("/home/alice/.ssh") + " " + env.Path("/home/alice/.ssh/authorized_keys")) {
		t.Errorf("owner must be set: %v", run.calls)
	}
	if state(t, c, env) != control.Applied {
		t.Fatal("should be applied")
	}

	// A second run with the same key adds nothing.
	must(t, c.Apply(ctx, env, control.Values{"keys": {key}}))
	if strings.Count(read(t, env, "/home/alice/.ssh/authorized_keys"), "ssh-ed25519") != 1 {
		t.Fatal("the key was added twice")
	}

	must(t, c.Revert(ctx, env))
	noFile(t, env, "/home/alice/.ssh/authorized_keys")
	noFile(t, env, "/home/alice/.ssh")
	if env.Rec.Has(authKeyID) {
		t.Fatal("record should be gone")
	}
}

func TestAuthorizedKeyRevertKeepsOtherKeys(t *testing.T) {
	ctx := context.Background()
	env, _, _ := sshEnv(t)
	mine := withKey(t, env) // present before the tool ran
	added := ed25519Key(2, "alice@phone")
	c := keyControl()
	must(t, c.Apply(ctx, env, control.Values{"keys": {mine + "\n" + added}}))
	if got := read(t, env, "/home/alice/.ssh/authorized_keys"); !strings.Contains(got, "alice@laptop") || !strings.Contains(got, "alice@phone") {
		t.Fatalf("both keys expected:\n%s", got)
	}
	must(t, c.Revert(ctx, env))
	got := read(t, env, "/home/alice/.ssh/authorized_keys")
	if !strings.Contains(got, "alice@laptop") || strings.Contains(got, "alice@phone") {
		t.Fatalf("only the key the tool added may go:\n%s", got)
	}
	if _, err := os.Stat(env.Path("/home/alice/.ssh")); err != nil {
		t.Fatal("the folder existed before and must stay")
	}
}

func TestAuthorizedKeyKeepsForeignLines(t *testing.T) {
	ctx := context.Background()
	env, _, _ := sshEnv(t)
	opt := `command="/bin/true" ` + ed25519Key(9, "backup")
	writeFile(t, env, "/home/alice/.ssh/authorized_keys", "# backup job\n"+opt+"\n")
	c := keyControl()
	must(t, c.Apply(ctx, env, control.Values{"keys": {ed25519Key(1, "new")}}))
	must(t, c.Revert(ctx, env))
	if got := read(t, env, "/home/alice/.ssh/authorized_keys"); got != "# backup job\n"+opt+"\n" {
		t.Fatalf("existing lines must stay as they were:\n%s", got)
	}
}

func TestAuthorizedKeyErrors(t *testing.T) {
	ctx := context.Background()
	env, _, _ := sshEnv(t)
	c := keyControl()
	if err := c.Apply(ctx, env, control.Values{"keys": {"-----BEGIN OPENSSH PRIVATE KEY-----"}}); err == nil {
		t.Error("a private key must be refused")
	}
	noFile(t, env, "/home/alice/.ssh")

	// Two administrators: the tool cannot know which one.
	writeFile(t, env, "/etc/passwd", basePasswd+"bob:x:1001:1001::/home/bob:/bin/bash\n")
	writeFile(t, env, "/etc/group", "root:x:0:\nsudo:x:27:alice,bob\nalice:x:1000:\n")
	if err := c.Apply(ctx, env, control.Values{"keys": {ed25519Key(1, "a")}}); err == nil || !strings.Contains(err.Error(), "more than one") {
		t.Errorf("two administrators: %v", err)
	}

	// No home directory.
	env2, _, _ := sshEnv(t)
	must(t, os.RemoveAll(env2.Path("/home/alice")))
	if err := c.Apply(ctx, env2, control.Values{"keys": {ed25519Key(1, "a")}}); err == nil || !strings.Contains(err.Error(), "home directory") {
		t.Errorf("no home: %v", err)
	}
}

func TestAuthorizedKeySuggestion(t *testing.T) {
	env, _, _ := sshEnv(t)
	if got := suggestedKeys(env); got != "" {
		t.Fatalf("nothing to suggest, got %q", got)
	}
	writeFile(t, env, "/root/.ssh/authorized_keys", ed25519Key(5, "root-key")+"\n")
	if got := suggestedKeys(env); !strings.Contains(got, "root-key") {
		t.Fatalf("root's key: %q", got)
	}
	k := withKey(t, env)
	t.Setenv("SUDO_USER", "alice")
	if got := suggestedKeys(env); got != k {
		t.Fatalf("the key of the account that started the tool comes first: %q", got)
	}
}

func TestAdminHasKey(t *testing.T) {
	env, _, _ := sshEnv(t)
	if ok, _ := adminHasKey(env); ok {
		t.Fatal("no key yet")
	}
	// Only a key with options: counts as an entry, so the account can log in.
	writeFile(t, env, "/home/alice/.ssh/authorized_keys", `command="x" `+ed25519Key(1, "a")+"\n")
	if ok, _ := adminHasKey(env); !ok {
		t.Fatal("an entry with options is still an entry")
	}
}
