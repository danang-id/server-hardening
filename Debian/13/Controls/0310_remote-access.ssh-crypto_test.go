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

func cryptoControl() *sshCrypto { return &sshCrypto{control.Base{M: control.Meta{ID: cryptoID}}} }

func removeIfExists(env *control.Env, p string) error {
	if err := os.Remove(env.Path(p)); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

func TestCryptoOnlyWritesWhatSSHSupports(t *testing.T) {
	ctx := context.Background()
	env, _, sim := sshEnv(t)
	c := cryptoControl()
	must(t, c.Apply(ctx, env, nil))
	got := dropIn(t, env, "crypto")
	wantContains(t, got,
		"KexAlgorithms sntrup761x25519-sha512@openssh.com,curve25519-sha256,curve25519-sha256@libssh.org\n",
		"Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr\n",
		"MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com\n",
		"HostKeyAlgorithms ssh-ed25519,sk-ssh-ed25519@openssh.com,rsa-sha2-512,rsa-sha2-256\n")
	for _, weak := range []string{"3des", "sha1", "diffie-hellman", "mlkem", "ssh-rsa,"} {
		if strings.Contains(got, weak) {
			t.Errorf("%q must not be written:\n%s", weak, got)
		}
	}
	if state(t, c, env) != control.Applied {
		t.Fatal("should be applied")
	}
	if len(sim.effective()["ciphers"]) == 0 {
		t.Fatal("ciphers not in force")
	}
	must(t, c.Revert(ctx, env))
	noFile(t, env, sshdFile("crypto"))
}

func TestCryptoUsesNewAlgorithmsWhenSupported(t *testing.T) {
	env, run, _ := sshEnv(t)
	run.out["ssh -Q kex"] += "mlkem768x25519-sha256\nsntrup761x25519-sha512\n"
	must(t, cryptoControl().Apply(context.Background(), env, nil))
	wantContains(t, dropIn(t, env, "crypto"),
		"KexAlgorithms mlkem768x25519-sha256,sntrup761x25519-sha512,sntrup761x25519-sha512@openssh.com,curve25519-sha256,curve25519-sha256@libssh.org\n")
}

func TestCryptoHostKeysFollowTheFiles(t *testing.T) {
	env, _, _ := sshEnv(t)
	must(t, removeIfExists(env, "/etc/ssh/ssh_host_rsa_key"))
	must(t, cryptoControl().Apply(context.Background(), env, nil))
	got := dropIn(t, env, "crypto")
	if strings.Contains(got, "rsa-sha2") {
		t.Fatalf("no RSA host key, so no RSA algorithm:\n%s", got)
	}
	wantContains(t, got, "HostKeyAlgorithms ssh-ed25519,sk-ssh-ed25519@openssh.com\n")
}

func TestCryptoHostKeysElsewhere(t *testing.T) {
	// No default host key file at all: the host keys are configured elsewhere,
	// so the list is not cut down.
	env, _, _ := sshEnv(t)
	must(t, removeIfExists(env, "/etc/ssh/ssh_host_rsa_key"))
	must(t, removeIfExists(env, "/etc/ssh/ssh_host_ed25519_key"))
	must(t, cryptoControl().Apply(context.Background(), env, nil))
	wantContains(t, dropIn(t, env, "crypto"), "rsa-sha2-512")
}

func TestCryptoRefusesWhenNothingIsSupported(t *testing.T) {
	env, run, _ := sshEnv(t)
	run.out["ssh -Q cipher"] = "3des-cbc\n"
	err := cryptoControl().Apply(context.Background(), env, nil)
	if err == nil || !strings.Contains(err.Error(), "cipher") {
		t.Fatalf("error: %v", err)
	}
	noFile(t, env, sshdFile("crypto"))
	if run.did("reload") {
		t.Fatal("nothing may change")
	}
}

func TestCryptoQueryFailure(t *testing.T) {
	env, run, _ := sshEnv(t)
	run.fail["ssh -Q kex"] = true
	if err := cryptoControl().Apply(context.Background(), env, nil); err == nil {
		t.Fatal("expected an error")
	}
	noFile(t, env, sshdFile("crypto"))
}

func TestCryptoMeta(t *testing.T) {
	c, _ := System.Get(cryptoID)
	m := c.Meta()
	if !m.Has(control.TagCompat) || !m.Has(control.TagLockout) {
		t.Fatalf("meta: %+v", m)
	}
}
