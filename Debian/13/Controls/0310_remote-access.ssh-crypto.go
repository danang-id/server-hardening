// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Danang Galuh Tegar Prasetyo

package controls

import (
	"context"
	"fmt"
	"strings"

	"github.com/danang-id/server-hardening/internal/control"
	"github.com/danang-id/server-hardening/internal/files"
)

const cryptoID = "remote-access.ssh-crypto"

type sshCrypto struct{ control.Base }

func init() {
	System.Add(&sshCrypto{control.Base{M: control.Meta{
		ID:       cryptoID,
		Category: control.RemoteAccess,
		Number:   10,
		Title:    "Restrict SSH to modern algorithms",
		Default:  true,
		Tags:     []control.Tag{control.TagCompat, control.TagLockout},
	}}})
}

// The modern algorithms, in order of preference. Only the ones this OpenSSH
// supports (ssh -Q) are written, so a newer name never breaks an older sshd.
var (
	wantKex     = []string{"mlkem768x25519-sha256", "sntrup761x25519-sha512", "sntrup761x25519-sha512@openssh.com", "curve25519-sha256", "curve25519-sha256@libssh.org"}
	wantCiphers = []string{"chacha20-poly1305@openssh.com", "aes256-gcm@openssh.com", "aes128-gcm@openssh.com", "aes256-ctr", "aes192-ctr", "aes128-ctr"}
	wantMACs    = []string{"hmac-sha2-512-etm@openssh.com", "hmac-sha2-256-etm@openssh.com", "umac-128-etm@openssh.com"}
	wantHostKey = []string{"ssh-ed25519", "sk-ssh-ed25519@openssh.com", "rsa-sha2-512", "rsa-sha2-256"}
)

// hostKeyFile maps a host key algorithm to the default host key file it needs.
var hostKeyFile = map[string]string{
	"ssh-ed25519":                "/etc/ssh/ssh_host_ed25519_key",
	"sk-ssh-ed25519@openssh.com": "",
	"rsa-sha2-512":               "/etc/ssh/ssh_host_rsa_key",
	"rsa-sha2-256":               "/etc/ssh/ssh_host_rsa_key",
}

func keepSupported(want, supported []string) []string {
	have := map[string]bool{}
	for _, s := range supported {
		have[s] = true
	}
	var out []string
	for _, w := range want {
		if have[w] {
			out = append(out, w)
		}
	}
	return out
}

func (c *sshCrypto) cryptoDirectives(ctx context.Context, env *control.Env) ([]directive, error) {
	var ds []directive
	for _, q := range []struct {
		key, query string
		want       []string
	}{
		{"KexAlgorithms", "kex", wantKex},
		{"Ciphers", "cipher", wantCiphers},
		{"MACs", "mac", wantMACs},
		{"HostKeyAlgorithms", "HostKeyAlgorithms", wantHostKey},
	} {
		supported, err := sshdQuery(ctx, env, q.query)
		if err != nil {
			return nil, fmt.Errorf("asking ssh which %s it supports: %w", q.query, err)
		}
		list := keepSupported(q.want, supported)
		if q.key == "HostKeyAlgorithms" {
			list = withHostKeys(env, list)
		}
		if len(list) == 0 {
			return nil, fmt.Errorf("this OpenSSH supports none of the modern %s (or no host key fits them), so nothing was changed", q.query)
		}
		ds = append(ds, directive{q.key, strings.Join(list, ",")})
	}
	return ds, nil
}

// withHostKeys keeps the host key algorithms that the server has a key for.
// If the server keeps its host keys elsewhere, the list is left as it is.
func withHostKeys(env *control.Env, list []string) []string {
	have := false
	for _, f := range hostKeyFile {
		if f != "" && files.Exists(env.Path(f)) {
			have = true
		}
	}
	if !have {
		return list
	}
	var out []string
	for _, a := range list {
		f := hostKeyFile[a]
		if f == "" || files.Exists(env.Path(f)) {
			out = append(out, a)
		}
	}
	return out
}

func (c *sshCrypto) Check(ctx context.Context, env *control.Env) (control.State, error) {
	return sshdCheck(ctx, env, cryptoID, "crypto")
}

func (c *sshCrypto) Apply(ctx context.Context, env *control.Env, _ control.Values) error {
	ds, err := c.cryptoDirectives(ctx, env)
	if err != nil {
		return err
	}
	if err := sshdApply(ctx, env, cryptoID, "crypto", ds); err != nil {
		return err
	}
	env.Log.Infof("SSH accepts modern algorithms only. Test from your usual client before you close this session")
	return nil
}

func (c *sshCrypto) Revert(ctx context.Context, env *control.Env) error {
	return sshdRevert(ctx, env, cryptoID, "crypto")
}
