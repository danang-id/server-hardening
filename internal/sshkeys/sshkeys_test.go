// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Danang Galuh Tegar Prasetyo

package sshkeys

import (
	"encoding/base64"
	"encoding/binary"
	"strings"
	"testing"
)

func TestParsePublicKey(t *testing.T) {
	good := ed25519Key(7, "me@host with spaces")
	k, err := ParsePublicKey(good)
	if err != nil || k.Type != "ssh-ed25519" || k.Comment != "me@host with spaces" || k.Line() != good {
		t.Fatalf("%+v %v", k, err)
	}
	if _, err := ParsePublicKey(rsaKey(2048, "")); err != nil {
		t.Fatalf("2048-bit RSA: %v", err)
	}
	for name, line := range map[string]string{
		"short RSA":       rsaKey(1024, ""),
		"options":         `command="ls" ` + good,
		"dsa":             "ssh-dss AAAA x",
		"certificate":     "ssh-ed25519-cert-v01@openssh.com AAAA x",
		"not base64":      "ssh-ed25519 !!!! x",
		"type mismatch":   strings.Replace(good, "ssh-ed25519", "ecdsa-sha2-nistp256", 1),
		"truncated":       "ssh-ed25519 AAAA x",
		"one field":       "ssh-ed25519",
		"empty":           "",
		"private key arm": "-----BEGIN OPENSSH PRIVATE KEY-----",
	} {
		if _, err := ParsePublicKey(line); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
}

func TestKeyIDIgnoresComment(t *testing.T) {
	a, _ := ParsePublicKey(ed25519Key(3, "one"))
	b, _ := ParsePublicKey(ed25519Key(3, "two"))
	if a.ID() != b.ID() {
		t.Fatal("the same key with another comment must have the same ID")
	}
}

func TestValidateKeyLines(t *testing.T) {
	keys, err := ValidateKeyLines("# my keys\n\n" + ed25519Key(1, "a") + "\n" + ed25519Key(2, "b") + "\n")
	if err != nil || len(keys) != 2 {
		t.Fatalf("%v %v", keys, err)
	}
	if _, err := ValidateKeyLines("\n# nothing\n"); err == nil {
		t.Error("no keys must be an error")
	}
	_, err = ValidateKeyLines("-----BEGIN OPENSSH PRIVATE KEY-----\nabc\n-----END OPENSSH PRIVATE KEY-----")
	if err == nil || !strings.Contains(err.Error(), "private key") {
		t.Errorf("private key: %v", err)
	}
	_, err = ValidateKeyLines(ed25519Key(1, "a") + "\nssh-dss AAAA x")
	if err == nil || !strings.Contains(err.Error(), "line 2") {
		t.Errorf("the error must name the line: %v", err)
	}
}

func TestParseAuthorizedKeys(t *testing.T) {
	keys, other := ParseAuthorizedKeys("# c\n\n" + ed25519Key(1, "a") + "\n" + `from="10.0.0.1" ` + ed25519Key(2, "b") + "\n")
	if len(keys) != 1 || other != 1 {
		t.Fatalf("keys %d other %d", len(keys), other)
	}
}

// Public keys for tests

func sshString(b []byte) []byte {
	out := make([]byte, 4, 4+len(b))
	binary.BigEndian.PutUint32(out, uint32(len(b)))
	return append(out, b...)
}

// ed25519Key builds a valid-looking ed25519 public key. The seed makes keys differ.
func ed25519Key(seed byte, comment string) string {
	raw := make([]byte, 32)
	for i := range raw {
		raw[i] = seed + byte(i)
	}
	blob := append(sshString([]byte("ssh-ed25519")), sshString(raw)...)
	return strings.TrimSpace("ssh-ed25519 " + base64.StdEncoding.EncodeToString(blob) + " " + comment)
}

// rsaKey builds an RSA public key with a modulus of the given size.
func rsaKey(bits int, comment string) string {
	mod := make([]byte, bits/8+1) // leading zero byte, as in an SSH mpint
	for i := 1; i < len(mod); i++ {
		mod[i] = 0xff
	}
	blob := append(sshString([]byte("ssh-rsa")), sshString([]byte{1, 0, 1})...)
	blob = append(blob, sshString(mod)...)
	return strings.TrimSpace("ssh-rsa " + base64.StdEncoding.EncodeToString(blob) + " " + comment)
}
