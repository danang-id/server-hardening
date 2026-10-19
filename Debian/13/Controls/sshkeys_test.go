// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Danang Galuh Tegar Prasetyo

package controls

import (
	"strings"
	"testing"
)

func TestParsePublicKey(t *testing.T) {
	good := ed25519Key(7, "me@host with spaces")
	k, err := parsePublicKey(good)
	if err != nil || k.Type != "ssh-ed25519" || k.Comment != "me@host with spaces" || k.Line() != good {
		t.Fatalf("%+v %v", k, err)
	}
	if _, err := parsePublicKey(rsaKey(2048, "")); err != nil {
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
		if _, err := parsePublicKey(line); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
}

func TestKeyIDIgnoresComment(t *testing.T) {
	a, _ := parsePublicKey(ed25519Key(3, "one"))
	b, _ := parsePublicKey(ed25519Key(3, "two"))
	if a.ID() != b.ID() {
		t.Fatal("the same key with another comment must have the same ID")
	}
}

func TestValidateKeyLines(t *testing.T) {
	keys, err := validateKeyLines("# my keys\n\n" + ed25519Key(1, "a") + "\n" + ed25519Key(2, "b") + "\n")
	if err != nil || len(keys) != 2 {
		t.Fatalf("%v %v", keys, err)
	}
	if _, err := validateKeyLines("\n# nothing\n"); err == nil {
		t.Error("no keys must be an error")
	}
	_, err = validateKeyLines("-----BEGIN OPENSSH PRIVATE KEY-----\nabc\n-----END OPENSSH PRIVATE KEY-----")
	if err == nil || !strings.Contains(err.Error(), "private key") {
		t.Errorf("private key: %v", err)
	}
	_, err = validateKeyLines(ed25519Key(1, "a") + "\nssh-dss AAAA x")
	if err == nil || !strings.Contains(err.Error(), "line 2") {
		t.Errorf("the error must name the line: %v", err)
	}
}

func TestParseAuthorizedKeys(t *testing.T) {
	keys, other := parseAuthorizedKeys("# c\n\n" + ed25519Key(1, "a") + "\n" + `from="10.0.0.1" ` + ed25519Key(2, "b") + "\n")
	if len(keys) != 1 || other != 1 {
		t.Fatalf("keys %d other %d", len(keys), other)
	}
}
