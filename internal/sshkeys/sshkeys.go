// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Danang Galuh Tegar Prasetyo

// Package sshkeys reads SSH public keys, as they appear in authorized_keys.
package sshkeys

import (
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"strings"
)

// Public SSH keys, as they appear in authorized_keys.

// PubKey is one key of an authorized_keys file.
type PubKey struct {
	Type    string
	Blob    string // base64, as written
	Comment string
}

// ID identifies a key regardless of its comment.
func (k PubKey) ID() string { return k.Type + " " + k.Blob }

// Line is how the key is written to authorized_keys.
func (k PubKey) Line() string {
	if k.Comment == "" {
		return k.ID()
	}
	return k.ID() + " " + k.Comment
}

// keyTypes are the key types that are accepted. DSA and certificates are not.
var keyTypes = map[string]bool{
	"ssh-ed25519":                        true,
	"sk-ssh-ed25519@openssh.com":         true,
	"ecdsa-sha2-nistp256":                true,
	"ecdsa-sha2-nistp384":                true,
	"ecdsa-sha2-nistp521":                true,
	"sk-ecdsa-sha2-nistp256@openssh.com": true,
	"ssh-rsa":                            true,
}

const minRSABits = 2048

// readString reads one SSH "string" (length-prefixed) from b.
func readString(b []byte) (val, rest []byte, err error) {
	if len(b) < 4 {
		return nil, nil, fmt.Errorf("truncated key")
	}
	n := binary.BigEndian.Uint32(b)
	if uint64(n) > uint64(len(b)-4) {
		return nil, nil, fmt.Errorf("truncated key")
	}
	return b[4 : 4+n], b[4+n:], nil
}

// ParsePublicKey checks one authorized_keys line.
func ParsePublicKey(line string) (PubKey, error) {
	f := strings.Fields(line)
	if len(f) < 2 {
		return PubKey{}, fmt.Errorf("not a public key (expected: type, key, optional comment)")
	}
	if !keyTypes[f[0]] {
		return PubKey{}, fmt.Errorf("%q is not an accepted key type. "+
			"A line with options (such as command=) is not accepted, and neither are DSA keys or certificates", f[0])
	}
	blob, err := base64.StdEncoding.DecodeString(f[1])
	if err != nil {
		return PubKey{}, fmt.Errorf("the key is not valid base64")
	}
	typ, rest, err := readString(blob)
	if err != nil {
		return PubKey{}, err
	}
	if string(typ) != f[0] {
		return PubKey{}, fmt.Errorf("the key says it is %q but the line says %q", typ, f[0])
	}
	switch f[0] {
	case "ssh-ed25519":
		k, _, err := readString(rest)
		if err != nil || len(k) != 32 {
			return PubKey{}, fmt.Errorf("not a valid ed25519 key")
		}
	case "ssh-rsa":
		_, rest, err := readString(rest) // exponent
		if err != nil {
			return PubKey{}, err
		}
		n, _, err := readString(rest) // modulus
		if err != nil {
			return PubKey{}, err
		}
		if bits := bitLength(n); bits < minRSABits {
			return PubKey{}, fmt.Errorf("the RSA key has %d bits, at least %d are needed", bits, minRSABits)
		}
	}
	return PubKey{Type: f[0], Blob: f[1], Comment: strings.Join(f[2:], " ")}, nil
}

func bitLength(mpint []byte) int {
	for len(mpint) > 0 && mpint[0] == 0 {
		mpint = mpint[1:]
	}
	if len(mpint) == 0 {
		return 0
	}
	bits := (len(mpint) - 1) * 8
	for b := mpint[0]; b != 0; b >>= 1 {
		bits++
	}
	return bits
}

// ParseAuthorizedKeys reads the keys of an authorized_keys file. Blank lines
// and comments are skipped. A line that is not a plain key (for example one
// with options) is skipped too, and counted in other.
func ParseAuthorizedKeys(content string) (keys []PubKey, other int) {
	for l := range strings.SplitSeq(content, "\n") {
		l = strings.TrimSpace(l)
		if l == "" || strings.HasPrefix(l, "#") {
			continue
		}
		k, err := ParsePublicKey(l)
		if err != nil {
			other++
			continue
		}
		keys = append(keys, k)
	}
	return keys, other
}

// ValidateKeyLines checks the pasted text and returns the keys.
func ValidateKeyLines(text string) ([]PubKey, error) {
	if strings.Contains(text, "PRIVATE KEY") {
		return nil, fmt.Errorf("that is a private key. Never paste it. Paste the public key (the .pub file)")
	}
	var keys []PubKey
	n := 0
	for l := range strings.SplitSeq(text, "\n") {
		n++
		l = strings.TrimSpace(l)
		if l == "" || strings.HasPrefix(l, "#") {
			continue
		}
		k, err := ParsePublicKey(l)
		if err != nil {
			return nil, fmt.Errorf("line %d: %w", n, err)
		}
		keys = append(keys, k)
	}
	if len(keys) == 0 {
		return nil, fmt.Errorf("enter at least one public key")
	}
	return keys, nil
}
