// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Danang Galuh Tegar Prasetyo

package controls

import "github.com/danang-id/server-hardening/internal/sshkeys"

// Short names for internal/sshkeys, which every system shares.

type pubKey = sshkeys.PubKey

func parsePublicKey(line string) (pubKey, error) { return sshkeys.ParsePublicKey(line) }

func parseAuthorizedKeys(content string) (keys []pubKey, other int) {
	return sshkeys.ParseAuthorizedKeys(content)
}

func validateKeyLines(text string) ([]pubKey, error) { return sshkeys.ValidateKeyLines(text) }
