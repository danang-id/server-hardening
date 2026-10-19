// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Danang Galuh Tegar Prasetyo

package main

// Every Linux system's controls are linked into the Linux binary. Each
// package registers its System when it is imported.
import (
	_ "github.com/danang-id/server-hardening/Debian/13/Controls"
)
