// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Danang Galuh Tegar Prasetyo

//go:build windows

package controls

import "io/fs"

// ownerOf has no meaning on Windows.
func ownerOf(fs.FileInfo) (uid, gid int, ok bool) { return 0, 0, false }
