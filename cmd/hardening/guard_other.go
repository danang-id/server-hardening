// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Danang Galuh Tegar Prasetyo

//go:build !linux

package main

import "github.com/danang-id/server-hardening/internal/control"

// newGuard returns nil: the automatic undo needs systemd, which exists only on
// Linux.
func newGuard(control.Runner) control.Guard { return nil }
