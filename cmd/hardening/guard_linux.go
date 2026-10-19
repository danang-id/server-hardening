// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Danang Galuh Tegar Prasetyo

//go:build linux

package main

import (
	"os"

	"github.com/danang-id/server-hardening/internal/control"
	"github.com/danang-id/server-hardening/internal/guard"
)

// newGuard arms the automatic undo with a systemd timer. Without systemd the
// engine runs without it and tells the user to keep the console open.
func newGuard(run control.Runner) control.Guard {
	exe, err := os.Executable()
	if err != nil {
		return nil
	}
	if _, err := os.Stat("/run/systemd/system"); err != nil {
		return nil
	}
	return &guard.Systemd{Run: run, Dir: recordsDir, Exe: exe}
}
