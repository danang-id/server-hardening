// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Danang Galuh Tegar Prasetyo

// Package guard undoes a risky change automatically when the user does not
// confirm it.
//
// A lockout control (such as turning off password login) can cut the
// connection that the tool itself runs in. A timer that lives in the tool would
// die with that connection, so the timer is a systemd transient timer instead.
// It runs this same binary with --undo <control>, long after the tool has gone.
package guard

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/danang-id/server-hardening/internal/control"
	"github.com/danang-id/server-hardening/internal/files"
)

// Systemd arms the undo as a systemd transient timer.
type Systemd struct {
	Run control.Runner
	// Dir is the records directory. A copy of the binary is kept in Dir/bin so
	// the timer can run it even if the original was deleted or moved.
	Dir string
	// Exe is the path of the running binary.
	Exe string
}

// UnitName is the systemd unit used for a control, for example
// "server-hardening-undo-remote-access-ssh-port".
func UnitName(id string) string {
	return "server-hardening-undo-" + strings.NewReplacer(".", "-", "_", "-").Replace(id)
}

// BinPath is where the copy of the binary lives.
func (g *Systemd) BinPath() string { return filepath.Join(g.Dir, "bin", "hardening") }

func (g *Systemd) install() error {
	b, err := os.ReadFile(g.Exe)
	if err != nil {
		return fmt.Errorf("reading the running binary: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(g.BinPath()), 0o700); err != nil {
		return err
	}
	return files.WriteAtomic(g.BinPath(), b, 0o700)
}

// Arm schedules "hardening --undo <id>" after window.
func (g *Systemd) Arm(ctx context.Context, id string, window time.Duration) (func(context.Context) error, error) {
	if window < time.Second {
		return nil, fmt.Errorf("window %v is too short", window)
	}
	if err := g.install(); err != nil {
		return nil, err
	}
	unit := UnitName(id)
	// A timer left over from an earlier run would make systemd-run fail.
	_, _ = g.Run.Run(ctx, "systemctl", "stop", unit+".timer")
	if _, err := g.Run.Run(ctx, "systemd-run",
		"--unit="+unit,
		fmt.Sprintf("--on-active=%ds", int(window.Seconds())),
		"--collect",
		"--description=Undo "+id+" unless it is confirmed",
		g.BinPath(), "--undo", id,
	); err != nil {
		return nil, fmt.Errorf("starting the timer: %w", err)
	}
	return func(ctx context.Context) error {
		_, err := g.Run.Run(ctx, "systemctl", "stop", unit+".timer")
		return err
	}, nil
}
