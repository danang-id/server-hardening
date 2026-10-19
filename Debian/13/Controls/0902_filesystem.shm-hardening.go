// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Danang Galuh Tegar Prasetyo

package controls

import (
	"context"
	"fmt"
	"strings"

	"github.com/danang-id/server-hardening/internal/control"
)

const (
	shmID    = "filesystem.shm-hardening"
	shmMount = "/dev/shm"
)

type shmHardening struct{ control.Base }

func init() {
	System.Add(&shmHardening{control.Base{M: control.Meta{
		ID:       shmID,
		Category: control.Filesystem,
		Number:   2,
		Title:    "Mount shared memory with restrictive options",
		Default:  true,
		Tags:     []control.Tag{control.TagInput, control.TagCompat},
	}}})
}

func (s *shmHardening) Inputs(context.Context, *control.Env) ([]control.Input, error) {
	return []control.Input{{
		Key: "noexec", Label: "Block running programs from shared memory?", Kind: control.Choice, Default: "yes",
		Help: "A few programs that compile code at run time, such as some browsers and runtimes with a just-in-time compiler, fail when this is on.",
		Options: []control.Option{
			{Value: "yes", Label: "Yes (recommended)"},
			{Value: "no", Label: "No"},
		},
	}}, nil
}

func shmEntry(noexec bool) string {
	o := "defaults,nosuid,nodev"
	if noexec {
		o += ",noexec"
	}
	return "tmpfs /dev/shm tmpfs " + o + " 0 0"
}

func (s *shmHardening) Check(ctx context.Context, env *control.Env) (control.State, error) {
	c, err := readFstab(env)
	if err != nil {
		return control.NotApplied, err
	}
	if _, ok := fstabHas(c, shmMount); !ok || !strings.Contains(c, managed(shmID)) {
		return control.NotApplied, nil
	}
	set, _, err := mountOptions(ctx, env, shmMount)
	if err != nil {
		return control.Partial, nil
	}
	want, _, _ := env.Rec.Get(shmID, "noexec")
	nosuid, nodev, noexec := flagsOf(set)
	if !nosuid || !nodev || noexec != (want != "no") {
		return control.Partial, nil
	}
	return control.Applied, nil
}

func (s *shmHardening) Apply(ctx context.Context, env *control.Env, in control.Values) error {
	noexec := in.String("noexec") != "no"
	set, _, err := mountOptions(ctx, env, shmMount)
	if err != nil {
		return err
	}
	if !env.Rec.Has(shmID) {
		nosuid, nodev, ne := flagsOf(set)
		if err := env.Rec.Put(shmID, "flags", fmt.Sprintf("%t,%t,%t", nosuid, nodev, ne)); err != nil {
			return err
		}
	}
	if err := env.Rec.Put(shmID, "noexec", yesNo(noexec)); err != nil {
		return err
	}
	c, err := readFstab(env)
	if err != nil {
		return err
	}
	if err := putFile(env, shmID, "/etc/fstab", fstabSet(c, shmMount, shmID, shmEntry(noexec)), 0o644); err != nil {
		return err
	}
	if _, err := env.Run.Run(ctx, "systemctl", "daemon-reload"); err != nil {
		_ = restoreFile(env, shmID, "/etc/fstab")
		return err
	}
	if err := remountFlags(ctx, env, shmMount, true, true, noexec); err != nil {
		_ = restoreFile(env, shmID, "/etc/fstab")
		_, _ = env.Run.Run(ctx, "systemctl", "daemon-reload")
		return err
	}
	return nil
}

func (s *shmHardening) Revert(ctx context.Context, env *control.Env) error {
	if !env.Rec.Has(shmID) {
		env.Log.Warnf("%s: no record, leaving shared memory alone", shmID)
		return nil
	}
	if err := restoreFile(env, shmID, "/etc/fstab"); err != nil {
		return err
	}
	if _, err := env.Run.Run(ctx, "systemctl", "daemon-reload"); err != nil {
		return err
	}
	f, _, _ := env.Rec.Get(shmID, "flags")
	var nosuid, nodev, noexec bool
	fmt.Sscanf(strings.ReplaceAll(f, ",", " "), "%t %t %t", &nosuid, &nodev, &noexec)
	if err := remountFlags(ctx, env, shmMount, nosuid, nodev, noexec); err != nil {
		return err
	}
	return env.Rec.Delete(shmID)
}
