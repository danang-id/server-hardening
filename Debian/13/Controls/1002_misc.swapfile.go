// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Danang Galuh Tegar Prasetyo

package controls

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/danang-id/server-hardening/internal/control"
	"github.com/danang-id/server-hardening/internal/files"
)

const swapID = "misc.swapfile"

type swapfile struct{ control.Base }

func init() {
	System.Add(&swapfile{control.Base{M: control.Meta{
		ID:           swapID,
		Category:     control.Misc,
		Number:       2,
		Title:        "Create a swap file",
		Default:      false,
		Tags:         []control.Tag{control.TagInput},
		RevertLimits: "If the system is short of memory, turning swap off may fail until memory is freed. The tool then stops and says so.",
	}}})
}

var (
	swapSize = regexp.MustCompile(`^([1-9][0-9]{0,5})([MG])$`)
	swapPath = regexp.MustCompile(`^/[A-Za-z0-9._/-]+$`)
)

func parseSwapSize(s string) (int64, error) {
	m := swapSize.FindStringSubmatch(strings.TrimSpace(s))
	if m == nil {
		return 0, fmt.Errorf("use a number with M or G, for example 2G")
	}
	n, _ := strconv.ParseInt(m[1], 10, 64)
	if m[2] == "G" {
		return n << 30, nil
	}
	return n << 20, nil
}

func validSwapPath(p string) error {
	p = strings.TrimSpace(p)
	if !swapPath.MatchString(p) || filepath.Clean(p) != p || strings.HasSuffix(p, "/") {
		return fmt.Errorf("use a clean absolute path such as /swapfile (letters, digits and / . _ - only)")
	}
	return nil
}

func (s *swapfile) Inputs(context.Context, *control.Env) ([]control.Input, error) {
	return []control.Input{
		{
			Key: "size", Label: "Size of the swap file", Default: "2G",
			Help: "A number with M or G, for example 2G",
			Validate: func(v string) error {
				_, err := parseSwapSize(v)
				return err
			},
		},
		{Key: "path", Label: "Where to put the swap file", Default: "/swapfile", Validate: validSwapPath},
	}, nil
}

func activeSwap(ctx context.Context, env *control.Env) []string {
	out, err := env.Run.Run(ctx, "swapon", "--show=NAME", "--noheadings")
	if err != nil {
		return nil
	}
	return lines(string(out))
}

func (s *swapfile) Check(ctx context.Context, env *control.Env) (control.State, error) {
	active := activeSwap(ctx, env)
	if !env.Rec.Has(swapID) {
		if len(active) > 0 {
			return control.Applied, nil // the server has swap: the purpose is met
		}
		return control.NotApplied, nil
	}
	path, _, _ := env.Rec.Get(swapID, "path")
	if !contains(active, path) {
		return control.Partial, nil
	}
	if fi, err := os.Stat(env.Path(path)); err != nil || fi.Mode().Perm()&0o077 != 0 {
		return control.Partial, nil
	}
	return control.Applied, nil
}

// freeBytes asks df how much room a directory has.
func freeBytes(ctx context.Context, env *control.Env, dir string) (int64, error) {
	out, err := env.Run.Run(ctx, "df", "--output=avail", "-B1", dir)
	if err != nil {
		return 0, err
	}
	l := lines(string(out))
	if len(l) < 2 {
		return 0, fmt.Errorf("unexpected df output")
	}
	return strconv.ParseInt(l[len(l)-1], 10, 64)
}

func (s *swapfile) Apply(ctx context.Context, env *control.Env, in control.Values) error {
	size, err := parseSwapSize(in.String("size"))
	if err != nil {
		return err
	}
	path := strings.TrimSpace(in.String("path"))
	if err := validSwapPath(path); err != nil {
		return err
	}
	if active := activeSwap(ctx, env); len(active) > 0 && !env.Rec.Has(swapID) {
		env.Log.Infof("this server already has swap (%s). Nothing created", strings.Join(active, ", "))
		return nil
	}
	if env.Rec.Has(swapID) {
		return s.repair(ctx, env)
	}
	if files.Exists(env.Path(path)) {
		return fmt.Errorf("%s exists already. Choose another path", path)
	}
	dir := filepath.Dir(path)
	if out, err := env.Run.Run(ctx, "findmnt", "-n", "-o", "FSTYPE", "-T", dir); err == nil {
		switch t := strings.TrimSpace(string(out)); t {
		case "btrfs", "zfs", "tmpfs", "overlay", "nfs", "nfs4", "cifs":
			return fmt.Errorf("%s is on %s, where a swap file does not work reliably. Choose a path on ext4 or xfs", dir, t)
		}
	}
	free, err := freeBytes(ctx, env, dir)
	if err != nil {
		return fmt.Errorf("cannot tell how much room %s has: %w", dir, err)
	}
	const margin = 1 << 30
	if free < size+margin {
		return fmt.Errorf("%s has %d MiB free. A %s swap file needs that plus 1 GiB of margin", dir, free>>20, in.String("size"))
	}

	if err := env.Rec.Put(swapID, "path", path); err != nil {
		return err
	}
	undo := func() {
		_, _ = env.Run.Run(ctx, "swapoff", path)
		_ = os.Remove(env.Path(path))
		_ = restoreFile(env, swapID, "/etc/fstab")
		_ = env.Rec.Delete(swapID)
	}
	// The file is created for root only before anything is written to it.
	f, err := os.OpenFile(env.Path(path), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		_ = env.Rec.Delete(swapID)
		return err
	}
	f.Close()
	sz := strconv.FormatInt(size, 10)
	if _, err := env.Run.Run(ctx, "fallocate", "-l", sz, path); err != nil {
		// Some filesystems cannot preallocate: write zeros instead.
		if out, err := env.Run.Run(ctx, "dd", "if=/dev/zero", "of="+path, "bs=1M", "count="+strconv.FormatInt(size>>20, 10)); err != nil {
			undo()
			return fmt.Errorf("cannot fill the swap file: %w: %s", err, strings.TrimSpace(string(out)))
		}
	}
	if out, err := env.Run.Run(ctx, "mkswap", path); err != nil {
		undo()
		return fmt.Errorf("mkswap failed: %w: %s", err, strings.TrimSpace(string(out)))
	}
	fstab, err := readFstab(env)
	if err != nil {
		undo()
		return err
	}
	line := path + " none swap sw 0 0"
	if err := putFile(env, swapID, "/etc/fstab", strings.TrimRight(fstab, "\n")+"\n"+managed(swapID)+"\n"+line+"\n", 0o644); err != nil {
		undo()
		return err
	}
	if out, err := env.Run.Run(ctx, "swapon", path); err != nil {
		undo()
		return fmt.Errorf("swapon failed: %w: %s", err, strings.TrimSpace(string(out)))
	}
	env.Log.Infof("swap file %s, %s, is active and comes back after a reboot", path, in.String("size"))
	return nil
}

// repair finishes a swap file that this control made earlier and that is no
// longer fully in place: switched off, or readable by others. The size and the
// path that were asked this time do not change the file that exists.
func (s *swapfile) repair(ctx context.Context, env *control.Env) error {
	path, _, _ := env.Rec.Get(swapID, "path")
	fi, err := os.Stat(env.Path(path))
	if err != nil {
		return fmt.Errorf("the swap file %s is gone. Revert this control and apply it again", path)
	}
	if fi.Mode().Perm()&0o077 != 0 {
		if err := os.Chmod(env.Path(path), 0o600); err != nil {
			return err
		}
	}
	if !contains(activeSwap(ctx, env), path) {
		if out, err := env.Run.Run(ctx, "swapon", path); err != nil {
			return fmt.Errorf("swapon failed: %w: %s", err, strings.TrimSpace(string(out)))
		}
	}
	env.Log.Infof("swap file %s is active again", path)
	return nil
}

func (s *swapfile) Revert(ctx context.Context, env *control.Env) error {
	if !env.Rec.Has(swapID) {
		env.Log.Warnf("%s: no record, leaving swap alone", swapID)
		return nil
	}
	path, _, _ := env.Rec.Get(swapID, "path")
	if contains(activeSwap(ctx, env), path) {
		if out, err := env.Run.Run(ctx, "swapoff", path); err != nil {
			return fmt.Errorf("cannot turn swap off, probably because there is not enough free memory: %w: %s. Free memory and revert again", err, strings.TrimSpace(string(out)))
		}
	}
	if err := restoreFile(env, swapID, "/etc/fstab"); err != nil {
		return err
	}
	if err := os.Remove(env.Path(path)); err != nil && !os.IsNotExist(err) {
		return err
	}
	return env.Rec.Delete(swapID)
}
