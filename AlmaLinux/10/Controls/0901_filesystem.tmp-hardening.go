// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Danang Galuh Tegar Prasetyo

package controls

import (
	"context"
	"fmt"
	"strings"

	"github.com/danang-id/server-hardening/internal/control"
	"github.com/danang-id/server-hardening/internal/systemd"
)

const (
	tmpID     = "filesystem.tmp-hardening"
	tmpDropIn = "/etc/systemd/system/tmp.mount.d/99-server-hardening.conf"
	tmpUnit   = "tmp.mount"
)

type tmpHardening struct{ control.Base }

func init() {
	System.Add(&tmpHardening{control.Base{M: control.Meta{
		ID:       tmpID,
		Category: control.Filesystem,
		Number:   1,
		Title:    "Mount /tmp with restrictive options",
		Default:  true,
		Tags:     []control.Tag{control.TagInput, control.TagCompat},
	}}})
}

func (t *tmpHardening) Inputs(context.Context, *control.Env) ([]control.Input, error) {
	return []control.Input{
		{
			Key: "size", Label: "Size limit of /tmp", Default: "50%",
			Help: "A percentage of RAM (50%) or a size (2G). /tmp is kept in memory.",
			Validate: func(s string) error {
				if !sizeValue.MatchString(strings.TrimSpace(s)) {
					return fmt.Errorf("use a percentage such as 50%% or a size such as 2G")
				}
				return nil
			},
		},
		{
			Key: "noexec", Label: "Block running programs from /tmp?", Kind: control.Choice, Default: "yes",
			Help: "Some installers, build tools and scripts run programs from /tmp and fail when this is on.",
			Options: []control.Option{
				{Value: "yes", Label: "Yes (recommended)"},
				{Value: "no", Label: "No"},
			},
		},
	}, nil
}

func tmpOptions(size string, noexec bool) string {
	o := "mode=1777,strictatime,nosuid,nodev"
	if noexec {
		o += ",noexec"
	}
	return o + ",size=" + size + ",nr_inodes=1m"
}

func tmpDropInContent(size string, noexec bool) string {
	return managed(tmpID) + "\n[Mount]\nOptions=" + tmpOptions(size, noexec) + "\n"
}

func (t *tmpHardening) Check(ctx context.Context, env *control.Env) (control.State, error) {
	if !hasMarker(env, tmpDropIn, tmpID) {
		return control.NotApplied, nil
	}
	set, _, err := mountOptions(ctx, env, "/tmp")
	if err != nil {
		return control.Partial, nil
	}
	want, _, _ := env.Rec.Get(tmpID, "noexec")
	nosuid, nodev, noexec := flagsOf(set)
	if !nosuid || !nodev || noexec != (want != "no") {
		return control.Partial, nil
	}
	return control.Applied, nil
}

func (t *tmpHardening) Apply(ctx context.Context, env *control.Env, in control.Values) error {
	size := strings.TrimSpace(in.String("size"))
	if !sizeValue.MatchString(size) {
		return fmt.Errorf("the size %q is not a percentage or a size", size)
	}
	noexec := in.String("noexec") != "no"
	if line, ok := fstabEntryFor(env, "/tmp"); ok {
		return fmt.Errorf("/etc/fstab has its own entry for /tmp (%s). Set the options there: this control only handles the systemd mount", line)
	}

	set, raw, err := mountOptions(ctx, env, "/tmp")
	if err != nil {
		return err
	}
	fsType := "tmpfs"
	if out, err := env.Run.Run(ctx, "findmnt", "-n", "-o", "FSTYPE", "-T", "/tmp"); err == nil {
		fsType = strings.TrimSpace(string(out))
	}
	if !env.Rec.Has(tmpID) {
		nosuid, nodev, ne := flagsOf(set)
		for k, v := range map[string]string{"flags": fmt.Sprintf("%t,%t,%t", nosuid, nodev, ne), "was-options": raw} {
			if err := env.Rec.Put(tmpID, k, v); err != nil {
				return err
			}
		}
	}
	if err := env.Rec.Put(tmpID, "noexec", yesNo(noexec)); err != nil {
		return err
	}
	if err := putFile(env, tmpID, tmpDropIn, tmpDropInContent(size, noexec), 0o644); err != nil {
		return err
	}
	if _, err := env.Run.Run(ctx, "systemctl", "daemon-reload"); err != nil {
		_ = restoreFile(env, tmpID, tmpDropIn)
		return err
	}
	if fsType != "tmpfs" {
		env.Log.Warnf("/tmp is on %s here, not tmpfs. Enabling the systemd /tmp mount puts a tmpfs over it: files now in /tmp are hidden until the next reboot", fsType)
		if err := recordUnit(ctx, env, tmpID, tmpUnit); err != nil {
			return err
		}
		if err := env.Rec.Put(tmpID, "turned-on", "yes"); err != nil {
			return err
		}
		if err := systemd.EnableNow(ctx, env, tmpUnit); err != nil {
			_ = restoreFile(env, tmpID, tmpDropIn)
			_, _ = env.Run.Run(ctx, "systemctl", "daemon-reload")
			return fmt.Errorf("cannot start the /tmp mount: %w", err)
		}
	} else if _, err := env.Run.Run(ctx, "systemctl", "reload", tmpUnit); err != nil {
		// The unit could not remount. Do the same by hand.
		if err := remountFlags(ctx, env, "/tmp", true, true, noexec); err != nil {
			env.Log.Warnf("%v. The new options apply at the next reboot", err)
			return nil
		}
	}
	got, _, err := mountOptions(ctx, env, "/tmp")
	if err == nil {
		if nosuid, nodev, ne := flagsOf(got); !nosuid || !nodev || ne != noexec {
			env.Log.Warnf("/tmp does not show the new options yet. They apply at the next reboot")
		}
	}
	if noexec {
		env.Log.Infof("programs can no longer run from /tmp")
	}
	return nil
}

func (t *tmpHardening) Revert(ctx context.Context, env *control.Env) error {
	if !env.Rec.Has(tmpID) {
		env.Log.Warnf("%s: no record, leaving /tmp alone", tmpID)
		return nil
	}
	if err := restoreFile(env, tmpID, tmpDropIn); err != nil {
		return err
	}
	if _, err := env.Run.Run(ctx, "systemctl", "daemon-reload"); err != nil {
		return err
	}
	if v, _, _ := env.Rec.Get(tmpID, "turned-on"); v == "yes" {
		// This control turned the /tmp mount on: turn it off again.
		if err := restoreUnit(ctx, env, tmpID, tmpUnit); err != nil {
			return err
		}
	} else {
		f, _, _ := env.Rec.Get(tmpID, "flags")
		var nosuid, nodev, noexec bool
		fmt.Sscanf(strings.ReplaceAll(f, ",", " "), "%t %t %t", &nosuid, &nodev, &noexec)
		if _, err := env.Run.Run(ctx, "systemctl", "reload", tmpUnit); err != nil {
			if err := remountFlags(ctx, env, "/tmp", nosuid, nodev, noexec); err != nil {
				return err
			}
		}
		// The unit's own options win over the old flags only if they differ: set them by hand to be sure.
		if got, _, err := mountOptions(ctx, env, "/tmp"); err == nil {
			if a, b, c := flagsOf(got); a != nosuid || b != nodev || c != noexec {
				if err := remountFlags(ctx, env, "/tmp", nosuid, nodev, noexec); err != nil {
					return err
				}
			}
		}
	}
	return env.Rec.Delete(tmpID)
}

// fstabEntryFor returns the /etc/fstab line of a mount point.
func fstabEntryFor(env *control.Env, mnt string) (string, bool) {
	c, err := readFstab(env)
	if err != nil {
		return "", false
	}
	l, ok := fstabHas(c, mnt)
	return strings.TrimSpace(l.Raw), ok
}
