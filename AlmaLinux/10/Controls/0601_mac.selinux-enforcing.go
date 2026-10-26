// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Danang Galuh Tegar Prasetyo

package controls

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/danang-id/server-hardening/internal/control"
	"github.com/danang-id/server-hardening/internal/dnf"
	"github.com/danang-id/server-hardening/internal/files"
)

const (
	selinuxID     = "mac.selinux-enforcing"
	selinuxConfig = "/etc/selinux/config"
)

type selinuxEnforcing struct{ control.Base }

func init() {
	System.Add(&selinuxEnforcing{control.Base{M: control.Meta{
		ID:           selinuxID,
		Category:     control.MAC,
		Number:       1,
		Title:        "Run SELinux in enforcing mode",
		Default:      true,
		Tags:         []control.Tag{control.TagCompat},
		RevertLimits: "The packages stay installed.",
	}}})
}

var selinuxLine = regexp.MustCompile(`(?m)^[ \t]*SELINUX[ \t]*=.*$`)

// selinuxMode returns what the kernel runs now: "Enforcing", "Permissive" or
// "Disabled". A system without the tool is taken as disabled.
func selinuxMode(ctx context.Context, env *control.Env) string {
	out, err := env.Run.Run(ctx, "getenforce")
	if err != nil {
		return "Disabled"
	}
	return strings.TrimSpace(string(out))
}

// selinuxConfigured returns the mode that /etc/selinux/config asks for at boot.
func selinuxConfigured(env *control.Env) (string, error) {
	b, err := files.ReadOptional(env.Path(selinuxConfig))
	if err != nil {
		return "", err
	}
	m := selinuxLine.FindAllString(string(b), -1)
	if len(m) == 0 {
		return "", nil
	}
	_, v, _ := strings.Cut(m[len(m)-1], "=")
	return strings.ToLower(strings.TrimSpace(v)), nil
}

func (s *selinuxEnforcing) Check(ctx context.Context, env *control.Env) (control.State, error) {
	conf, err := selinuxConfigured(env)
	if err != nil {
		return control.NotApplied, err
	}
	switch mode := selinuxMode(ctx, env); {
	case mode == "Enforcing" && conf == "enforcing":
		return control.Applied, nil
	case mode == "Enforcing", mode == "Permissive" && conf == "enforcing":
		return control.Partial, nil // right now or at the next boot, but not both
	}
	return control.NotApplied, nil
}

// withSELinuxMode sets SELINUX= in the content of /etc/selinux/config. The
// file has no spaces around the equal sign, and libselinux needs it that way.
func withSELinuxMode(content, mode string) string {
	line := "SELINUX=" + mode
	if selinuxLine.MatchString(content) {
		done := false
		return selinuxLine.ReplaceAllStringFunc(content, func(string) string {
			if done {
				return "#" + line
			}
			done = true
			return line
		})
	}
	if content != "" && !strings.HasSuffix(content, "\n") {
		content += "\n"
	}
	return content + line + "\n"
}

func (s *selinuxEnforcing) Apply(ctx context.Context, env *control.Env, _ control.Values) error {
	if err := dnf.Install(ctx, env, "libselinux-utils"); err != nil {
		return err
	}
	mode := selinuxMode(ctx, env)
	if mode == "Disabled" {
		// Going from disabled to enforcing needs a reboot and a relabel of every
		// file, which can take long and can stop a server from booting.
		return fmt.Errorf("SELinux is switched off in the kernel. Turning it on needs a reboot and a relabel of the whole disk, "+
			"so do that by hand: set SELINUX=permissive in %s, remove selinux=0 from the kernel command line, "+
			"run \"fixfiles onboot\", reboot, then apply this control", selinuxConfig)
	}
	if _, ok, err := env.Rec.Get(selinuxID, "was-runtime"); err != nil {
		return err
	} else if !ok {
		if err := env.Rec.Put(selinuxID, "was-runtime", mode); err != nil {
			return err
		}
	}
	old, err := files.ReadOptional(env.Path(selinuxConfig))
	if err != nil {
		return err
	}
	if err := env.Rec.Backup(selinuxID, env.Path(selinuxConfig)); err != nil {
		return err
	}
	if err := files.WriteAtomic(env.Path(selinuxConfig), []byte(withSELinuxMode(string(old), "enforcing")), 0o644); err != nil {
		return err
	}
	if mode != "Enforcing" {
		if _, err := env.Run.Run(ctx, "setenforce", "1"); err != nil {
			_, _ = env.Rec.Restore(selinuxID, env.Path(selinuxConfig))
			return fmt.Errorf("switching SELinux to enforcing: %w", err)
		}
	}
	env.Log.Infof("SELinux is enforcing now and at every boot. Look at what it blocked with mac.selinux-audit")
	return env.Rec.Put(selinuxID, "applied", "yes")
}

func (s *selinuxEnforcing) Revert(ctx context.Context, env *control.Env) error {
	if !env.Rec.Has(selinuxID) {
		env.Log.Warnf("%s: no record, leaving SELinux alone", selinuxID)
		return nil
	}
	if _, err := env.Rec.Restore(selinuxID, env.Path(selinuxConfig)); err != nil {
		return err
	}
	if was, _, _ := env.Rec.Get(selinuxID, "was-runtime"); was == "Permissive" && selinuxMode(ctx, env) == "Enforcing" {
		if _, err := env.Run.Run(ctx, "setenforce", "0"); err != nil {
			return fmt.Errorf("switching SELinux back to permissive: %w", err)
		}
	}
	return env.Rec.Delete(selinuxID)
}
