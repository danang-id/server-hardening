// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Danang Galuh Tegar Prasetyo

package controls

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/danang-id/server-hardening/internal/control"
	"github.com/danang-id/server-hardening/internal/files"
)

const (
	hostnameID       = "baseline.hostname"
	hostnameFile     = "/etc/hostname"
	cloudInitPreserv = "/etc/cloud/cloud.cfg.d/99-server-hardening-hostname.cfg"
)

type hostname struct{ control.Base }

func init() {
	System.Add(&hostname{control.Base{M: control.Meta{
		ID:       hostnameID,
		Category: control.Baseline,
		Number:   1,
		Title:    "Set the hostname",
		Default:  true,
		Tags:     []control.Tag{control.TagInput},
	}}})
}

var label = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)

// validFQDN accepts a fully qualified name such as web-1.example.com.
func validFQDN(s string) error {
	if len(s) > 253 {
		return fmt.Errorf("too long")
	}
	parts := strings.Split(strings.ToLower(s), ".")
	if len(parts) < 2 {
		return fmt.Errorf("enter a fully qualified name, such as web-1.example.com")
	}
	for _, p := range parts {
		if !label.MatchString(p) {
			return fmt.Errorf("%q is not a valid name part (letters, digits and hyphens only)", p)
		}
	}
	return nil
}

func currentHostname(env *control.Env) (string, error) {
	b, err := files.ReadOptional(env.Path(hostnameFile))
	return strings.TrimSpace(string(b)), err
}

func (h *hostname) Inputs(_ context.Context, env *control.Env) ([]control.Input, error) {
	cur, err := currentHostname(env)
	if err != nil {
		return nil, err
	}
	return []control.Input{{
		Key:      "hostname",
		Label:    "Fully qualified hostname",
		Help:     "For example web-1.example.com",
		Default:  cur,
		Validate: validFQDN,
	}}, nil
}

// Check reports Applied when this control set a name earlier and the server
// still has it.
func (h *hostname) Check(_ context.Context, env *control.Env) (control.State, error) {
	want, ok, err := env.Rec.Get(hostnameID, "applied")
	if err != nil || !ok {
		return control.NotApplied, err
	}
	cur, err := currentHostname(env)
	if err != nil {
		return control.NotApplied, err
	}
	if cur == want {
		return control.Applied, nil
	}
	return control.NotApplied, nil
}

func (h *hostname) Apply(ctx context.Context, env *control.Env, in control.Values) error {
	name := strings.ToLower(in.String("hostname"))
	if err := validFQDN(name); err != nil {
		return err
	}
	// Record the previous state before changing anything.
	prev, err := currentHostname(env)
	if err != nil {
		return err
	}
	if err := env.Rec.Backup(hostnameID, env.Path(hostnameFile)); err != nil {
		return err
	}
	if err := env.Rec.Put(hostnameID, "previous", prev); err != nil {
		return err
	}

	if err := files.WriteAtomic(env.Path(hostnameFile), []byte(name+"\n"), 0o644); err != nil {
		return err
	}
	if _, err := env.Run.Run(ctx, "hostnamectl", "set-hostname", name); err != nil {
		return err
	}

	// cloud-init can reset the hostname at the next boot. Tell it not to.
	if files.Exists(env.Path("/etc/cloud/cloud.cfg.d")) {
		if err := env.Rec.Backup(hostnameID, env.Path(cloudInitPreserv)); err != nil {
			return err
		}
		if err := files.WriteAtomic(env.Path(cloudInitPreserv), []byte("preserve_hostname: true\n"), 0o644); err != nil {
			return err
		}
	}
	env.Log.Infof("hostname set to %s", name)
	return env.Rec.Put(hostnameID, "applied", name)
}

func (h *hostname) Revert(ctx context.Context, env *control.Env) error {
	prev, ok, err := env.Rec.Get(hostnameID, "previous")
	if err != nil {
		return err
	}
	if !ok {
		env.Log.Warnf("%s: no record of the previous hostname, leaving it alone", hostnameID)
		return nil
	}
	for _, p := range []string{hostnameFile, cloudInitPreserv} {
		if _, err := env.Rec.Restore(hostnameID, env.Path(p)); err != nil {
			return err
		}
	}
	if prev != "" {
		if _, err := env.Run.Run(ctx, "hostnamectl", "set-hostname", prev); err != nil {
			return err
		}
	}
	return env.Rec.Delete(hostnameID)
}
