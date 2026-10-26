// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Danang Galuh Tegar Prasetyo

// Package sshd writes sshd settings the same way for every system.
//
// Every SSH control owns one drop-in in /etc/ssh/sshd_config.d/. sshd uses the
// first value it reads and reads the files in name order, so the drop-ins are
// named 00-server-hardening-<name>.conf and win over provider files such as
// 50-cloud-init.conf. After every change the helpers let sshd check the whole
// configuration (sshd -t), reload it, and read back the effective settings
// (sshd -T) to make sure the setting really is in force.
package sshd

import (
	"context"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/danang-id/server-hardening/internal/control"
	"github.com/danang-id/server-hardening/internal/files"
	"github.com/danang-id/server-hardening/internal/kit"
	"github.com/danang-id/server-hardening/internal/systemd"
)

// Dir is the folder of the drop-ins.
const Dir = "/etc/ssh/sshd_config.d/"

// Directive is one line of a drop-in.
type Directive struct{ Key, Value string }

// Server says how a system runs sshd. The settings and the checks are the
// same everywhere. Only these three things differ.
type Server struct {
	// Service is the systemd unit that runs sshd ("ssh" or "sshd").
	Service string
	// Install makes sure the OpenSSH server is installed.
	Install func(ctx context.Context, env *control.Env) error
	// PrivSepDir is a folder that sshd -t needs to exist even when the service
	// is not running ("/run/sshd" on Debian). Empty when the system needs none.
	PrivSepDir string
}

// File is the drop-in of the control called name.
func File(name string) string { return Dir + "00-server-hardening-" + name + ".conf" }

// Render writes the content of a control's drop-in.
func Render(id string, ds []Directive) string {
	var b strings.Builder
	b.WriteString(kit.Marker(id))
	b.WriteString("\n")
	for _, d := range ds {
		fmt.Fprintf(&b, "%s %s\n", d.Key, d.Value)
	}
	return b.String()
}

// Parse reads the directives back from a drop-in.
func Parse(content string) []Directive {
	var out []Directive
	for l := range strings.SplitSeq(content, "\n") {
		l = strings.TrimSpace(l)
		if l == "" || strings.HasPrefix(l, "#") {
			continue
		}
		k, v, _ := strings.Cut(l, " ")
		out = append(out, Directive{k, strings.TrimSpace(v)})
	}
	return out
}

// Effective runs sshd -T and returns the settings that are in force, keyed by
// lower-case name, one entry per line sshd printed.
func Effective(ctx context.Context, env *control.Env) (map[string][]string, error) {
	out, err := env.Run.Run(ctx, "sshd", "-T")
	if err != nil {
		return nil, fmt.Errorf("reading the effective sshd configuration: %w", err)
	}
	m := map[string][]string{}
	for l := range strings.SplitSeq(string(out), "\n") {
		k, v, _ := strings.Cut(strings.TrimSpace(l), " ")
		if k != "" {
			m[strings.ToLower(k)] = append(m[strings.ToLower(k)], strings.TrimSpace(v))
		}
	}
	return m, nil
}

// tokenKeys hold a list of names. sshd -T prints them one per line.
var tokenKeys = map[string]bool{"allowusers": true, "allowgroups": true, "denyusers": true, "denygroups": true}

func normalized(key string, vals []string) []string {
	var out []string
	for _, v := range vals {
		if tokenKeys[key] {
			out = append(out, strings.Fields(v)...)
		} else {
			out = append(out, v)
		}
	}
	sort.Strings(out)
	return out
}

// Mismatches lists the directives whose effective value differs from what
// the drop-in asks for.
func Mismatches(eff map[string][]string, want []Directive) []string {
	byKey := map[string][]string{}
	var order []string
	for _, d := range want {
		k := strings.ToLower(d.Key)
		if _, ok := byKey[k]; !ok {
			order = append(order, k)
		}
		byKey[k] = append(byKey[k], d.Value)
	}
	var bad []string
	for _, k := range order {
		w, g := normalized(k, byKey[k]), normalized(k, eff[k])
		if strings.Join(w, "\x00") != strings.Join(g, "\x00") {
			bad = append(bad, fmt.Sprintf("%s is %q, wanted %q", k, strings.Join(g, " "), strings.Join(w, " ")))
		}
	}
	return bad
}

// Check compares a drop-in with the effective configuration.
func Check(ctx context.Context, env *control.Env, id, name string) (control.State, error) {
	b, err := files.ReadOptional(env.Path(File(name)))
	if err != nil || !strings.Contains(string(b), kit.Marker(id)) {
		return control.NotApplied, err
	}
	eff, err := Effective(ctx, env)
	if err != nil {
		return control.Partial, nil
	}
	if len(Mismatches(eff, Parse(string(b)))) > 0 {
		return control.Partial, nil
	}
	return control.Applied, nil
}

// Validate lets sshd check the whole configuration.
func (s Server) Validate(ctx context.Context, env *control.Env) error {
	if s.PrivSepDir != "" {
		// sshd -t needs this directory even when the service is not running.
		if err := os.MkdirAll(env.Path(s.PrivSepDir), 0o755); err != nil {
			return err
		}
	}
	_, err := env.Run.Run(ctx, "sshd", "-t")
	return err
}

// Reload makes sshd read its configuration. Running sessions stay.
func (s Server) Reload(ctx context.Context, env *control.Env) error {
	if !systemd.IsActive(ctx, env, s.Service) {
		// Started through its socket and idle: it reads the file on the next connection.
		env.Log.Infof("sshd is not running now, it reads the new settings on the next connection")
		return nil
	}
	_, err := env.Run.Run(ctx, "systemctl", "reload", s.Service)
	return err
}

// Apply writes the drop-in of a control and makes it take effect. If the
// configuration is refused, reloading fails, or another setting overrides the
// drop-in, the previous state is put back and the error says why.
func (s Server) Apply(ctx context.Context, env *control.Env, id, name string, ds []Directive) error {
	if err := s.Install(ctx, env); err != nil {
		return err
	}
	path := env.Path(File(name))
	if err := env.Rec.Backup(id, path); err != nil {
		return err
	}
	rollback := func() {
		_, _ = env.Rec.Restore(id, path)
		_ = s.Reload(ctx, env)
	}
	if err := files.WriteAtomic(path, []byte(Render(id, ds)), 0o644); err != nil {
		return err
	}
	if err := s.Validate(ctx, env); err != nil {
		rollback()
		return fmt.Errorf("sshd refused the configuration, nothing was changed: %w", err)
	}
	if err := s.Reload(ctx, env); err != nil {
		rollback()
		return fmt.Errorf("reloading sshd: %w", err)
	}
	eff, err := Effective(ctx, env)
	if err != nil {
		rollback()
		return err
	}
	if bad := Mismatches(eff, ds); len(bad) > 0 {
		rollback()
		return fmt.Errorf("another sshd setting overrides this one, so it was undone (%s)", strings.Join(bad, "; "))
	}
	return env.Rec.Put(id, "applied", "yes")
}

// Revert removes the drop-in of a control (or puts an earlier file back).
func (s Server) Revert(ctx context.Context, env *control.Env, id, name string) error {
	if !env.Rec.Has(id) {
		env.Log.Warnf("%s: no record, leaving the sshd settings alone", id)
		return nil
	}
	if _, err := env.Rec.Restore(id, env.Path(File(name))); err != nil {
		return err
	}
	if err := s.Validate(ctx, env); err != nil {
		return fmt.Errorf("sshd refuses the configuration after the revert: %w", err)
	}
	if err := s.Reload(ctx, env); err != nil {
		return err
	}
	return env.Rec.Delete(id)
}

// Query lists what this OpenSSH supports, for example "kex" or "cipher".
func Query(ctx context.Context, env *control.Env, what string) ([]string, error) {
	out, err := env.Run.Run(ctx, "ssh", "-Q", what)
	if err != nil {
		return nil, err
	}
	return strings.Fields(string(out)), nil
}
