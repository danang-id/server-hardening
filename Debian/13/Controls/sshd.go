// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Danang Galuh Tegar Prasetyo

package controls

import (
	"context"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/danang-id/server-hardening/internal/apt"
	"github.com/danang-id/server-hardening/internal/control"
	"github.com/danang-id/server-hardening/internal/files"
	"github.com/danang-id/server-hardening/internal/systemd"
)

// Shared helpers for the controls that write sshd settings.
//
// Every SSH control owns one drop-in in /etc/ssh/sshd_config.d/. sshd uses the
// first value it reads and reads the files in name order, so the drop-ins are
// named 00-server-hardening-<name>.conf and win over provider files such as
// 50-cloud-init.conf. After every change the helpers let sshd check the whole
// configuration (sshd -t), reload it, and read back the effective settings
// (sshd -T) to make sure the setting really is in force.

const (
	sshdDir     = "/etc/ssh/sshd_config.d/"
	sshdService = "ssh"
	sshdPackage = "openssh-server"
)

type directive struct{ Key, Value string }

func sshdFile(name string) string { return sshdDir + "00-server-hardening-" + name + ".conf" }
func sshdMarker(id string) string {
	return "# Managed by github.com/danang-id/server-hardening (" + id + ")"
}

func renderSSHD(id string, ds []directive) string {
	var b strings.Builder
	b.WriteString(sshdMarker(id))
	b.WriteString("\n")
	for _, d := range ds {
		fmt.Fprintf(&b, "%s %s\n", d.Key, d.Value)
	}
	return b.String()
}

// parseSSHD reads the directives back from a drop-in.
func parseSSHD(content string) []directive {
	var out []directive
	for l := range strings.SplitSeq(content, "\n") {
		l = strings.TrimSpace(l)
		if l == "" || strings.HasPrefix(l, "#") {
			continue
		}
		k, v, _ := strings.Cut(l, " ")
		out = append(out, directive{k, strings.TrimSpace(v)})
	}
	return out
}

// sshdEffective runs sshd -T and returns the settings that are in force,
// keyed by lower-case name, one entry per line sshd printed.
func sshdEffective(ctx context.Context, env *control.Env) (map[string][]string, error) {
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

// sshdMismatches lists the directives whose effective value differs from what
// the drop-in asks for.
func sshdMismatches(eff map[string][]string, want []directive) []string {
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

// sshdCheck compares a drop-in with the effective configuration.
func sshdCheck(ctx context.Context, env *control.Env, id, name string) (control.State, error) {
	b, err := files.ReadOptional(env.Path(sshdFile(name)))
	if err != nil || !strings.Contains(string(b), sshdMarker(id)) {
		return control.NotApplied, err
	}
	eff, err := sshdEffective(ctx, env)
	if err != nil {
		return control.Partial, nil
	}
	if len(sshdMismatches(eff, parseSSHD(string(b)))) > 0 {
		return control.Partial, nil
	}
	return control.Applied, nil
}

// sshdValidate lets sshd check the whole configuration.
func sshdValidate(ctx context.Context, env *control.Env) error {
	// sshd -t needs this directory even when the service is not running.
	if err := os.MkdirAll(env.Path("/run/sshd"), 0o755); err != nil {
		return err
	}
	_, err := env.Run.Run(ctx, "sshd", "-t")
	return err
}

// sshdReload makes sshd read its configuration. Running sessions stay.
func sshdReload(ctx context.Context, env *control.Env) error {
	if !systemd.IsActive(ctx, env, sshdService) {
		// Started through its socket and idle: it reads the file on the next connection.
		env.Log.Infof("sshd is not running now, it reads the new settings on the next connection")
		return nil
	}
	_, err := env.Run.Run(ctx, "systemctl", "reload", sshdService)
	return err
}

// sshdApply writes the drop-in of a control and makes it take effect. If the
// configuration is refused, reloading fails, or another setting overrides the
// drop-in, the previous state is put back and the error says why.
func sshdApply(ctx context.Context, env *control.Env, id, name string, ds []directive) error {
	if err := apt.Install(ctx, env, sshdPackage); err != nil {
		return err
	}
	path := env.Path(sshdFile(name))
	if err := env.Rec.Backup(id, path); err != nil {
		return err
	}
	rollback := func() {
		_, _ = env.Rec.Restore(id, path)
		_ = sshdReload(ctx, env)
	}
	if err := files.WriteAtomic(path, []byte(renderSSHD(id, ds)), 0o644); err != nil {
		return err
	}
	if err := sshdValidate(ctx, env); err != nil {
		rollback()
		return fmt.Errorf("sshd refused the configuration, nothing was changed: %w", err)
	}
	if err := sshdReload(ctx, env); err != nil {
		rollback()
		return fmt.Errorf("reloading sshd: %w", err)
	}
	eff, err := sshdEffective(ctx, env)
	if err != nil {
		rollback()
		return err
	}
	if bad := sshdMismatches(eff, ds); len(bad) > 0 {
		rollback()
		return fmt.Errorf("another sshd setting overrides this one, so it was undone (%s)", strings.Join(bad, "; "))
	}
	return env.Rec.Put(id, "applied", "yes")
}

// sshdRevert removes the drop-in of a control (or puts an earlier file back).
func sshdRevert(ctx context.Context, env *control.Env, id, name string) error {
	if !env.Rec.Has(id) {
		env.Log.Warnf("%s: no record, leaving the sshd settings alone", id)
		return nil
	}
	if _, err := env.Rec.Restore(id, env.Path(sshdFile(name))); err != nil {
		return err
	}
	if err := sshdValidate(ctx, env); err != nil {
		return fmt.Errorf("sshd refuses the configuration after the revert: %w", err)
	}
	if err := sshdReload(ctx, env); err != nil {
		return err
	}
	return env.Rec.Delete(id)
}

// sshdQuery lists what this OpenSSH supports, for example "kex" or "cipher".
func sshdQuery(ctx context.Context, env *control.Env, what string) ([]string, error) {
	out, err := env.Run.Run(ctx, "ssh", "-Q", what)
	if err != nil {
		return nil, err
	}
	return strings.Fields(string(out)), nil
}
