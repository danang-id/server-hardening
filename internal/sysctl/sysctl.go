// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Danang Galuh Tegar Prasetyo

// Package sysctl sets kernel parameters the same way for every system.
//
// Each control owns one file in /etc/sysctl.d/. The name starts with 99, so it
// is read after the distribution's own files and wins over them. The values
// are also set in the running kernel, and the values they replace are
// recorded, so a revert puts the running kernel back without a reboot.
package sysctl

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/danang-id/server-hardening/internal/control"
	"github.com/danang-id/server-hardening/internal/files"
	"github.com/danang-id/server-hardening/internal/kit"
)

// Setting is one kernel parameter and the value it is set to.
type Setting struct{ Key, Value string }

// File is the drop-in a control called name writes.
func File(name string) string { return "/etc/sysctl.d/99-server-hardening-" + name + ".conf" }

// norm makes values comparable: the kernel prints several values separated by tabs.
func norm(v string) string { return strings.Join(strings.Fields(v), " ") }

// Get reads a running value. ok is false when the kernel has no such parameter
// (for example IPv6 parameters on a system without IPv6).
func Get(ctx context.Context, env *control.Env, key string) (string, bool) {
	out, err := env.Run.Run(ctx, "sysctl", "-n", key)
	if err != nil {
		return "", false
	}
	return norm(string(out)), true
}

// Render writes the content of a control's drop-in.
func Render(id string, want []Setting) string {
	var b strings.Builder
	b.WriteString(kit.Marker(id))
	b.WriteString("\n")
	for _, s := range want {
		fmt.Fprintf(&b, "%s = %s\n", s.Key, s.Value)
	}
	return b.String()
}

// Parse reads the settings back from a drop-in.
func Parse(content string) []Setting {
	var out []Setting
	for l := range strings.SplitSeq(content, "\n") {
		l = strings.TrimSpace(l)
		if l == "" || strings.HasPrefix(l, "#") || strings.HasPrefix(l, ";") {
			continue
		}
		if k, v, ok := strings.Cut(l, "="); ok {
			out = append(out, Setting{strings.TrimSpace(k), norm(v)})
		}
	}
	return out
}

func recordedKeys(env *control.Env, id string) ([]string, error) {
	v, _, err := env.Rec.Get(id, "keys")
	if err != nil {
		return nil, err
	}
	return strings.Fields(v), nil
}

// Apply writes the file and sets the values. Parameters the kernel does
// not have are left out and returned in skipped. If a value does not take
// effect, everything is put back.
func Apply(ctx context.Context, env *control.Env, id, name string, want []Setting) (skipped []string, err error) {
	path := env.Path(File(name))
	var use []Setting
	for _, s := range want {
		if _, ok := Get(ctx, env, s.Key); !ok {
			skipped = append(skipped, s.Key)
			continue
		}
		use = append(use, s)
	}
	if len(use) == 0 {
		return skipped, fmt.Errorf("the kernel has none of these parameters")
	}

	// Record the running values the first time a key is touched.
	old, err := recordedKeys(env, id)
	if err != nil {
		return nil, err
	}
	have := map[string]bool{}
	for _, k := range old {
		have[k] = true
	}
	keys := append([]string(nil), old...)
	for _, s := range use {
		if have[s.Key] {
			continue
		}
		cur, _ := Get(ctx, env, s.Key)
		if err := env.Rec.Put(id, "prev:"+s.Key, cur); err != nil {
			return nil, err
		}
		keys = append(keys, s.Key)
		have[s.Key] = true
	}
	// Keys an earlier run set and this run no longer does go back to their old values.
	inUse := map[string]bool{}
	for _, s := range use {
		inUse[s.Key] = true
	}
	var kept []string
	for _, k := range keys {
		if inUse[k] {
			kept = append(kept, k)
			continue
		}
		if prev, ok, _ := env.Rec.Get(id, "prev:"+k); ok {
			_, _ = env.Run.Run(ctx, "sysctl", "-w", k+"="+prev)
		}
	}
	if err := env.Rec.Put(id, "keys", strings.Join(kept, " ")); err != nil {
		return nil, err
	}

	if err := env.Rec.Backup(id, path); err != nil {
		return nil, err
	}
	if err := files.WriteAtomic(path, []byte(Render(id, use)), 0o644); err != nil {
		return nil, err
	}
	rollback := func() {
		_, _ = env.Rec.Restore(id, path)
		for _, s := range use {
			if prev, ok, _ := env.Rec.Get(id, "prev:"+s.Key); ok {
				_, _ = env.Run.Run(ctx, "sysctl", "-w", s.Key+"="+prev)
			}
		}
	}
	if _, err := env.Run.Run(ctx, "sysctl", "-p", path); err != nil {
		rollback()
		return nil, fmt.Errorf("the kernel refused the settings, nothing was changed: %w", err)
	}
	if bad := Mismatches(ctx, env, use); len(bad) > 0 {
		rollback()
		return nil, fmt.Errorf("the kernel did not take the settings, so they were undone (%s)", strings.Join(bad, "; "))
	}
	return skipped, env.Rec.Put(id, "applied", "yes")
}

// Mismatches lists the settings the running kernel does not have.
func Mismatches(ctx context.Context, env *control.Env, want []Setting) []string {
	var bad []string
	for _, s := range want {
		got, ok := Get(ctx, env, s.Key)
		if !ok {
			continue // the parameter disappeared, for example with a module
		}
		if got != norm(s.Value) {
			bad = append(bad, fmt.Sprintf("%s is %q, wanted %q", s.Key, got, norm(s.Value)))
		}
	}
	return bad
}

// Check compares the file and the running kernel.
func Check(ctx context.Context, env *control.Env, id, name string) (control.State, error) {
	b, err := files.ReadOptional(env.Path(File(name)))
	if err != nil || !strings.Contains(string(b), kit.Marker(id)) {
		return control.NotApplied, err
	}
	if len(Mismatches(ctx, env, Parse(string(b)))) > 0 {
		return control.Partial, nil
	}
	return control.Applied, nil
}

// Revert removes the file and puts the recorded running values back.
func Revert(ctx context.Context, env *control.Env, id, name string) error {
	if !env.Rec.Has(id) {
		env.Log.Warnf("%s: no record, leaving the kernel settings alone", id)
		return nil
	}
	if _, err := env.Rec.Restore(id, env.Path(File(name))); err != nil {
		return err
	}
	keys, err := recordedKeys(env, id)
	if err != nil {
		return err
	}
	sort.Strings(keys)
	for _, k := range keys {
		prev, ok, _ := env.Rec.Get(id, "prev:"+k)
		if !ok {
			continue
		}
		if _, err := env.Run.Run(ctx, "sysctl", "-w", k+"="+prev); err != nil {
			env.Log.Warnf("%s: could not set %s back to %s: %v", id, k, prev, err)
		}
	}
	return env.Rec.Delete(id)
}
