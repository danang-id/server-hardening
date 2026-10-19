// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Danang Galuh Tegar Prasetyo

package controls

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/danang-id/server-hardening/internal/apt"
	"github.com/danang-id/server-hardening/internal/control"
	"github.com/danang-id/server-hardening/internal/files"
	"github.com/danang-id/server-hardening/internal/systemd"
)

const (
	dnsID       = "network.dns-resolver"
	resolvedCfg = "/etc/systemd/resolved.conf.d/00-server-hardening.conf"
	resolvConf  = "/etc/resolv.conf"
	resolvStub  = "/run/systemd/resolve/stub-resolv.conf"
)

type dnsResolver struct{ control.Base }

func init() {
	System.Add(&dnsResolver{control.Base{M: control.Meta{
		ID:           dnsID,
		Category:     control.Network,
		Number:       7,
		Title:        "Resolve names through systemd-resolved",
		Default:      false,
		Weight:       810,
		Requires:     []string{networkdID},
		Tags:         []control.Tag{control.TagInput},
		RevertLimits: "The systemd-resolved package stays installed.",
	}}})
}

var (
	dotModes    = map[string]bool{"no": true, "opportunistic": true, "yes": true}
	dnssecModes = map[string]bool{"no": true, "allow-downgrade": true, "yes": true}
)

func (d *dnsResolver) Inputs(_ context.Context, env *control.Env) ([]control.Input, error) {
	var current []string
	for _, p := range []string{"/run/systemd/resolve/resolv.conf", resolvConf} {
		if b, err := files.ReadOptional(env.Path(p)); err == nil && b != nil {
			if s := resolvConfServers(string(b)); len(s) > 0 {
				current = s
				break
			}
		}
	}
	return []control.Input{
		{Key: "dns", Label: "DNS servers (separated by spaces)", Default: strings.Join(current, " "),
			Help: "Default: the servers the provider handed out.",
			Validate: func(s string) error {
				if len(strings.Fields(s)) == 0 {
					return fmt.Errorf("enter at least one DNS server")
				}
				return validAddrList(s, false)
			}},
		{Key: "dot", Label: "DNS over TLS", Kind: control.Choice, Default: "opportunistic", Options: []control.Option{
			{Value: "no", Label: "No"},
			{Value: "opportunistic", Label: "Opportunistic: use TLS when the server offers it"},
			{Value: "yes", Label: "Yes: only over TLS", Help: "Lookups fail if the servers do not support DNS over TLS (port 853)."},
		}},
		{Key: "dnssec", Label: "DNSSEC validation", Kind: control.Choice, Default: "allow-downgrade", Options: []control.Option{
			{Value: "no", Label: "No"},
			{Value: "allow-downgrade", Label: "Validate when the server supports it"},
			{Value: "yes", Label: "Always validate", Help: "Breaks lookups for domains with broken signatures."},
		}},
	}, nil
}

func renderResolved(servers []string, dot, dnssec string) string {
	return fmt.Sprintf("%s\n[Resolve]\nDNS=%s\nFallbackDNS=\nDNSOverTLS=%s\nDNSSEC=%s\n",
		sshdMarker(dnsID), strings.Join(servers, " "), dot, dnssec)
}

func (d *dnsResolver) Check(ctx context.Context, env *control.Env) (control.State, error) {
	b, err := files.ReadOptional(env.Path(resolvedCfg))
	if err != nil || !strings.Contains(string(b), sshdMarker(dnsID)) {
		return control.NotApplied, err
	}
	target, err := os.Readlink(env.Path(resolvConf))
	if err != nil || target != resolvStub || !systemd.IsActive(ctx, env, "systemd-resolved") {
		return control.Partial, nil
	}
	return control.Applied, nil
}

// portInUse finds another program that holds the DNS port on all addresses.
func dnsPortHolder(ctx context.Context, env *control.Env) string {
	out, err := env.Run.Run(ctx, "ss", "-H", "-lntup")
	if err != nil {
		return ""
	}
	for l := range strings.SplitSeq(string(out), "\n") {
		f := strings.Fields(l)
		if len(f) < 5 || !(strings.HasSuffix(f[4], ":53")) {
			continue
		}
		host := strings.TrimSuffix(f[4], ":53")
		if (host == "0.0.0.0" || host == "[::]" || host == "*") && !strings.Contains(l, "systemd-resolve") {
			if m := processName.FindStringSubmatch(l); m != nil {
				return m[1]
			}
			return "another program"
		}
	}
	return ""
}

func (d *dnsResolver) Apply(ctx context.Context, env *control.Env, in control.Values) error {
	servers := strings.Fields(in.String("dns"))
	dot, dnssec := in.String("dot"), in.String("dnssec")
	if len(servers) == 0 {
		return fmt.Errorf("enter at least one DNS server")
	}
	if err := validAddrList(strings.Join(servers, " "), false); err != nil {
		return err
	}
	if !dotModes[dot] || !dnssecModes[dnssec] {
		return fmt.Errorf("unknown DNS over TLS (%q) or DNSSEC (%q) mode", dot, dnssec)
	}
	if h := dnsPortHolder(ctx, env); h != "" {
		return fmt.Errorf("%s listens on the DNS port (53) on all addresses and would clash with the local resolver. "+
			"Make it listen on its own address only, or leave name resolution as it is", h)
	}
	if err := apt.Install(ctx, env, "systemd-resolved"); err != nil {
		return err
	}

	// Remember how resolv.conf was: a link, or a file.
	if _, ok, _ := env.Rec.Get(dnsID, "resolv"); !ok {
		kind := "file"
		if t, err := os.Readlink(env.Path(resolvConf)); err == nil {
			kind = "link:" + t
		} else if err := env.Rec.Backup(dnsID, env.Path(resolvConf)); err != nil {
			return err
		}
		for k, v := range map[string]string{
			"resolv":         kind,
			"active-before":  yesNo(systemd.IsActive(ctx, env, "systemd-resolved")),
			"enabled-before": yesNo(systemd.IsEnabled(ctx, env, "systemd-resolved")),
		} {
			if err := env.Rec.Put(dnsID, k, v); err != nil {
				return err
			}
		}
	}
	if err := env.Rec.Backup(dnsID, env.Path(resolvedCfg)); err != nil {
		return err
	}
	if err := files.WriteAtomic(env.Path(resolvedCfg), []byte(renderResolved(servers, dot, dnssec)), 0o644); err != nil {
		return err
	}
	rollback := func() { _ = d.undo(ctx, env) }
	if err := systemd.EnableNow(ctx, env, "systemd-resolved"); err != nil {
		rollback()
		return err
	}
	if _, err := env.Run.Run(ctx, "systemctl", "restart", "systemd-resolved"); err != nil {
		rollback()
		return err
	}
	if err := pointResolvConfAtStub(env); err != nil {
		rollback()
		return err
	}
	// A resolver that cannot answer would cut the server off from package mirrors and mail.
	if _, err := env.Run.Run(ctx, "resolvectl", "query", "--legend=no", "deb.debian.org"); err != nil {
		rollback()
		return fmt.Errorf("a test lookup failed with the new settings, so they were undone. "+
			"With DNS over TLS set to yes, the servers must support it: %w", err)
	}
	env.Log.Infof("names are resolved through systemd-resolved (%s)", strings.Join(servers, ", "))
	return nil
}

func pointResolvConfAtStub(env *control.Env) error {
	p := env.Path(resolvConf)
	if err := os.Remove(p); err != nil && !os.IsNotExist(err) {
		return err
	}
	return os.Symlink(resolvStub, p)
}

// undo puts the earlier name resolution back.
func (d *dnsResolver) undo(ctx context.Context, env *control.Env) error {
	if _, err := env.Rec.Restore(dnsID, env.Path(resolvedCfg)); err != nil {
		return err
	}
	kind, _, _ := env.Rec.Get(dnsID, "resolv")
	p := env.Path(resolvConf)
	switch {
	case strings.HasPrefix(kind, "link:"):
		_ = os.Remove(p)
		if err := os.Symlink(strings.TrimPrefix(kind, "link:"), p); err != nil {
			return err
		}
	case kind == "file":
		_ = os.Remove(p) // the link now belongs to this control; the backup is a file
		if _, err := env.Rec.Restore(dnsID, p); err != nil {
			return err
		}
	}
	if v, _, _ := env.Rec.Get(dnsID, "active-before"); v == "yes" {
		_, err := env.Run.Run(ctx, "systemctl", "restart", "systemd-resolved")
		return err
	}
	if v, _, _ := env.Rec.Get(dnsID, "enabled-before"); v == "yes" {
		_, err := env.Run.Run(ctx, "systemctl", "stop", "systemd-resolved") // enabled but not running before
		return err
	}
	return systemd.DisableNow(ctx, env, "systemd-resolved")
}

func (d *dnsResolver) Revert(ctx context.Context, env *control.Env) error {
	if !env.Rec.Has(dnsID) {
		env.Log.Warnf("%s: no record, leaving name resolution alone", dnsID)
		return nil
	}
	if err := d.undo(ctx, env); err != nil {
		return err
	}
	return env.Rec.Delete(dnsID)
}
