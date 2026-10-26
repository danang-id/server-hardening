// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Danang Galuh Tegar Prasetyo

package controls

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/danang-id/server-hardening/internal/control"
	"github.com/danang-id/server-hardening/internal/dnf"
)

const removeID = "asr.remove-unneeded-packages"

type removeUnneeded struct{ control.Base }

func init() {
	System.Add(&removeUnneeded{control.Base{M: control.Meta{
		ID:       removeID,
		Category: control.ASR,
		Number:   2,
		Title:    "Remove packages a server does not need",
		Default:  true,
		Action:   true,
		Tags:     []control.Tag{control.TagInput, control.TagIrreversible},
		NoRevertReason: "Removed packages cannot be restored together with their configuration. " +
			"Reinstall by hand if needed.",
	}}})
}

// unneeded is a package that a server rarely needs.
type unneeded struct {
	pkg       string
	why       string
	byDefault bool // ticked at first
}

var unneededList = []unneeded{
	{"telnet", "Telnet client. It sends everything, passwords included, in clear text", true},
	{"rsh", "Remote shell client of the old rsh family, without encryption", true},
	{"rsh-server", "Remote shell server of the old rsh family, without encryption", true},
	{"talk", "Old terminal chat client", true},
	{"talk-server", "Old terminal chat server", true},
	{"xinetd", "Super-server that starts old network services on demand", true},
	{"tftp", "Trivial file transfer client. No login, no encryption", true},
	{"tftp-server", "Trivial file transfer server. No login, no encryption", true},
	{"ypbind", "Old network login client (NIS)", true},
	{"ypserv", "Old network login server (NIS)", true},
	{"avahi", "Finds devices on the local network automatically (mDNS). Servers do not need it", true},
	{"bluez", "Bluetooth stack", true},
	{"ModemManager", "Manages mobile broadband modems", true},
	{"cups", "Print server. It opens a network port", true},
	{"cups-browsed", "Finds network printers. It opens a network port", true},
	{"cockpit-ws", "Web console. It opens a network port (9090). Remove it if you do not use the console", false},
	{"sendmail", "Mail transfer agent. Removing it stops local mail delivery, including mail from cron jobs", false},
	{"postfix", "Mail transfer agent. Removing it stops local mail delivery, including mail from cron jobs", false},
}

// Packages that must never be removed, however a removal gets there. A name
// that ends with "-" matches every package that starts with it.
var protectedPackages = []string{
	"systemd", "systemd-", "dnf", "dnf-", "yum", "rpm", "rpm-", "sudo", "openssh", "openssh-",
	"glibc", "glibc-", "bash", "coreutils", "util-linux", "shadow-utils", "setup", "filesystem",
	"basesystem", "almalinux-", "iproute", "NetworkManager", "NetworkManager-", "nftables", "firewalld",
	"fail2ban", "audit", "audit-", "selinux-policy", "selinux-policy-", "policycoreutils", "libselinux",
	"authselect", "pam", "crypto-policies", "chrony", "cloud-init", "ca-certificates",
	"qemu-guest-agent", "open-vm-tools", "grub2-", "kernel", "kernel-", "dbus", "dbus-", "aide",
	"python3", "python3-", "sssd", "sssd-", "cronie", "rsyslog",
}

func isProtected(pkg string) bool {
	for _, p := range protectedPackages {
		if pkg == p || (strings.HasSuffix(p, "-") && strings.HasPrefix(pkg, p)) {
			return true
		}
	}
	return false
}

func installedCandidates(ctx context.Context, env *control.Env) []unneeded {
	var out []unneeded
	for _, u := range unneededList {
		if dnf.Installed(ctx, env, u.pkg) {
			out = append(out, u)
		}
	}
	return out
}

func (r *removeUnneeded) Inputs(ctx context.Context, env *control.Env) ([]control.Input, error) {
	cands := installedCandidates(ctx, env)
	if len(cands) == 0 {
		return nil, nil
	}
	var opts []control.Option
	var def []string
	for _, c := range cands {
		help := c.why + "."
		if plan, err := dnf.RemovePlan(ctx, env, c.pkg); err == nil {
			var more []string
			for _, p := range plan {
				if p != c.pkg {
					more = append(more, p)
				}
			}
			if len(more) > 0 {
				help += " Removed with it: " + strings.Join(more, ", ") + "."
			}
			for _, p := range plan {
				if isProtected(p) {
					help += " Not safe to remove: it would also remove " + p + "."
				}
			}
		}
		opts = append(opts, control.Option{Value: c.pkg, Label: c.pkg, Help: help})
		if c.byDefault {
			def = append(def, c.pkg)
		}
	}
	return []control.Input{{
		Key: "packages", Label: "Which packages do you want to remove?",
		Help: "The packages are removed, with the packages that only they needed. Nothing is removed that you do not tick.",
		Kind: control.MultiChoice, Options: opts, DefaultMulti: def,
	}}, nil
}

// Idle says there is nothing to choose from when none of the packages this
// control looks for is installed. That is different from "applied": the list
// is fixed, so a server without these packages has never had them.
func (r *removeUnneeded) Idle(ctx context.Context, env *control.Env) string {
	if len(installedCandidates(ctx, env)) == 0 {
		return "nothing to remove"
	}
	return ""
}

// Check is never asked: this control is an action (see control.Meta.Action).
func (r *removeUnneeded) Check(context.Context, *control.Env) (control.State, error) {
	return control.NotApplied, nil
}

func (r *removeUnneeded) Apply(ctx context.Context, env *control.Env, in control.Values) error {
	known := map[string]bool{}
	for _, u := range unneededList {
		known[u.pkg] = true
	}
	var pkgs []string
	for _, p := range in.List("packages") {
		if !known[p] {
			return fmt.Errorf("%q is not one of the packages this control offers", p)
		}
		if dnf.Installed(ctx, env, p) {
			pkgs = append(pkgs, p)
		}
	}
	if len(pkgs) == 0 {
		env.Log.Infof("none of the packages this control offers is installed or chosen, nothing removed")
		return nil
	}
	plan, err := dnf.RemovePlan(ctx, env, pkgs...)
	if err != nil {
		return fmt.Errorf("cannot work out what the removal would take with it: %w", err)
	}
	for _, p := range plan {
		if isProtected(p) {
			return fmt.Errorf("removing %s would also remove %s, which the server needs. Nothing was removed", strings.Join(pkgs, ", "), p)
		}
	}
	sort.Strings(plan)
	env.Log.Infof("removing %d package(s): %s", len(plan), strings.Join(plan, ", "))
	return dnf.Remove(ctx, env, pkgs...)
}

func (r *removeUnneeded) Revert(context.Context, *control.Env) error { return control.ErrNoRevert }
