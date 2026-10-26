// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Danang Galuh Tegar Prasetyo

package controls

import (
	"context"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/danang-id/server-hardening/internal/control"
	"github.com/danang-id/server-hardening/internal/systemd"
)

const servicesID = "asr.review-services"

type reviewServices struct{ control.Base }

func init() {
	System.Add(&reviewServices{control.Base{M: control.Meta{
		ID:       servicesID,
		Category: control.ASR,
		Number:   4,
		Title:    "Review and disable unneeded services",
		Default:  true,
		Tags:     []control.Tag{control.TagInput},
	}}})
}

// Services that are never offered: the server's access, its network, and the
// tools this project sets up.
var protectedServices = []string{
	"sshd.service", "dbus.service", "dbus-broker.service", "NetworkManager.service",
	"NetworkManager-wait-online.service", "NetworkManager-dispatcher.service", "rsyslog.service",
	"auditd.service", "chronyd.service", "fail2ban.service", "nftables.service", "firewalld.service",
	"qemu-guest-agent.service", "open-vm-tools.service", "crond.service", "sssd.service",
	"irqbalance.service", "tuned.service", "polkit.service", "restorecon.service",
}

var protectedServicePrefixes = []string{"systemd-", "cloud-", "getty@", "serial-getty@", "user@", "hv-", "dnf-", "rpm-", "selinux-", "NetworkManager-", "dracut-", "plymouth-"}

func serviceProtected(unit string) bool {
	for _, p := range protectedServices {
		if unit == p {
			return true
		}
	}
	for _, p := range protectedServicePrefixes {
		if strings.HasPrefix(unit, p) {
			return true
		}
	}
	return strings.HasSuffix(unit, "@.service")
}

type serviceInfo struct {
	why       string
	byDefault bool
}

var knownServices = map[string]serviceInfo{
	"avahi-daemon.service":   {"Finds devices on the local network automatically (mDNS). Servers do not need it", true},
	"bluetooth.service":      {"Bluetooth", true},
	"ModemManager.service":   {"Manages mobile broadband modems", true},
	"cups.service":           {"Print server", true},
	"cups-browsed.service":   {"Finds network printers", true},
	"rpcbind.service":        {"Maps remote procedure calls to ports. Needed by NFS and NIS only", false},
	"nfs-server.service":     {"NFS file server", false},
	"nfs-client.service":     {"NFS client support", false},
	"smb.service":            {"Samba file server", false},
	"nmb.service":            {"Samba name service", false},
	"snmpd.service":          {"SNMP monitoring agent", false},
	"sendmail.service":       {"Mail transfer agent. Disabling it stops local mail delivery", false},
	"postfix.service":        {"Mail transfer agent. Disabling it stops local mail delivery", false},
	"httpd.service":          {"Web server", false},
	"nginx.service":          {"Web server", false},
	"mariadb.service":        {"Database server", false},
	"mysqld.service":         {"Database server", false},
	"postgresql.service":     {"Database server", false},
	"docker.service":         {"Container engine", false},
	"containerd.service":     {"Container runtime", false},
	"lvm2-monitor.service":   {"Monitors logical volumes", false},
	"atd.service":            {"Runs one-time scheduled jobs (at)", false},
	"smartd.service":         {"Watches disk health", false},
	"multipathd.service":     {"Multipath storage", false},
	"mdmonitor.service":      {"Watches software RAID", false},
	"kdump.service":          {"Saves a crash dump when the kernel fails", false},
	"tailscaled.service":     {"Tailscale VPN", false},
	"wpa_supplicant.service": {"Wi-Fi", false},
}

var enabledLine = regexp.MustCompile(`^(\S+\.service)\s+enabled`)

func enabledServices(ctx context.Context, env *control.Env) ([]string, error) {
	out, err := env.Run.Run(ctx, "systemctl", "list-unit-files", "--type=service", "--state=enabled", "--no-legend", "--no-pager")
	if err != nil {
		return nil, err
	}
	var units []string
	for l := range strings.SplitSeq(string(out), "\n") {
		if m := enabledLine.FindStringSubmatch(strings.TrimSpace(l)); m != nil && !serviceProtected(m[1]) {
			units = append(units, m[1])
		}
	}
	sort.Strings(units)
	return units, nil
}

// portsByProcess maps a process name to the ports it listens on.
func portsByProcess(ctx context.Context, env *control.Env) map[string][]string {
	out, err := env.Run.Run(ctx, "ss", "-H", "-lntup")
	if err != nil {
		return nil
	}
	m := map[string][]string{}
	for l := range strings.SplitSeq(string(out), "\n") {
		f := strings.Fields(l)
		if len(f) < 5 {
			continue
		}
		pm := processName.FindStringSubmatch(l)
		if pm == nil {
			continue
		}
		i := strings.LastIndex(f[4], ":")
		if i < 0 {
			continue
		}
		entry := f[0] + " " + f[4][i+1:]
		if !contains(m[pm[1]], entry) {
			m[pm[1]] = append(m[pm[1]], entry)
		}
	}
	return m
}

func contains(l []string, s string) bool {
	for _, x := range l {
		if x == s {
			return true
		}
	}
	return false
}

// portsOf finds the ports of the process that belongs to a service, by name.
func portsOf(unit string, byProc map[string][]string) []string {
	base := strings.ToLower(strings.TrimSuffix(unit, ".service"))
	var ports []string
	for p, l := range byProc {
		lp := strings.ToLower(p)
		if lp == base || strings.HasPrefix(lp, base) || strings.HasPrefix(base, lp) && len(lp) >= 4 {
			ports = append(ports, l...)
		}
	}
	sort.Strings(ports)
	return ports
}

func (r *reviewServices) Inputs(ctx context.Context, env *control.Env) ([]control.Input, error) {
	units, err := enabledServices(ctx, env)
	if err != nil || len(units) == 0 {
		return nil, nil
	}
	byProc := portsByProcess(ctx, env)
	var opts []control.Option
	var def []string
	for _, u := range units {
		info, known := knownServices[u]
		why := info.why
		if !known {
			if out, err := env.Run.Run(ctx, "systemctl", "show", "-p", "Description", "--value", u); err == nil {
				why = strings.TrimSpace(string(out))
			}
		}
		if why == "" {
			why = "No description available"
		}
		help := why + "."
		if p := portsOf(u, byProc); len(p) > 0 {
			help += " Listens on " + strings.Join(p, ", ") + "."
		}
		opts = append(opts, control.Option{Value: u, Label: strings.TrimSuffix(u, ".service"), Help: help})
		if info.byDefault {
			def = append(def, u)
		}
	}
	return []control.Input{{
		Key: "services", Label: "Which services do you want to stop and disable?",
		Help: "Access, networking, logging and the tools of this project are not listed. Nothing is disabled that you do not tick.",
		Kind: control.MultiChoice, Options: opts, DefaultMulti: def,
	}}, nil
}

func (r *reviewServices) Check(ctx context.Context, env *control.Env) (control.State, error) {
	if !env.Rec.Has(servicesID) {
		return control.NotApplied, nil
	}
	v, _, _ := env.Rec.Get(servicesID, "units")
	for _, u := range strings.Fields(v) {
		if systemd.IsEnabled(ctx, env, u) || systemd.IsActive(ctx, env, u) {
			return control.Partial, nil
		}
	}
	return control.Applied, nil
}

func (r *reviewServices) Apply(ctx context.Context, env *control.Env, in control.Values) error {
	offered, err := enabledServices(ctx, env)
	if err != nil {
		return err
	}
	ok := map[string]bool{}
	for _, u := range offered {
		ok[u] = true
	}
	prev, _, _ := env.Rec.Get(servicesID, "units")
	all := strings.Fields(prev)
	var done []string
	rollback := func() {
		for _, u := range done {
			_ = restoreUnit(ctx, env, servicesID, u)
		}
	}
	for _, u := range in.List("services") {
		if !ok[u] {
			rollback()
			return fmt.Errorf("%s is not an enabled service this control offers", u)
		}
		if err := recordUnit(ctx, env, servicesID, u); err != nil {
			rollback()
			return err
		}
		if err := systemd.DisableNow(ctx, env, u); err != nil {
			rollback()
			return fmt.Errorf("cannot disable %s: %w", u, err)
		}
		done = append(done, u)
		if !contains(all, u) {
			all = append(all, u)
		}
		env.Log.Infof("disabled %s", u)
	}
	if len(done) == 0 {
		env.Log.Infof("no service chosen, nothing disabled")
	}
	return env.Rec.Put(servicesID, "units", strings.Join(all, "\n"))
}

func (r *reviewServices) Revert(ctx context.Context, env *control.Env) error {
	if !env.Rec.Has(servicesID) {
		env.Log.Warnf("%s: no record, leaving services alone", servicesID)
		return nil
	}
	v, _, _ := env.Rec.Get(servicesID, "units")
	for _, u := range strings.Fields(v) {
		if err := restoreUnit(ctx, env, servicesID, u); err != nil {
			return fmt.Errorf("cannot restore %s: %w", u, err)
		}
		env.Log.Infof("restored %s", u)
	}
	return env.Rec.Delete(servicesID)
}
