// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Danang Galuh Tegar Prasetyo

package controls

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/danang-id/server-hardening/internal/apt"
	"github.com/danang-id/server-hardening/internal/control"
	"github.com/danang-id/server-hardening/internal/files"
	"github.com/danang-id/server-hardening/internal/systemd"
)

const (
	networkdID   = "network.systemd-networkd"
	networkdBin  = "/usr/lib/systemd/systemd-networkd"
	cloudNetOff  = "/etc/cloud/cloud.cfg.d/99-server-hardening-network.cfg"
	networkdDir  = "/etc/systemd/network/"
	networkdName = "10-server-hardening-"
)

type networkd struct{ control.Base }

func init() {
	System.Add(&networkd{control.Base{M: control.Meta{
		ID:       networkdID,
		Category: control.Network,
		Number:   6,
		Title:    "Move the network configuration to systemd-networkd",
		Default:  false,
		Weight:   800,
		Tags:     []control.Tag{control.TagLockout, control.TagInput, control.TagReboot, control.TagIrreversible},
		NoRevertReason: "Rewriting the network configuration again carries lockout risk, and a failed restore cannot be repaired from the server itself. " +
			"The previous configuration is kept in the records folder, so restore it from the provider's console.",
	}}})
}

// netConfig is what the .network file is built from.
type netConfig struct {
	Iface string
	DHCP4 bool     // IPv4 address from DHCP
	RA    bool     // accept IPv6 router advertisements
	Addrs []string // static addresses, CIDR, both families
	GW4   string
	GW6   string
	DNS   []string
}

var ifaceName = regexp.MustCompile(`^[A-Za-z0-9_.:-]{1,15}$`)

// detectNetwork reads the running configuration of the main interface.
func detectNetwork(ctx context.Context, env *control.Env) netConfig {
	var c netConfig
	route := func(fam string) (gw, dev string, ra bool) {
		out, err := env.Run.Run(ctx, "ip", fam, "route", "show", "default")
		if err != nil {
			return
		}
		f := strings.Fields(strings.SplitN(string(out), "\n", 2)[0])
		for i := 0; i+1 < len(f); i++ {
			switch f[i] {
			case "via":
				gw = f[i+1]
			case "dev":
				dev = f[i+1]
			case "proto":
				ra = f[i+1] == "ra"
			}
		}
		return
	}
	var dev6 string
	c.GW4, c.Iface, _ = route("-4")
	c.GW6, dev6, c.RA = route("-6")
	if c.Iface == "" {
		c.Iface = dev6
	}
	if c.Iface == "" {
		return c
	}
	for _, fam := range []string{"-4", "-6"} {
		out, _ := env.Run.Run(ctx, "ip", "-o", fam, "addr", "show", "dev", c.Iface, "scope", "global")
		for l := range strings.SplitSeq(string(out), "\n") {
			f := strings.Fields(l)
			var cidr string
			for i := 0; i+1 < len(f); i++ {
				if f[i] == "inet" || f[i] == "inet6" {
					cidr = f[i+1]
				}
			}
			if cidr == "" || strings.Contains(l, "temporary") {
				continue
			}
			if strings.Contains(l, "dynamic") {
				if fam == "-4" {
					c.DHCP4 = true
				} else {
					c.RA = true
				}
				continue
			}
			c.Addrs = append(c.Addrs, cidr)
		}
	}
	if b, err := files.ReadOptional(env.Path("/etc/resolv.conf")); err == nil {
		c.DNS = resolvConfServers(string(b))
	}
	return c
}

// resolvConfServers lists the real name servers of a resolv.conf: the local stub is skipped.
func resolvConfServers(content string) []string {
	var out []string
	for l := range strings.SplitSeq(content, "\n") {
		f := strings.Fields(l)
		if len(f) == 2 && f[0] == "nameserver" && f[1] != "127.0.0.53" && f[1] != "127.0.0.1" && f[1] != "::1" {
			out = append(out, f[1])
		}
	}
	return out
}

func validAddrList(s string, cidr bool) error {
	for _, a := range strings.Fields(s) {
		if cidr {
			if _, _, err := net.ParseCIDR(a); err != nil {
				return fmt.Errorf("%q is not an address with a prefix length, such as 203.0.113.5/24", a)
			}
		} else if net.ParseIP(a) == nil {
			return fmt.Errorf("%q is not an IP address", a)
		}
	}
	return nil
}

func validOptionalIP(s string) error {
	s = strings.TrimSpace(s)
	if s == "" || net.ParseIP(s) != nil {
		return nil
	}
	return fmt.Errorf("%q is not an IP address", s)
}

func (n *networkd) Inputs(ctx context.Context, env *control.Env) ([]control.Input, error) {
	d := detectNetwork(ctx, env)
	mode := "static"
	if d.DHCP4 {
		mode = "dhcp"
	}
	ra := "no"
	if d.RA {
		ra = "yes"
	}
	return []control.Input{
		{Key: "iface", Label: "Network interface", Help: "The interface that carries the default route.", Default: d.Iface,
			Validate: func(s string) error {
				if !ifaceName.MatchString(strings.TrimSpace(s)) {
					return fmt.Errorf("not an interface name")
				}
				return nil
			}},
		{Key: "mode", Label: "IPv4 address", Kind: control.Choice, Default: mode, Options: []control.Option{
			{Value: "static", Label: "Static: fixed address and gateway"},
			{Value: "dhcp", Label: "DHCP: the provider hands it out"},
		}},
		{Key: "addresses", Label: "Static addresses with prefix length (IPv4 and IPv6, separated by spaces)", Optional: true,
			Default: strings.Join(d.Addrs, " "), Validate: func(s string) error { return validAddrList(s, true) }},
		{Key: "gateway4", Label: "IPv4 gateway", Optional: true, Default: d.GW4, Validate: validOptionalIP},
		{Key: "gateway6", Label: "IPv6 gateway", Optional: true, Default: d.GW6, Validate: validOptionalIP},
		{Key: "ra", Label: "Accept IPv6 router advertisements?", Kind: control.Choice, Default: ra, Options: []control.Option{
			{Value: "no", Label: "No: the IPv6 address and route are static"},
			{Value: "yes", Label: "Yes: they come from the provider's router"},
		}},
		{Key: "dns", Label: "DNS servers (separated by spaces)", Optional: true,
			Help:    "With DHCP, leave empty to use the servers DHCP hands out.",
			Default: strings.Join(d.DNS, " "), Validate: func(s string) error { return validAddrList(s, false) }},
	}, nil
}

func configFromInput(in control.Values) netConfig {
	return netConfig{
		Iface: strings.TrimSpace(in.String("iface")),
		DHCP4: in.String("mode") == "dhcp",
		RA:    in.String("ra") == "yes",
		Addrs: strings.Fields(in.String("addresses")),
		GW4:   strings.TrimSpace(in.String("gateway4")),
		GW6:   strings.TrimSpace(in.String("gateway6")),
		DNS:   strings.Fields(in.String("dns")),
	}
}

func isV6(s string) bool { return strings.Contains(s, ":") }

// validate refuses a configuration that could leave the server without a network.
func (c netConfig) validate(env *control.Env) error {
	if !ifaceName.MatchString(c.Iface) || !files.Exists(env.Path("/sys/class/net/"+c.Iface)) {
		return fmt.Errorf("there is no network interface %q", c.Iface)
	}
	var v4, v6 []string
	for _, a := range c.Addrs {
		if _, _, err := net.ParseCIDR(a); err != nil {
			return fmt.Errorf("%q is not an address with a prefix length", a)
		}
		if isV6(a) {
			v6 = append(v6, a)
		} else {
			v4 = append(v4, a)
		}
	}
	if !c.DHCP4 && len(v4) == 0 {
		return fmt.Errorf("a static IPv4 configuration needs at least one address. Choose DHCP, or enter the address")
	}
	if len(v4) > 0 && c.DHCP4 {
		return fmt.Errorf("IPv4 is set to DHCP but IPv4 addresses are given as well")
	}
	if !c.DHCP4 && c.GW4 == "" {
		return fmt.Errorf("a static IPv4 configuration needs a gateway")
	}
	if c.GW4 != "" && (net.ParseIP(c.GW4) == nil || isV6(c.GW4)) {
		return fmt.Errorf("the IPv4 gateway %q is not an IPv4 address", c.GW4)
	}
	if c.GW6 != "" && (net.ParseIP(c.GW6) == nil || !isV6(c.GW6)) {
		return fmt.Errorf("the IPv6 gateway %q is not an IPv6 address", c.GW6)
	}
	if len(v6) > 0 && !c.RA && c.GW6 == "" {
		return fmt.Errorf("static IPv6 addresses need an IPv6 gateway, or accept router advertisements")
	}
	return nil
}

func onLink(gw string, addrs []string) bool {
	ip := net.ParseIP(gw)
	for _, a := range addrs {
		if _, n, err := net.ParseCIDR(a); err == nil && isV6(a) == isV6(gw) && n.Contains(ip) {
			return true
		}
	}
	return false
}

func (c netConfig) render() string {
	var b strings.Builder
	w := func(f string, a ...any) { fmt.Fprintf(&b, f+"\n", a...) }
	w("%s", sshdMarker(networkdID))
	w("[Match]")
	w("Name=%s", c.Iface)
	w("")
	w("[Network]")
	if c.DHCP4 {
		w("DHCP=ipv4")
	} else {
		w("DHCP=no")
	}
	w("IPv6AcceptRA=%s", map[bool]string{true: "yes", false: "no"}[c.RA])
	for _, a := range c.Addrs {
		w("Address=%s", a)
	}
	for _, d := range c.DNS {
		w("DNS=%s", d)
	}
	for _, gw := range []string{c.GW4, c.GW6} {
		if gw == "" {
			continue
		}
		w("")
		w("[Route]")
		w("Gateway=%s", gw)
		if !onLink(gw, c.Addrs) && !(gw == c.GW4 && c.DHCP4) {
			w("GatewayOnLink=yes") // the gateway is outside the subnet, as some providers do it
		}
	}
	return b.String()
}

func networkdFile(iface string) string { return networkdDir + networkdName + iface + ".network" }

func (n *networkd) Check(ctx context.Context, env *control.Env) (control.State, error) {
	iface, ok, err := env.Rec.Get(networkdID, "iface")
	if err != nil || !ok {
		return control.NotApplied, err
	}
	if !files.Exists(env.Path(networkdFile(iface))) {
		return control.NotApplied, nil
	}
	if systemd.IsActive(ctx, env, "systemd-networkd") && systemd.IsEnabled(ctx, env, "systemd-networkd") {
		return control.Applied, nil
	}
	return control.Pending, nil // written, and waiting for the reboot
}

// oldNetworkFiles lists the files of the earlier network configuration.
func oldNetworkFiles(env *control.Env) []string {
	var out []string
	for _, pat := range []string{"/etc/network/interfaces", "/etc/network/interfaces.d/*", "/etc/netplan/*.yaml", networkdDir + "*"} {
		m, _ := filepath.Glob(env.Path(pat))
		for _, p := range m {
			if st, err := filepath.Rel(env.Root, p); err == nil && !strings.Contains(p, networkdName) {
				if fi, err := os.Stat(p); err == nil && !fi.IsDir() {
					out = append(out, "/"+filepath.ToSlash(st))
				}
			}
		}
	}
	return out
}

func (n *networkd) Apply(ctx context.Context, env *control.Env, in control.Values) error {
	cfg := configFromInput(in)
	if err := cfg.validate(env); err != nil {
		return err
	}
	if !files.Exists(env.Path(networkdBin)) {
		if err := apt.Install(ctx, env, "systemd-networkd"); err != nil || !files.Exists(env.Path(networkdBin)) {
			return fmt.Errorf("systemd-networkd is not available on this system (%v), so nothing was changed", err)
		}
	}
	// Save the earlier configuration first: this is the only way back.
	saved := oldNetworkFiles(env)
	for _, p := range saved {
		if err := env.Rec.Backup(networkdID, env.Path(p)); err != nil {
			return err
		}
	}
	if err := env.Rec.Backup(networkdID, env.Path(cloudNetOff)); err != nil {
		return err
	}
	for k, v := range map[string]string{
		"iface": cfg.Iface, "saved": strings.Join(saved, "\n"),
		"networking-enabled": yesNo(systemd.IsEnabled(ctx, env, "networking")),
	} {
		if err := env.Rec.Put(networkdID, k, v); err != nil {
			return err
		}
	}

	if err := files.WriteAtomic(env.Path(networkdFile(cfg.Iface)), []byte(cfg.render()), 0o644); err != nil {
		return err
	}
	// cloud-init would write its own network files again at boot.
	if files.Exists(env.Path("/etc/cloud")) {
		body := sshdMarker(networkdID) + "\nnetwork: {config: disabled}\n"
		if err := files.WriteAtomic(env.Path(cloudNetOff), []byte(body), 0o644); err != nil {
			return err
		}
	}
	if m, _ := filepath.Glob(env.Path("/etc/netplan/*.yaml")); len(m) > 0 {
		env.Log.Warnf("%s: netplan files exist in /etc/netplan and were left in place. Remove them if netplan should not configure the network", networkdID)
	}
	// networkd is not started now: it would take the interface over while the
	// session is connected. The old service is switched off and the new one on,
	// for the next boot.
	if systemd.IsEnabled(ctx, env, "networking") {
		if err := systemd.Disable(ctx, env, "networking"); err != nil {
			return fmt.Errorf("switching off the old network service: %w", err)
		}
	}
	if err := systemd.Enable(ctx, env, "systemd-networkd"); err != nil {
		_ = systemd.Enable(ctx, env, "networking")
		return fmt.Errorf("switching on systemd-networkd: %w", err)
	}
	env.Log.Warnf("%s: the new network configuration takes effect at the next boot. Keep your provider's console open and reboot when you are ready. "+
		"The earlier configuration is saved in /var/lib/server-hardening", networkdID)
	return nil
}

func (n *networkd) Revert(context.Context, *control.Env) error { return control.ErrNoRevert }
