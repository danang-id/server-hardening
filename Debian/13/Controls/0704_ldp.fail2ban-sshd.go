// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Danang Galuh Tegar Prasetyo

package controls

import (
	"context"
	"fmt"
	"net"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/danang-id/server-hardening/internal/apt"
	"github.com/danang-id/server-hardening/internal/control"
	"github.com/danang-id/server-hardening/internal/systemd"
)

const (
	f2bID   = "ldp.fail2ban-sshd"
	f2bFile = "/etc/fail2ban/jail.d/00-server-hardening-sshd.local"
	f2bUnit = "fail2ban.service"
)

var jailPoll = struct {
	tries int
	every time.Duration
}{10, time.Second}

type fail2banSSHD struct{ control.Base }

func init() {
	System.Add(&fail2banSSHD{control.Base{M: control.Meta{
		ID:           f2bID,
		Category:     control.LDP,
		Number:       4,
		Title:        "Ban hosts that repeatedly fail SSH login",
		Default:      true,
		Requires:     []string{fwID},
		Tags:         []control.Tag{control.TagInput},
		RevertLimits: "The fail2ban package stays installed.",
	}}})
}

var f2bTime = regexp.MustCompile(`^[1-9][0-9]{0,5}[smhdw]?$`)

func timeInput(key, label, def string) control.Input {
	return control.Input{
		Key: key, Label: label, Default: def,
		Help: "A number with s, m, h, d or w, for example 10m or 1h",
		Validate: func(s string) error {
			if !f2bTime.MatchString(strings.TrimSpace(s)) {
				return fmt.Errorf("use a number with s, m, h, d or w, for example 10m")
			}
			return nil
		},
	}
}

func validAddresses(s string) ([]string, error) {
	var out []string
	for _, a := range listItems(s) {
		if ip := net.ParseIP(a); ip != nil {
			out = append(out, a)
			continue
		}
		if _, _, err := net.ParseCIDR(a); err == nil {
			out = append(out, a)
			continue
		}
		return nil, fmt.Errorf("%q is not an IP address or network", a)
	}
	return out, nil
}

// clientAddress finds the address of the user who is logged in over SSH.
// sudo usually removes SSH_CONNECTION, so the established connections to the
// SSH ports are a second source. It returns "" when the answer is not clear.
func clientAddress(ctx context.Context, env *control.Env) string {
	if f := strings.Fields(os.Getenv("SSH_CONNECTION")); len(f) == 4 {
		return f[0]
	}
	ports, err := sshPorts(ctx, env)
	if err != nil {
		return ""
	}
	isSSH := map[string]bool{}
	for _, p := range ports {
		isSSH[strconv.Itoa(p)] = true
	}
	out, err := env.Run.Run(ctx, "ss", "-H", "-tn", "state", "established")
	if err != nil {
		return ""
	}
	peers := map[string]bool{}
	for l := range strings.SplitSeq(string(out), "\n") {
		f := strings.Fields(l)
		if len(f) < 4 {
			continue
		}
		li, pi := strings.LastIndex(f[2], ":"), strings.LastIndex(f[3], ":")
		if li < 0 || pi < 0 || !isSSH[f[2][li+1:]] {
			continue
		}
		peers[strings.Trim(f[3][:pi], "[]")] = true
	}
	if len(peers) != 1 {
		return ""
	}
	for p := range peers {
		return p
	}
	return ""
}

func (f *fail2banSSHD) Inputs(ctx context.Context, env *control.Env) ([]control.Input, error) {
	return []control.Input{
		numberInput("maxretry", "Failed attempts before a ban", "5", 1, 100),
		timeInput("findtime", "Time window in which the attempts count", "10m"),
		timeInput("bantime", "How long a ban lasts", "1h"),
		{
			Key: "ignore", Label: "Addresses that are never banned", Optional: true,
			Default: clientAddress(ctx, env),
			Help:    "IP addresses or networks, separated by spaces. The default is the address of your current session.",
			Validate: func(s string) error {
				_, err := validAddresses(s)
				return err
			},
		},
	}, nil
}

// banAction names the fail2ban action that matches the firewall engine.
func banAction(e firewall) (string, error) {
	switch e {
	case nftables:
		return "nftables", nil
	case ufw:
		return "ufw", nil
	case firewalld:
		return "firewallcmd-rich-rules", nil
	}
	return "", fmt.Errorf("no ban method is known for the firewall %q", e)
}

func f2bJail(action string, ports []int, maxretry, findtime, bantime string, ignore []string) string {
	ign := append([]string{"127.0.0.1/8", "::1"}, ignore...)
	var b strings.Builder
	b.WriteString(managed(f2bID))
	b.WriteString("\n[sshd]\nenabled = true\n")
	b.WriteString("backend = systemd\n")
	b.WriteString("banaction = ")
	b.WriteString(action)
	b.WriteString("\n")
	b.WriteString("port = ")
	b.WriteString(joinInts(ports))
	b.WriteString("\n")
	b.WriteString("maxretry = ")
	b.WriteString(maxretry)
	b.WriteString("\n")
	b.WriteString("findtime = ")
	b.WriteString(findtime)
	b.WriteString("\n")
	b.WriteString("bantime = ")
	b.WriteString(bantime)
	b.WriteString("\n")
	b.WriteString("ignoreip = ")
	b.WriteString(strings.Join(ign, " "))
	b.WriteString("\n")
	return b.String()
}

func jailRunning(ctx context.Context, env *control.Env) bool {
	_, err := env.Run.Run(ctx, "fail2ban-client", "status", "sshd")
	return err == nil
}

func (f *fail2banSSHD) Check(ctx context.Context, env *control.Env) (control.State, error) {
	if !hasMarker(env, f2bFile, f2bID) {
		return control.NotApplied, nil
	}
	if !systemd.IsEnabled(ctx, env, f2bUnit) || !jailRunning(ctx, env) {
		return control.Partial, nil
	}
	return control.Applied, nil
}

func (f *fail2banSSHD) Apply(ctx context.Context, env *control.Env, in control.Values) error {
	e, err := engineOf(env)
	if err != nil {
		return err
	}
	action, err := banAction(e)
	if err != nil {
		return err
	}
	maxretry := strings.TrimSpace(in.String("maxretry"))
	if n, err := strconv.Atoi(maxretry); err != nil || n < 1 || n > 100 {
		return fmt.Errorf("the number of attempts %q is not a number from 1 to 100", maxretry)
	}
	findtime, bantime := strings.TrimSpace(in.String("findtime")), strings.TrimSpace(in.String("bantime"))
	for _, t := range []string{findtime, bantime} {
		if !f2bTime.MatchString(t) {
			return fmt.Errorf("the time %q is not a number with s, m, h, d or w", t)
		}
	}
	ignore, err := validAddresses(in.String("ignore"))
	if err != nil {
		return err
	}
	ports, err := sshPorts(ctx, env)
	if err != nil {
		return err
	}
	sort.Ints(ports)

	if err := apt.Install(ctx, env, "fail2ban", "python3-systemd"); err != nil {
		return err
	}
	if err := recordUnit(ctx, env, f2bID, f2bUnit); err != nil {
		return err
	}
	if err := putFile(env, f2bID, f2bFile, f2bJail(action, ports, maxretry, findtime, bantime, ignore), 0o644); err != nil {
		return err
	}
	undo := func() { _ = restoreFile(env, f2bID, f2bFile) }
	if out, err := env.Run.Run(ctx, "fail2ban-client", "-t"); err != nil {
		undo()
		return fmt.Errorf("fail2ban does not accept the jail: %w: %s", err, strings.TrimSpace(string(out)))
	}
	if systemd.IsActive(ctx, env, f2bUnit) {
		if _, err := env.Run.Run(ctx, "fail2ban-client", "reload"); err != nil {
			undo()
			_, _ = env.Run.Run(ctx, "fail2ban-client", "reload")
			return fmt.Errorf("fail2ban did not reload: %w", err)
		}
		if err := systemd.Enable(ctx, env, f2bUnit); err != nil {
			return err
		}
	} else if err := systemd.EnableNow(ctx, env, f2bUnit); err != nil {
		undo()
		return fmt.Errorf("cannot start fail2ban: %w", err)
	}
	for i := 0; i < jailPoll.tries; i++ {
		if jailRunning(ctx, env) {
			env.Log.Infof("the sshd jail watches port(s) %s with the %s ban method", joinInts(ports), action)
			return nil
		}
		time.Sleep(jailPoll.every)
	}
	undo()
	_, _ = env.Run.Run(ctx, "fail2ban-client", "reload")
	return fmt.Errorf("the sshd jail did not start")
}

func (f *fail2banSSHD) Revert(ctx context.Context, env *control.Env) error {
	if !env.Rec.Has(f2bID) {
		env.Log.Warnf("%s: no record, leaving fail2ban alone", f2bID)
		return nil
	}
	active := systemd.IsActive(ctx, env, f2bUnit)
	if active {
		// Lift the bans first: once the jail is gone nothing can lift them.
		_, _ = env.Run.Run(ctx, "fail2ban-client", "unban", "--all")
	}
	if err := restoreFile(env, f2bID, f2bFile); err != nil {
		return err
	}
	if active {
		if _, err := env.Run.Run(ctx, "fail2ban-client", "reload"); err != nil {
			env.Log.Warnf("fail2ban did not reload: %v", err)
		}
	}
	if err := restoreUnit(ctx, env, f2bID, f2bUnit); err != nil {
		return err
	}
	return env.Rec.Delete(f2bID)
}
