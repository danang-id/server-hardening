// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Danang Galuh Tegar Prasetyo

package controls

import (
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/danang-id/server-hardening/internal/control"
)

// fwSim emulates nftables, ufw and firewalld well enough to see what the
// firewall controls do to them.
type fwSim struct {
	t   *testing.T
	env *control.Env
	run *fakeRunner

	// nftables
	nftLoadedText string
	nftBad        bool   // nft -c -f refuses the file
	foreign       string // rules of another firewall, shown by "nft list ruleset"

	// ufw
	ufwInstalled bool
	ufwActive    bool
	ufwRules     []string
	ufwLogging   string // "off" or a level

	// firewalld
	fwdInstalled bool
	fwdRunning   bool
	fwdZone      string
	fwdPorts     []string
	fwdRich      []string
	fwdLog       string
}

// fwEnv is the SSH test system (sshd on port 22) with the firewalls simulated.
func fwEnv(t *testing.T) (*control.Env, *fakeRunner, *sshSim, *fwSim) {
	t.Helper()
	env, r, ssh := sshEnv(t)
	f := &fwSim{t: t, env: env, run: r, ufwLogging: "off", fwdZone: "public", fwdLog: "off"}
	prev := r.hook
	r.hook = func(fr *fakeRunner, cmd string) {
		if prev != nil {
			prev(fr, cmd)
		}
		f.hook(cmd)
	}
	writeFile(t, env, "/etc/nftables.conf", "#!/usr/sbin/nft -f\n\nflush ruleset\n\ntable inet filter {\n}\n")
	return env, r, ssh, f
}

func (f *fwSim) hook(cmd string) {
	fields := strings.Fields(cmd)
	if len(fields) == 0 {
		return
	}
	switch fields[0] {
	case "nft":
		f.nft(cmd, fields)
	case "ufw":
		f.ufw(cmd, fields)
	case "firewall-cmd":
		f.firewalld(cmd, fields)
	case "apt-get", "env":
		if strings.Contains(cmd, "install") {
			if strings.HasSuffix(cmd, " ufw") || strings.Contains(cmd, " ufw ") {
				f.ufwInstalled = true
			}
			if strings.HasSuffix(cmd, " firewalld") || strings.Contains(cmd, " firewalld ") {
				f.fwdInstalled = true
			}
		}
	case "systemctl":
		if len(fields) >= 3 && fields[1] == "enable" && fields[2] == "--now" && len(fields) > 3 && fields[3] == "firewalld" {
			f.fwdRunning = true
		}
		if len(fields) >= 4 && fields[1] == "disable" && fields[2] == "--now" && fields[3] == "firewalld" {
			f.fwdRunning = false
		}
		if len(fields) == 4 && fields[1] == "is-active" && fields[3] == "firewalld" {
			f.setFail(cmd, !f.fwdRunning)
		}
	}
}

func (f *fwSim) setFail(cmd string, fail bool) {
	if fail {
		f.run.fail[cmd] = true
	} else {
		delete(f.run.fail, cmd)
	}
}

func (f *fwSim) nft(cmd string, fields []string) {
	switch {
	case len(fields) == 4 && fields[1] == "-c" && fields[2] == "-f":
		f.setFail(cmd, f.nftBad)
	case len(fields) == 3 && fields[1] == "-f":
		b, err := os.ReadFile(fields[2])
		if err != nil {
			f.t.Fatalf("nft -f: %v", err)
		}
		f.nftLoadedText = string(b)
	case cmd == "nft delete table inet "+nftTable:
		f.nftLoadedText = ""
	case cmd == "nft list table inet "+nftTable:
		if f.nftLoadedText == "" {
			f.run.fail[cmd] = true
		} else {
			delete(f.run.fail, cmd)
			f.run.out[cmd] = f.nftLoadedText
		}
	case cmd == "nft list ruleset":
		f.run.out[cmd] = f.foreign + f.nftLoadedText
	}
}

func (f *fwSim) ufw(cmd string, fields []string) {
	if !f.ufwInstalled {
		f.run.fail[cmd] = true
		return
	}
	delete(f.run.fail, cmd)
	args := fields[1:]
	switch {
	case cmd == "ufw status":
		out := "Status: inactive\n"
		if f.ufwActive {
			out = "Status: active\n\nTo Action From\n-- ------ ----\n"
			for _, r := range f.ufwRules {
				out += r + "\n"
			}
		}
		f.run.out[cmd] = out
	case cmd == "ufw status verbose":
		out := "Status: inactive\n"
		if f.ufwActive {
			out = "Status: active\nLogging: " + map[bool]string{true: "off", false: "on (" + f.ufwLogging + ")"}[f.ufwLogging == "off"] +
				"\nDefault: deny (incoming), allow (outgoing), disabled (routed)\n"
			for _, r := range f.ufwRules {
				out += r + "\n"
			}
		}
		f.run.out[cmd] = out
	case cmd == "ufw --force enable":
		f.ufwActive = true
	case cmd == "ufw --force disable":
		f.ufwActive = false
	case len(args) > 0 && args[0] == "logging":
		f.ufwLogging = args[1]
	case len(args) > 0 && args[0] == "allow":
		f.ufwRules = addUnique(f.ufwRules, ufwLine(args[1:]))
	case len(args) > 1 && args[0] == "delete" && args[1] == "allow":
		f.ufwRules = remove(f.ufwRules, ufwLine(args[2:]))
	}
}

func ufwLine(spec []string) string {
	if len(spec) == 1 {
		return spec[0] + " ALLOW Anywhere"
	}
	// from SRC to any port N proto P
	return fmt.Sprintf("%s/%s ALLOW %s", spec[5], spec[7], spec[1])
}

func (f *fwSim) firewalld(cmd string, fields []string) {
	if !f.fwdInstalled {
		f.run.fail[cmd] = true
		return
	}
	delete(f.run.fail, cmd)
	if cmd == "firewall-cmd --state" {
		if f.fwdRunning {
			f.run.out[cmd] = "running\n"
		} else {
			f.run.fail[cmd] = true
		}
		return
	}
	if !f.fwdRunning {
		f.run.fail[cmd] = true
		return
	}
	for _, a := range fields[1:] {
		switch {
		case a == "--get-default-zone":
			f.run.out[cmd] = f.fwdZone + "\n"
		case strings.HasPrefix(a, "--set-default-zone="):
			f.fwdZone = strings.TrimPrefix(a, "--set-default-zone=")
		case strings.HasPrefix(a, "--add-port="):
			f.fwdPorts = addUnique(f.fwdPorts, strings.TrimPrefix(a, "--add-port="))
		case strings.HasPrefix(a, "--remove-port="):
			f.fwdPorts = remove(f.fwdPorts, strings.TrimPrefix(a, "--remove-port="))
		case a == "--list-ports":
			f.run.out[cmd] = strings.Join(f.fwdPorts, " ") + "\n"
		case a == "--list-rich-rules":
			f.run.out[cmd] = strings.Join(f.fwdRich, "\n") + "\n"
		case a == "--get-log-denied":
			f.run.out[cmd] = f.fwdLog + "\n"
		case strings.HasPrefix(a, "--set-log-denied="):
			f.fwdLog = strings.TrimPrefix(a, "--set-log-denied=")
		}
	}
	// A rich rule has spaces; take it from the whole command line.
	if i := strings.Index(cmd, "-rich-rule="); i >= 0 {
		rule := cmd[i+len("-rich-rule="):]
		if strings.Contains(cmd, "--add-rich-rule") {
			f.fwdRich = addUnique(f.fwdRich, rule)
		} else {
			f.fwdRich = remove(f.fwdRich, rule)
		}
	}
}

func addUnique(l []string, s string) []string {
	for _, x := range l {
		if x == s {
			return l
		}
	}
	return append(l, s)
}

func remove(l []string, s string) []string {
	var out []string
	for _, x := range l {
		if x != s {
			out = append(out, x)
		}
	}
	return out
}
