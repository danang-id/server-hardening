// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Danang Galuh Tegar Prasetyo

package controls

import (
	"context"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/danang-id/server-hardening/internal/control"
	"github.com/danang-id/server-hardening/internal/dnf"
	"github.com/danang-id/server-hardening/internal/files"
	fwrules "github.com/danang-id/server-hardening/internal/firewall"
	"github.com/danang-id/server-hardening/internal/systemd"
)

const (
	portID         = "remote-access.ssh-port"
	portSocketFile = "/etc/systemd/system/sshd.socket.d/00-server-hardening-port.conf"
	sshSocket      = "sshd.socket"
)

// portPoll is how long to wait for sshd to listen on a port after a change.
var portPoll = struct {
	tries int
	every time.Duration
}{10, 500 * time.Millisecond}

type sshPort struct{ control.Base }

func init() {
	System.Add(&sshPort{control.Base{M: control.Meta{
		ID:       portID,
		Category: control.RemoteAccess,
		Number:   5,
		Title:    "Move SSH to another port",
		Default:  false,
		Tags:     []control.Tag{control.TagLockout, control.TagInput},
	}}})
}

func validPort(s string) error {
	n, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil || n < 1 || n > 65535 {
		return fmt.Errorf("enter a port from 1 to 65535")
	}
	if n == 22 {
		return fmt.Errorf("22 is the port SSH uses now. Choose another one")
	}
	return nil
}

func (p *sshPort) Inputs(context.Context, *control.Env) ([]control.Input, error) {
	return []control.Input{{
		Key:      "port",
		Label:    "New SSH port",
		Help:     "Every client, script and monitor must use it afterwards. There is no default on purpose.",
		Validate: validPort,
	}}, nil
}

// Listening ports

// listeningPorts returns the TCP ports in use, with the line that names the
// process (when ss can show it).
func listeningPorts(ctx context.Context, env *control.Env) (map[int]string, error) {
	out, err := env.Run.Run(ctx, "ss", "-H", "-ltnp")
	if err != nil {
		return nil, fmt.Errorf("listing listening ports: %w", err)
	}
	m := map[int]string{}
	for l := range strings.SplitSeq(string(out), "\n") {
		f := strings.Fields(l)
		if len(f) < 4 {
			continue
		}
		i := strings.LastIndex(f[3], ":")
		if i < 0 {
			continue
		}
		if n, err := strconv.Atoi(f[3][i+1:]); err == nil {
			m[n] += l + "\n"
		}
	}
	return m, nil
}

func waitListening(ctx context.Context, env *control.Env, port int) error {
	for i := 0; i < portPoll.tries; i++ {
		if m, err := listeningPorts(ctx, env); err == nil {
			if _, ok := m[port]; ok {
				return nil
			}
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(portPoll.every):
		}
	}
	return fmt.Errorf("sshd is not listening on port %d", port)
}

func currentPorts(ctx context.Context, env *control.Env) ([]int, error) {
	eff, err := sshdEffective(ctx, env)
	if err != nil {
		return nil, err
	}
	var out []int
	for _, v := range eff["port"] {
		if n, err := strconv.Atoi(v); err == nil {
			out = append(out, n)
		}
	}
	if len(out) == 0 {
		out = []int{22}
	}
	return out, nil
}

var portLine = regexp.MustCompile(`(?im)^\s*Port\s+\d+`)

// portSetElsewhere finds a Port line in another sshd file. sshd adds up all
// Port lines, so this control could not close the old port while that line
// exists. It names the file instead of editing a file it does not own.
func portSetElsewhere(env *control.Env) (string, error) {
	paths := []string{"/etc/ssh/sshd_config"}
	ents, err := os.ReadDir(env.Path(sshdDir))
	if err != nil && !os.IsNotExist(err) {
		return "", err
	}
	for _, e := range ents {
		if strings.HasSuffix(e.Name(), ".conf") && sshdDir+e.Name() != sshdFile("port") {
			paths = append(paths, sshdDir+e.Name())
		}
	}
	for _, p := range paths {
		b, err := files.ReadOptional(env.Path(p))
		if err != nil {
			return "", err
		}
		if portLine.Match(b) {
			return p, nil
		}
	}
	return "", nil
}

func joinInts(ns []int) string { return fwrules.JoinInts(ns) }

func splitInts(s string) []int { return fwrules.SplitInts(s) }

// Firewall

type firewall string

const (
	noFirewall firewall = ""
	firewalld  firewall = "firewalld"
)

var nftDropsInput = regexp.MustCompile(`(?s)hook input[^\n]*policy drop`)

// detectFirewall finds an active firewall this control can open a port in.
// An active nftables firewall is refused: the port would stay closed.
func detectFirewall(ctx context.Context, env *control.Env) (firewall, error) {
	// The nftables table of network.firewall: this control can open ports in it.
	if e, _, _ := env.Rec.Get(fwID, "engine"); e == string(nftables) {
		return nftables, nil
	}
	if out, err := env.Run.Run(ctx, "firewall-cmd", "--state"); err == nil && strings.TrimSpace(string(out)) == "running" {
		return firewalld, nil
	}
	if out, err := env.Run.Run(ctx, "nft", "list", "ruleset"); err == nil && nftDropsInput.Match(out) {
		return noFirewall, fmt.Errorf("an nftables firewall is active that drops incoming traffic. " +
			"This control cannot open a port in it yet. Allow the new port in the firewall yourself first, then run this again")
	}
	return noFirewall, nil
}

// fwAllow opens a TCP port. It reports whether it added a rule.
func fwAllow(ctx context.Context, env *control.Env, fw firewall, port int) (bool, error) {
	spec := strconv.Itoa(port) + "/tcp"
	switch fw {
	case nftables:
		return nftExtraSSH(ctx, env, port, true)
	case firewalld:
		if _, err := env.Run.Run(ctx, "firewall-cmd", "--permanent", "--query-port="+spec); err == nil {
			return false, nil
		}
		if _, err := env.Run.Run(ctx, "firewall-cmd", "--permanent", "--add-port="+spec); err != nil {
			return false, err
		}
		_, err := env.Run.Run(ctx, "firewall-cmd", "--reload")
		return err == nil, err
	}
	return false, nil
}

func fwRemove(ctx context.Context, env *control.Env, fw firewall, port int) error {
	spec := strconv.Itoa(port) + "/tcp"
	switch fw {
	case nftables:
		_, err := nftExtraSSH(ctx, env, port, false)
		return err
	case firewalld:
		if _, err := env.Run.Run(ctx, "firewall-cmd", "--permanent", "--remove-port="+spec); err != nil {
			return err
		}
		_, err := env.Run.Run(ctx, "firewall-cmd", "--reload")
		return err
	}
	return nil
}

// nftExtraSSH adds a port to (or removes it from) the SSH ports of the
// nftables table of network.firewall. It reports whether it changed anything.
func nftExtraSSH(ctx context.Context, env *control.Env, port int, add bool) (bool, error) {
	cur, _, err := env.Rec.Get(fwID, "extra-ssh")
	if err != nil {
		return false, err
	}
	base, _, _ := env.Rec.Get(fwID, "ssh-ports")
	in := func(list []int) bool {
		for _, p := range list {
			if p == port {
				return true
			}
		}
		return false
	}
	extra := splitInts(cur)
	if add && (in(extra) || in(splitInts(base))) {
		return false, nil
	}
	if !add && !in(extra) {
		return false, nil
	}
	var next []int
	for _, p := range extra {
		if p != port {
			next = append(next, p)
		}
	}
	if add {
		next = append(next, port)
	}
	if err := env.Rec.Put(fwID, "extra-ssh", joinInts(next)); err != nil {
		return false, err
	}
	if err := nftRebuild(ctx, env); err != nil {
		_ = env.Rec.Put(fwID, "extra-ssh", cur)
		return false, err
	}
	return true, nil
}

// SELinux

// sshPortLabeled reports whether "semanage port -l" shows the TCP port as
// ssh_port_t. The line looks like "ssh_port_t   tcp   2222, 22". It also
// returns the type that holds the port, if another type has it.
func sshPortLabeled(list string, port int) (labeled bool, other string) {
	for l := range strings.SplitSeq(list, "\n") {
		f := strings.Fields(l)
		if len(f) < 3 || f[1] != "tcp" {
			continue
		}
		for _, tok := range f[2:] {
			lo, hi, isRange := strings.Cut(strings.TrimSuffix(tok, ","), "-")
			a, err := strconv.Atoi(lo)
			if err != nil {
				continue
			}
			b := a
			if isRange {
				if b, err = strconv.Atoi(hi); err != nil {
					continue
				}
			}
			if port >= a && port <= b {
				if f[0] == "ssh_port_t" {
					return true, ""
				}
				other = f[0]
			}
		}
	}
	return false, other
}

// selinuxEnforced reports whether SELinux is on, so ports need labels.
func selinuxEnforced(ctx context.Context, env *control.Env) bool {
	out, err := env.Run.Run(ctx, "getenforce")
	return err == nil && strings.TrimSpace(string(out)) != "Disabled"
}

// labelPort lets sshd bind to the port under SELinux. It reports whether it
// added a label.
func labelPort(ctx context.Context, env *control.Env, port int) (bool, error) {
	if !selinuxEnforced(ctx, env) {
		return false, nil
	}
	if err := dnf.Install(ctx, env, "policycoreutils-python-utils"); err != nil {
		return false, err
	}
	out, err := env.Run.Run(ctx, "semanage", "port", "-l")
	if err != nil {
		return false, fmt.Errorf("reading the SELinux port labels: %w", err)
	}
	labeled, other := sshPortLabeled(string(out), port)
	if labeled {
		return false, nil
	}
	if other != "" {
		return false, fmt.Errorf("port %d belongs to the SELinux type %s, so sshd may not use it. Choose another port", port, other)
	}
	if _, err := env.Run.Run(ctx, "semanage", "port", "-a", "-t", "ssh_port_t", "-p", "tcp", strconv.Itoa(port)); err != nil {
		return false, fmt.Errorf("labelling port %d for sshd in SELinux: %w", port, err)
	}
	return true, nil
}

func unlabelPort(ctx context.Context, env *control.Env, port int) error {
	_, err := env.Run.Run(ctx, "semanage", "port", "-d", "-t", "ssh_port_t", "-p", "tcp", strconv.Itoa(port))
	return err
}

// Systemd socket

func socketContent(ports []int) string {
	var b strings.Builder
	b.WriteString(sshdMarker(portID))
	b.WriteString("\n[Socket]\nListenStream=\n")
	for _, p := range ports {
		fmt.Fprintf(&b, "ListenStream=%d\n", p)
	}
	return b.String()
}

func applySocket(ctx context.Context, env *control.Env, ports []int) error {
	if err := files.WriteAtomic(env.Path(portSocketFile), []byte(socketContent(ports)), 0o644); err != nil {
		return err
	}
	return restartSocket(ctx, env)
}

func restartSocket(ctx context.Context, env *control.Env) error {
	if _, err := env.Run.Run(ctx, "systemctl", "daemon-reload"); err != nil {
		return err
	}
	return systemd.Restart(ctx, env, sshSocket)
}

// The control

func (p *sshPort) Check(ctx context.Context, env *control.Env) (control.State, error) {
	return sshdCheck(ctx, env, portID, "port")
}

func portDirectives(ports ...int) []directive {
	var ds []directive
	for _, p := range ports {
		ds = append(ds, directive{"Port", strconv.Itoa(p)})
	}
	return ds
}

func (p *sshPort) Apply(ctx context.Context, env *control.Env, in control.Values) error {
	if err := validPort(in.String("port")); err != nil {
		return err
	}
	port, _ := strconv.Atoi(strings.TrimSpace(in.String("port")))

	if f, err := portSetElsewhere(env); err != nil {
		return err
	} else if f != "" {
		return fmt.Errorf("the SSH port is already set in %s. sshd adds all Port lines together, "+
			"so this control cannot close the old port. Change the port in that file yourself, or remove the line there and run this again", f)
	}

	// Which ports sshd listens on now. Kept from the first run, so that a second
	// run does not mistake the port this control added for the old one.
	recorded, hasRecord, err := env.Rec.Get(portID, "old-ports")
	if err != nil {
		return err
	}
	var old []int
	if hasRecord {
		old = splitInts(recorded)
	} else if old, err = currentPorts(ctx, env); err != nil {
		return err
	}
	for _, o := range old {
		if o == port {
			return fmt.Errorf("sshd already listens on port %d", port)
		}
	}
	used, err := listeningPorts(ctx, env)
	if err != nil {
		return err
	}
	if line, taken := used[port]; taken && !strings.Contains(line, `"sshd"`) {
		return fmt.Errorf("port %d is already used by another service", port)
	}
	fw, err := detectFirewall(ctx, env)
	if err != nil {
		return err
	}
	socket := systemd.IsActive(ctx, env, sshSocket)

	if !hasRecord {
		for k, v := range map[string]string{"old-ports": joinInts(old), "socket": yesNo(socket), "firewall": string(fw)} {
			if err := env.Rec.Put(portID, k, v); err != nil {
				return err
			}
		}
	}
	// A second run may choose another port, or the same one again. Remember
	// the port and the firewall rule of the earlier run, so none is left behind.
	prevPortS, _, _ := env.Rec.Get(portID, "port")
	prevPort, _ := strconv.Atoi(prevPortS)
	prevAdded, _, _ := env.Rec.Get(portID, "firewall-added")
	prevLabel, _, _ := env.Rec.Get(portID, "selinux-added")
	if err := env.Rec.Put(portID, "port", strconv.Itoa(port)); err != nil {
		return err
	}

	// 1. The firewall first, so the new port is reachable the moment sshd listens.
	added, err := fwAllow(ctx, env, fw, port)
	if err != nil {
		return fmt.Errorf("opening port %d in the firewall: %w", port, err)
	}
	ours := added || (prevPort == port && prevAdded == "yes")
	if err := env.Rec.Put(portID, "firewall-added", yesNo(ours)); err != nil {
		return err
	}
	// SELinux lets sshd bind only to ports that carry the ssh_port_t label.
	labeled, err := labelPort(ctx, env, port)
	if err != nil {
		if added {
			_ = fwRemove(ctx, env, fw, port)
		}
		return err
	}
	ourLabel := labeled || (prevPort == port && prevLabel == "yes")
	if err := env.Rec.Put(portID, "selinux-added", yesNo(ourLabel)); err != nil {
		return err
	}
	undo := func() {
		_ = p.restoreSSH(ctx, env, socket)
		if added {
			_ = fwRemove(ctx, env, fw, port)
		}
		if labeled {
			_ = unlabelPort(ctx, env, port)
		}
	}

	// 2. sshd listens on the old and the new port until the change is confirmed.
	both := append(append([]int(nil), old...), port)
	if socket {
		if err := env.Rec.Backup(portID, env.Path(portSocketFile)); err != nil {
			undo()
			return err
		}
		if err := applySocket(ctx, env, both); err != nil {
			undo()
			return fmt.Errorf("changing the SSH socket: %w", err)
		}
	}
	if err := sshdApply(ctx, env, portID, "port", portDirectives(both...)); err != nil {
		undo()
		return err
	}
	if err := waitListening(ctx, env, port); err != nil {
		undo()
		return err
	}
	if prevPort != 0 && prevPort != port && prevAdded == "yes" {
		if err := fwRemove(ctx, env, fw, prevPort); err != nil {
			env.Log.Warnf("%s: could not close the earlier port %d in the firewall: %v", portID, prevPort, err)
		}
	}
	if prevPort != 0 && prevPort != port && prevLabel == "yes" {
		if err := unlabelPort(ctx, env, prevPort); err != nil {
			env.Log.Warnf("%s: could not remove the SELinux label of the earlier port %d: %v", portID, prevPort, err)
		}
	}
	env.Log.Infof("SSH listens on ports %s now. From a new terminal, log in on port %d", joinInts(both), port)
	return nil
}

// Finalize closes the old port once the user has logged in on the new one.
func (p *sshPort) Finalize(ctx context.Context, env *control.Env) error {
	if !env.Rec.Has(portID) {
		return nil
	}
	port, _, err := env.Rec.Get(portID, "port")
	if err != nil {
		return err
	}
	n, err := strconv.Atoi(port)
	if err != nil {
		return fmt.Errorf("the recorded port %q is not a number", port)
	}
	socket := systemd.IsActive(ctx, env, sshSocket)
	if err := sshdApply(ctx, env, portID, "port", portDirectives(n)); err != nil {
		return err
	}
	if socket {
		if err := applySocket(ctx, env, []int{n}); err != nil {
			return err
		}
	}
	if err := waitListening(ctx, env, n); err != nil {
		return err
	}
	env.Log.Infof("SSH listens on port %d only", n)
	return nil
}

// restoreSSH puts the sshd drop-in and the socket override back to how they were.
func (p *sshPort) restoreSSH(ctx context.Context, env *control.Env, socket bool) error {
	if _, err := env.Rec.Restore(portID, env.Path(sshdFile("port"))); err != nil {
		return err
	}
	if socket {
		if _, err := env.Rec.Restore(portID, env.Path(portSocketFile)); err != nil {
			return err
		}
		if err := restartSocket(ctx, env); err != nil {
			return err
		}
	}
	if err := sshdValidate(ctx, env); err != nil {
		return err
	}
	return sshdReload(ctx, env)
}

func (p *sshPort) Revert(ctx context.Context, env *control.Env) error {
	if !env.Rec.Has(portID) {
		env.Log.Warnf("%s: no record, leaving the SSH port alone", portID)
		return nil
	}
	get := func(k string) string { v, _, _ := env.Rec.Get(portID, k); return v }
	old := splitInts(get("old-ports"))
	port, _ := strconv.Atoi(get("port"))
	socket := get("socket") == "yes"
	fw := firewall(get("firewall"))

	// Open the old ports again before the new one closes.
	for _, o := range old {
		if _, err := fwAllow(ctx, env, fw, o); err != nil {
			return fmt.Errorf("opening port %d in the firewall: %w", o, err)
		}
	}
	if err := p.restoreSSH(ctx, env, socket); err != nil {
		return err
	}
	for _, o := range old {
		if err := waitListening(ctx, env, o); err != nil {
			env.Log.Warnf("%s: %v", portID, err)
		}
	}
	if get("firewall-added") == "yes" {
		if err := fwRemove(ctx, env, fw, port); err != nil {
			env.Log.Warnf("%s: could not close port %d in the firewall: %v", portID, port, err)
		}
	}
	if get("selinux-added") == "yes" {
		if err := unlabelPort(ctx, env, port); err != nil {
			env.Log.Warnf("%s: could not remove the SELinux label of port %d: %v", portID, port, err)
		}
	}
	return env.Rec.Delete(portID)
}
