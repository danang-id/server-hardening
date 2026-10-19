// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Danang Galuh Tegar Prasetyo

package controls

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/danang-id/server-hardening/internal/control"
	"github.com/danang-id/server-hardening/internal/files"
	"github.com/danang-id/server-hardening/internal/systemd"
)

const (
	healthID = "misc.health-check"
	// minFreeKiB is the free space below which the check fails: 500 MiB.
	minFreeKiB = 500 * 1024
	// minMemKiB is the available memory below which the check fails: 64 MiB.
	minMemKiB = 64 * 1024
)

type healthCheck struct{ control.Base }

func init() {
	System.Add(&healthCheck{control.Base{M: control.Meta{
		ID:       healthID,
		Category: control.Misc,
		Number:   6,
		Title:    "Check that the server is healthy after the changes",
		Default:  true,
		Weight:   990,
		Tags:     []control.Tag{control.TagReadonly},
	}}})
}

type level int

const (
	levelOK level = iota
	levelWarn
	levelFail
)

type finding struct {
	level level
	text  string
}

func fail(f string, a ...any) finding { return finding{levelFail, fmt.Sprintf(f, a...)} }
func warn(f string, a ...any) finding { return finding{levelWarn, fmt.Sprintf(f, a...)} }

// healthFindings runs every check and returns what is wrong. Nothing is
// changed. A check that cannot run is reported as a warning, not as a pass.
func healthFindings(ctx context.Context, env *control.Env) []finding {
	var out []finding
	for _, check := range []func(context.Context, *control.Env) []finding{
		healthControls, healthSSH, healthFirewall, healthUnits, healthTime, healthPackages, healthDisk, healthMemory,
	} {
		out = append(out, check(ctx, env)...)
	}
	return out
}

// healthControls compares each applied control with what it reports now.
func healthControls(ctx context.Context, env *control.Env) []finding {
	var out []finding
	for _, c := range System.Controls() {
		m := c.Meta()
		if m.ID == healthID || m.Has(control.TagReadonly) || !env.Rec.Has(m.ID) {
			continue
		}
		st, err := c.Check(ctx, env)
		switch {
		case err != nil:
			out = append(out, warn("%s: cannot be checked: %v", m.ID, err))
		case st != control.Applied:
			out = append(out, fail("%s was applied, but no longer holds in full", m.ID))
		}
	}
	return out
}

func healthSSH(ctx context.Context, env *control.Env) []finding {
	if !systemd.IsActive(ctx, env, sshdService) {
		return nil // the SSH server is not used on this machine
	}
	var out []finding
	if o, err := env.Run.Run(ctx, "sshd", "-t"); err != nil {
		return []finding{fail("the SSH configuration does not pass sshd -t: %s", firstLine(string(o), err))}
	}
	ports, err := currentPorts(ctx, env)
	if err != nil {
		return []finding{warn("cannot read the SSH ports: %v", err)}
	}
	used, err := listeningPorts(ctx, env)
	if err != nil {
		return []finding{warn("cannot list listening ports: %v", err)}
	}
	for _, p := range ports {
		if _, ok := used[p]; !ok {
			out = append(out, fail("sshd is configured for port %d, but nothing listens on it", p))
		}
	}
	return out
}

func healthFirewall(ctx context.Context, env *control.Env) []finding {
	if !env.Rec.Has(fwID) {
		return nil
	}
	e, _, _ := env.Rec.Get(fwID, "engine")
	var up bool
	switch firewall(e) {
	case nftables:
		up = nftLoaded(ctx, env)
	case ufw:
		o, err := env.Run.Run(ctx, "ufw", "status")
		up = err == nil && strings.Contains(string(o), "Status: active")
	case firewalld:
		o, err := env.Run.Run(ctx, "firewall-cmd", "--state")
		up = err == nil && strings.TrimSpace(string(o)) == "running"
	default:
		return []finding{warn("the recorded firewall engine %q is unknown", e)}
	}
	if !up {
		return []finding{fail("the %s firewall is not active", e)}
	}
	return healthExposed(ctx, env)
}

// healthExposed warns about ports that listen on the network and that no rule
// of this tool allows. Another firewall rule may still allow them, so this is
// a warning.
func healthExposed(ctx context.Context, env *control.Env) []finding {
	used, err := listeningPorts(ctx, env)
	if err != nil {
		return []finding{warn("cannot list listening ports: %v", err)}
	}
	allowed := map[int]bool{}
	for _, key := range []string{"ssh-ports", "extra-ssh"} {
		v, _, _ := env.Rec.Get(fwID, key)
		for _, p := range splitInts(v) {
			allowed[p] = true
		}
	}
	rules, _ := recordedRules(env)
	var ranges [][2]int
	for _, r := range rules {
		lo, hi, ok := portBounds(r.Port)
		if ok {
			ranges = append(ranges, [2]int{lo, hi})
		}
	}
	var out []finding
	for _, p := range sortedKeys(used) {
		if allowed[p] || !onNetwork(used[p]) {
			continue
		}
		covered := false
		for _, r := range ranges {
			if p >= r[0] && p <= r[1] {
				covered = true
			}
		}
		if !covered {
			out = append(out, warn("port %d listens on the network, and no rule of this tool allows it", p))
		}
	}
	return out
}

func portBounds(s string) (lo, hi int, ok bool) {
	a, b, found := strings.Cut(s, "-")
	lo, err := strconv.Atoi(a)
	if err != nil {
		return 0, 0, false
	}
	hi = lo
	if found {
		if hi, err = strconv.Atoi(b); err != nil {
			return 0, 0, false
		}
	}
	return lo, hi, true
}

// onNetwork reports whether any of the ss lines is a socket that is not bound
// to a loopback address.
func onNetwork(ssLines string) bool {
	for _, l := range lines(ssLines) {
		f := strings.Fields(l)
		if len(f) < 4 {
			continue
		}
		a := f[3]
		if strings.HasPrefix(a, "127.") || strings.HasPrefix(a, "[::1]") {
			continue
		}
		return true
	}
	return false
}

func sortedKeys(m map[int]string) []int {
	var k []int
	for n := range m {
		k = append(k, n)
	}
	for i := 1; i < len(k); i++ {
		for j := i; j > 0 && k[j-1] > k[j]; j-- {
			k[j-1], k[j] = k[j], k[j-1]
		}
	}
	return k
}

func healthUnits(ctx context.Context, env *control.Env) []finding {
	o, err := env.Run.Run(ctx, "systemctl", "--failed", "--no-legend", "--plain")
	if err != nil {
		return []finding{warn("cannot list failed units: %v", err)}
	}
	var out []finding
	for _, l := range lines(string(o)) {
		if f := strings.Fields(l); len(f) > 0 {
			out = append(out, fail("the unit %s has failed", f[0]))
		}
	}
	return out
}

func healthTime(ctx context.Context, env *control.Env) []finding {
	o, err := env.Run.Run(ctx, "timedatectl", "show", "-p", "NTPSynchronized", "--value")
	if err != nil {
		return []finding{warn("cannot read the clock state: %v", err)}
	}
	if strings.TrimSpace(string(o)) != "yes" {
		return []finding{warn("the clock is not synchronised")}
	}
	return nil
}

func healthPackages(ctx context.Context, env *control.Env) []finding {
	var out []finding
	if o, err := env.Run.Run(ctx, "dpkg", "--audit"); err != nil || strings.TrimSpace(string(o)) != "" {
		out = append(out, fail("dpkg --audit reports broken packages: %s", firstLine(string(o), err)))
	}
	if o, err := env.Run.Run(ctx, "apt-get", "check"); err != nil {
		out = append(out, fail("apt-get check fails: %s", firstLine(string(o), err)))
	}
	return out
}

func firstLine(out string, err error) string {
	if l := lines(out); len(l) > 0 {
		return l[0]
	}
	if err != nil {
		return err.Error()
	}
	return "no details"
}

func healthDisk(ctx context.Context, env *control.Env) []finding {
	var out []finding
	seen := map[string]bool{}
	for _, dir := range []string{"/", "/var", "/boot"} {
		o, err := env.Run.Run(ctx, "df", "-Pk", dir)
		if err != nil {
			continue // /boot is often not a separate directory
		}
		l := lines(string(o))
		if len(l) < 2 {
			continue
		}
		f := strings.Fields(l[len(l)-1])
		if len(f) < 6 || seen[f[5]] {
			continue
		}
		seen[f[5]] = true
		free, err := strconv.Atoi(f[3])
		if err != nil {
			out = append(out, warn("cannot read the free space of %s", f[5]))
		} else if free < minFreeKiB {
			out = append(out, fail("%s has only %d MiB free", f[5], free/1024))
		}
	}
	return out
}

func healthMemory(_ context.Context, env *control.Env) []finding {
	b, err := files.ReadOptional(env.Path("/proc/meminfo"))
	if err != nil || len(b) == 0 {
		return []finding{warn("cannot read /proc/meminfo")}
	}
	var total, avail int
	for _, l := range lines(string(b)) {
		f := strings.Fields(l)
		if len(f) < 2 {
			continue
		}
		n, _ := strconv.Atoi(f[1])
		switch f[0] {
		case "MemTotal:":
			total = n
		case "MemAvailable:":
			avail = n
		}
	}
	switch {
	case total == 0 || avail == 0:
		return []finding{warn("/proc/meminfo has no MemAvailable")}
	case avail < minMemKiB:
		return []finding{fail("only %d MiB of memory is available", avail/1024)}
	case avail*10 < total:
		return []finding{warn("less than 10%% of the memory is available (%d MiB)", avail/1024)}
	}
	return nil
}

func (h *healthCheck) Check(_ context.Context, env *control.Env) (control.State, error) {
	if !env.Rec.Has(healthID) {
		return control.NotApplied, nil
	}
	if v, _, _ := env.Rec.Get(healthID, "last"); v != "ok" {
		return control.Partial, nil
	}
	return control.Applied, nil
}

func (h *healthCheck) Apply(ctx context.Context, env *control.Env, _ control.Values) error {
	var problems []string
	for _, f := range healthFindings(ctx, env) {
		switch f.level {
		case levelFail:
			problems = append(problems, f.text)
			env.Log.Warnf("PROBLEM: %s", f.text)
		case levelWarn:
			env.Log.Warnf("%s", f.text)
		}
	}
	if files.Exists(env.Path("/var/run/reboot-required")) {
		env.Log.Infof("a reboot is pending")
	}
	if len(problems) == 0 {
		env.Log.Infof("the health check passed")
		return env.Rec.Put(healthID, "last", "ok")
	}
	if err := env.Rec.Put(healthID, "last", fmt.Sprintf("failed:%d", len(problems))); err != nil {
		return err
	}
	if files.Exists(env.Path(notifyPath)) {
		msg := strings.Join(problems, "\n")
		if _, err := env.Run.Run(ctx, notifyPath, "misc.health-check.failed", "critical", "Health check failed", msg); err != nil {
			env.Log.Warnf("the notification was not sent: %v", err)
		}
	}
	return fmt.Errorf("the health check found %d problem(s):\n  %s", len(problems), strings.Join(problems, "\n  "))
}

func (h *healthCheck) Revert(context.Context, *control.Env) error { return control.ErrNoRevert }
