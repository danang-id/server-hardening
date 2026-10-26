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
)

const selinuxAuditID = "mac.selinux-audit"

type selinuxAudit struct{ control.Base }

func init() {
	System.Add(&selinuxAudit{control.Base{M: control.Meta{
		ID:       selinuxAuditID,
		Category: control.MAC,
		Number:   2,
		Title:    "Audit what SELinux blocks and what it does not confine",
		Default:  true,
		Tags:     []control.Tag{control.TagReadonly},
	}}})
}

var avcComm = regexp.MustCompile(`\bcomm="?([^" ]+)"?`)

// avcDenials counts the access denials SELinux logged since the boot, by
// program. ausearch exits with an error when it finds nothing, so a failing
// command with no output means "none".
func avcDenials(ctx context.Context, env *control.Env) map[string]int {
	out, _ := env.Run.Run(ctx, "ausearch", "-m", "AVC,USER_AVC", "-ts", "boot", "-i")
	byComm := map[string]int{}
	for l := range strings.SplitSeq(string(out), "\n") {
		if !strings.Contains(l, "denied") {
			continue
		}
		name := "unknown"
		if m := avcComm.FindStringSubmatch(l); m != nil {
			name = m[1]
		}
		byComm[name]++
	}
	return byComm
}

// unconfinedServices lists the programs that run as a service but without a
// policy of their own (unconfined_service_t): SELinux does not limit them.
func unconfinedServices(ctx context.Context, env *control.Env) []string {
	out, err := env.Run.Run(ctx, "ps", "-eZ", "--no-headers")
	if err != nil {
		return nil
	}
	set := map[string]bool{}
	for l := range strings.SplitSeq(string(out), "\n") {
		f := strings.Fields(l)
		if len(f) < 2 {
			continue
		}
		parts := strings.Split(f[0], ":")
		if len(parts) >= 3 && parts[2] == "unconfined_service_t" {
			set[f[len(f)-1]] = true
		}
	}
	var names []string
	for n := range set {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

// auditSELinux lists what looks unsafe or unusual. It reads only.
func auditSELinux(ctx context.Context, env *control.Env) []string {
	var findings []string
	add := func(f string, a ...any) { findings = append(findings, fmt.Sprintf(f, a...)) }

	mode := selinuxMode(ctx, env)
	switch mode {
	case "Disabled":
		add("SELinux is switched off")
		return findings // the rest needs SELinux
	case "Permissive":
		add("SELinux is permissive: it logs what it would block, but blocks nothing")
	}
	if conf, err := selinuxConfigured(env); err == nil && conf != "" && conf != "enforcing" {
		add("%s asks for %s at the next boot", selinuxConfig, conf)
	}
	if d := avcDenials(ctx, env); len(d) > 0 {
		var names []string
		total := 0
		for n, c := range d {
			names = append(names, fmt.Sprintf("%s (%d)", n, c))
			total += c
		}
		sort.Strings(names)
		add("SELinux logged %d denial(s) since the boot: %s. Read them with \"ausearch -m AVC -ts boot -i\" and \"sealert\"", total, strings.Join(names, ", "))
	}
	if u := unconfinedServices(ctx, env); len(u) > 0 {
		add("these services run without a SELinux policy of their own: %s", strings.Join(u, ", "))
	}
	return findings
}

func (a *selinuxAudit) Check(ctx context.Context, env *control.Env) (control.State, error) {
	if len(auditSELinux(ctx, env)) > 0 {
		return control.Partial, nil
	}
	return control.Applied, nil
}

func (a *selinuxAudit) Apply(ctx context.Context, env *control.Env, _ control.Values) error {
	f := auditSELinux(ctx, env)
	if len(f) == 0 {
		env.Log.Infof("SELinux enforces its policy, logged no denial since the boot, and every service is confined")
		return nil
	}
	for _, x := range f {
		env.Log.Warnf("%s", x)
	}
	env.Log.Infof("%d finding(s). This control changes nothing: review them yourself", len(f))
	return nil
}

func (a *selinuxAudit) Revert(context.Context, *control.Env) error { return control.ErrNoRevert }
