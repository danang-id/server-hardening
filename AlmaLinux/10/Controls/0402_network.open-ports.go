// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Danang Galuh Tegar Prasetyo

package controls

import (
	"context"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/danang-id/server-hardening/internal/control"
)

type openPorts struct{ control.Base }

func init() {
	System.Add(&openPorts{control.Base{M: control.Meta{
		ID:           portsID,
		Category:     control.Network,
		Number:       2,
		Title:        "Choose which ports stay open",
		Default:      true,
		Requires:     []string{fwID},
		Tags:         []control.Tag{control.TagInput},
		RevertLimits: "Services that were reachable through those rules become unreachable.",
	}}})
}

type listener struct {
	Port    int
	Proto   string
	Process string
}

var processName = regexp.MustCompile(`\(\("([^"]+)"`)

// listeners lists the ports that answer from outside: loopback-only sockets
// and SSH are left out.
func listeners(ctx context.Context, env *control.Env) []listener {
	out, err := env.Run.Run(ctx, "ss", "-H", "-lntup")
	if err != nil {
		return nil
	}
	ssh, _ := sshPorts(ctx, env)
	isSSH := map[int]bool{}
	for _, p := range ssh {
		isSSH[p] = true
	}
	seen := map[string]bool{}
	var res []listener
	for l := range strings.SplitSeq(string(out), "\n") {
		f := strings.Fields(l)
		if len(f) < 5 || (f[0] != "tcp" && f[0] != "udp") {
			continue
		}
		addr := f[4]
		i := strings.LastIndex(addr, ":")
		if i < 0 {
			continue
		}
		host, ps := addr[:i], addr[i+1:]
		if strings.HasPrefix(host, "127.") || host == "[::1]" || strings.Contains(host, "%lo") {
			continue
		}
		p, err := strconv.Atoi(ps)
		if err != nil || (isSSH[p] && f[0] == "tcp") {
			continue
		}
		key := fmt.Sprintf("%d/%s", p, f[0])
		if seen[key] {
			continue
		}
		seen[key] = true
		proc := ""
		if m := processName.FindStringSubmatch(l); m != nil {
			proc = m[1]
		}
		res = append(res, listener{p, f[0], proc})
	}
	sort.Slice(res, func(i, j int) bool {
		if res[i].Port != res[j].Port {
			return res[i].Port < res[j].Port
		}
		return res[i].Proto < res[j].Proto
	})
	return res
}

func (o *openPorts) Inputs(ctx context.Context, env *control.Env) ([]control.Input, error) {
	var ins []control.Input
	if ls := listeners(ctx, env); len(ls) > 0 {
		var opts []control.Option
		for _, l := range ls {
			label := fmt.Sprintf("%d/%s", l.Port, l.Proto)
			if l.Process != "" {
				label += " (" + l.Process + ")"
			}
			opts = append(opts, control.Option{Value: fmt.Sprintf("%d/%s", l.Port, l.Proto), Label: label})
		}
		ins = append(ins, control.Input{
			Key:   "listening",
			Label: "Open the ports that are listening now",
			Help:  "Services listening on the server. SSH is open already. Open only what must be reachable from outside.",
			Kind:  control.MultiChoice, Options: opts,
		})
	}
	ins = append(ins, control.Input{
		Key:   "rules",
		Label: "More ports to open, one per line (optional)",
		Help:  "Form: PORT, PORT/PROTO, or PORT/PROTO from ADDRESS. Examples: 443/tcp, 8000-8010/tcp, 51820/udp from 203.0.113.0/24.",
		Kind:  control.TextArea, Optional: true,
		Validate: func(s string) error { _, err := parsePortRules(s); return err },
	})
	return ins, nil
}

func (o *openPorts) Check(ctx context.Context, env *control.Env) (control.State, error) {
	if !env.Rec.Has(portsID) {
		return control.NotApplied, nil
	}
	e, err := engineOf(env)
	if err != nil {
		return control.NotApplied, nil
	}
	rules, err := recordedRules(env)
	if err != nil {
		return control.NotApplied, err
	}
	var listing string
	switch e {
	case nftables:
		out, err := env.Run.Run(ctx, "nft", "list", "table", "inet", nftTable)
		if err != nil {
			return control.Partial, nil
		}
		listing = string(out)
	case firewalld:
		a, _ := env.Run.Run(ctx, "firewall-cmd", "--list-ports")
		b, _ := env.Run.Run(ctx, "firewall-cmd", "--list-rich-rules")
		listing = string(a) + "\n" + string(b)
	}
	for _, r := range rules {
		if !strings.Contains(listing, r.Port) {
			return control.Partial, nil
		}
	}
	return control.Applied, nil
}

func (o *openPorts) Apply(ctx context.Context, env *control.Env, in control.Values) error {
	e, err := engineOf(env)
	if err != nil {
		return err
	}
	text := strings.Join(in.List("listening"), "\n") + "\n" + in.String("rules")
	want, err := parsePortRules(text)
	if err != nil {
		return err
	}
	have, err := recordedRules(env)
	if err != nil {
		return err
	}
	if err := o.sync(ctx, env, e, have, want); err != nil {
		return err
	}
	if len(want) == 0 {
		env.Log.Infof("no port is open beyond SSH")
	} else {
		env.Log.Infof("open: %s", strings.ReplaceAll(ruleLines(want), "\n", ", "))
	}
	return nil
}

// sync turns the rules of the engine from have into want.
func (o *openPorts) sync(ctx context.Context, env *control.Env, e firewall, have, want []portRule) error {
	in := func(list []portRule, r portRule) bool {
		for _, x := range list {
			if x == r {
				return true
			}
		}
		return false
	}
	var drop, add []portRule
	for _, r := range have {
		if !in(want, r) {
			drop = append(drop, r)
		}
	}
	for _, r := range want {
		if !in(have, r) {
			add = append(add, r)
		}
	}
	if e == nftables {
		if err := env.Rec.Put(portsID, "rules", ruleLines(want)); err != nil {
			return err
		}
		if err := nftRebuild(ctx, env); err != nil {
			_ = env.Rec.Put(portsID, "rules", ruleLines(have))
			return err
		}
		return nil
	}
	var done []portRule
	undo := func() {
		for _, r := range done {
			_ = o.change(ctx, env, e, r, false)
		}
	}
	for _, r := range add {
		if err := o.change(ctx, env, e, r, true); err != nil {
			undo()
			return fmt.Errorf("opening %s: %w", r, err)
		}
		done = append(done, r)
		if err := env.Rec.Put(portsID, "rules", ruleLines(append(append([]portRule(nil), have...), done...))); err != nil {
			return err
		}
	}
	for _, r := range drop {
		if err := o.change(ctx, env, e, r, false); err != nil {
			env.Log.Warnf("%s: could not close %s: %v", portsID, r, err)
		}
	}
	if e == firewalld {
		if err := fwcmd(ctx, env, "--reload"); err != nil {
			return err
		}
	}
	return env.Rec.Put(portsID, "rules", ruleLines(want))
}

// change adds or removes one rule in firewalld.
func (o *openPorts) change(ctx context.Context, env *control.Env, e firewall, r portRule, add bool) error {
	switch e {
	case firewalld:
		verb := "--add-"
		if !add {
			verb = "--remove-"
		}
		rich, port := firewalldRule(r)
		if rich != "" {
			return fwcmd(ctx, env, "--permanent", "--zone=public", verb+"rich-rule="+rich)
		}
		return fwcmd(ctx, env, "--permanent", "--zone=public", verb+"port="+port)
	}
	return fmt.Errorf("unknown engine %s", e)
}

func (o *openPorts) Revert(ctx context.Context, env *control.Env) error {
	if !env.Rec.Has(portsID) {
		env.Log.Warnf("%s: no record, leaving the firewall rules alone", portsID)
		return nil
	}
	e, err := engineOf(env)
	if err != nil {
		// The firewall was reverted first; its own revert removed the rules.
		return env.Rec.Delete(portsID)
	}
	have, err := recordedRules(env)
	if err != nil {
		return err
	}
	if err := o.sync(ctx, env, e, have, nil); err != nil {
		return err
	}
	return env.Rec.Delete(portsID)
}
