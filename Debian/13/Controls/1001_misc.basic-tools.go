// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Danang Galuh Tegar Prasetyo

package controls

import (
	"context"
	"fmt"
	"strings"

	"github.com/danang-id/server-hardening/internal/apt"
	"github.com/danang-id/server-hardening/internal/control"
)

const toolsID = "misc.basic-tools"

type basicTools struct{ control.Base }

func init() {
	System.Add(&basicTools{control.Base{M: control.Meta{
		ID:           toolsID,
		Category:     control.Misc,
		Number:       1,
		Title:        "Install common administration tools",
		Default:      false,
		Tags:         []control.Tag{control.TagInput},
		RevertLimits: "The tool does not remove the packages. It lists the ones it installed, with the command to remove them.",
	}}})
}

type tool struct {
	pkg, why  string
	byDefault bool
}

var toolList = []tool{
	{"curl", "Fetch and send data over HTTP", true},
	{"vim", "Text editor", true},
	{"htop", "Interactive process viewer", true},
	{"tmux", "Terminal multiplexer: sessions that survive a dropped connection", true},
	{"rsync", "Copy files, locally or over SSH", true},
	{"unzip", "Open zip archives", true},
	{"lsof", "List open files and the ports programs hold", true},
	{"jq", "Read and filter JSON on the command line", true},
	{"bind9-dnsutils", "dig and nslookup, to test DNS", true},
	{"git", "Version control", false},
	{"wget", "Download files", false},
	{"ncdu", "Find what uses the disk", false},
	{"mtr-tiny", "Trace the network path to a host", false},
}

func (b *basicTools) Inputs(context.Context, *control.Env) ([]control.Input, error) {
	var opts []control.Option
	var def []string
	for _, t := range toolList {
		opts = append(opts, control.Option{Value: t.pkg, Label: t.pkg, Help: t.why})
		if t.byDefault {
			def = append(def, t.pkg)
		}
	}
	return []control.Input{{
		Key: "packages", Label: "Which tools do you want to install?",
		Help: "Every package is also code on the server that must be kept up to date.",
		Kind: control.MultiChoice, Options: opts, DefaultMulti: def,
	}}, nil
}

func (b *basicTools) Check(ctx context.Context, env *control.Env) (control.State, error) {
	if !env.Rec.Has(toolsID) {
		return control.NotApplied, nil
	}
	v, _, _ := env.Rec.Get(toolsID, "chosen")
	for _, p := range lines(v) {
		if !apt.Installed(ctx, env, p) {
			return control.Partial, nil
		}
	}
	return control.Applied, nil
}

func (b *basicTools) Apply(ctx context.Context, env *control.Env, in control.Values) error {
	known := map[string]bool{}
	for _, t := range toolList {
		known[t.pkg] = true
	}
	prevChosen, _, _ := env.Rec.Get(toolsID, "chosen")
	prevAdded, _, _ := env.Rec.Get(toolsID, "installed")
	chosen, added := lines(prevChosen), lines(prevAdded)
	var fresh []string
	for _, p := range in.List("packages") {
		if !known[p] {
			return fmt.Errorf("%q is not a package this control offers", p)
		}
		if !contains(chosen, p) {
			chosen = append(chosen, p)
		}
		if !apt.Installed(ctx, env, p) {
			fresh = append(fresh, p)
		}
	}
	if len(chosen) == 0 {
		env.Log.Infof("no tool chosen, nothing installed")
		return nil
	}
	// Remember what was missing before, so a revert can name only those.
	for _, p := range fresh {
		if !contains(added, p) {
			added = append(added, p)
		}
	}
	if err := env.Rec.Put(toolsID, "installed", strings.Join(added, "\n")); err != nil {
		return err
	}
	if err := env.Rec.Put(toolsID, "chosen", strings.Join(chosen, "\n")); err != nil {
		return err
	}
	return apt.Install(ctx, env, chosen...)
}

func (b *basicTools) Revert(_ context.Context, env *control.Env) error {
	if !env.Rec.Has(toolsID) {
		env.Log.Warnf("%s: no record, nothing to revert", toolsID)
		return nil
	}
	v, _, _ := env.Rec.Get(toolsID, "installed")
	if l := lines(v); len(l) > 0 {
		env.Log.Infof("the packages stay installed. To remove the ones this control installed: apt-get purge %s", strings.Join(l, " "))
	}
	return env.Rec.Delete(toolsID)
}
