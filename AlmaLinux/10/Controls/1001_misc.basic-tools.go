// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Danang Galuh Tegar Prasetyo

package controls

import (
	"context"
	"fmt"
	"strings"

	"github.com/danang-id/server-hardening/internal/control"
	"github.com/danang-id/server-hardening/internal/dnf"
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
	epel      bool // only in EPEL: offered when that repository is enabled
}

var toolList = []tool{
	{"curl", "Fetch and send data over HTTP", true, false},
	{"vim-enhanced", "Text editor (the plain vi is always there)", true, false},
	{"tmux", "Terminal multiplexer: sessions that survive a dropped connection", true, false},
	{"rsync", "Copy files, locally or over SSH", true, false},
	{"unzip", "Open zip archives", true, false},
	{"lsof", "List open files and the ports programs hold", true, false},
	{"jq", "Read and filter JSON on the command line", true, false},
	{"bind-utils", "dig and nslookup, to test DNS", true, false},
	{"htop", "Interactive process viewer (from EPEL)", true, true},
	{"git", "Version control", false, false},
	{"ncdu", "Find what uses the disk (from EPEL)", false, true},
	{"mtr", "Trace the network path to a host", false, false},
}

// offered lists the tools that can be installed now.
func offeredTools(ctx context.Context, env *control.Env) []tool {
	epel := dnf.RepoEnabled(ctx, env, "epel")
	var out []tool
	for _, t := range toolList {
		if !t.epel || epel {
			out = append(out, t)
		}
	}
	return out
}

func (b *basicTools) Inputs(ctx context.Context, env *control.Env) ([]control.Input, error) {
	var opts []control.Option
	var def []string
	for _, t := range offeredTools(ctx, env) {
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
		if !dnf.Installed(ctx, env, p) {
			return control.Partial, nil
		}
	}
	return control.Applied, nil
}

func (b *basicTools) Apply(ctx context.Context, env *control.Env, in control.Values) error {
	known := map[string]bool{}
	for _, t := range offeredTools(ctx, env) {
		known[t.pkg] = true
	}
	prevChosen, _, _ := env.Rec.Get(toolsID, "chosen")
	prevAdded, _, _ := env.Rec.Get(toolsID, "installed")
	chosen, added := lines(prevChosen), lines(prevAdded)
	var fresh []string
	for _, p := range in.List("packages") {
		if !known[p] {
			return fmt.Errorf("%q is not a package this control offers here (htop and ncdu need the EPEL repository: apply baseline.epel first)", p)
		}
		if !contains(chosen, p) {
			chosen = append(chosen, p)
		}
		if !dnf.Installed(ctx, env, p) {
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
	return dnf.Install(ctx, env, chosen...)
}

func (b *basicTools) Revert(_ context.Context, env *control.Env) error {
	if !env.Rec.Has(toolsID) {
		env.Log.Warnf("%s: no record, nothing to revert", toolsID)
		return nil
	}
	v, _, _ := env.Rec.Get(toolsID, "installed")
	if l := lines(v); len(l) > 0 {
		env.Log.Infof("the packages stay installed. To remove the ones this control installed: dnf remove %s", strings.Join(l, " "))
	}
	return env.Rec.Delete(toolsID)
}
