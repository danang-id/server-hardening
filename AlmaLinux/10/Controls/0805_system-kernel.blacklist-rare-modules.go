// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Danang Galuh Tegar Prasetyo

package controls

import (
	"context"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/danang-id/server-hardening/internal/control"
	"github.com/danang-id/server-hardening/internal/files"
)

const (
	modulesID   = "system-kernel.blacklist-rare-modules"
	modulesFile = "/etc/modprobe.d/server-hardening-blacklist.conf"
)

type blacklistModules struct{ control.Base }

func init() {
	System.Add(&blacklistModules{control.Base{M: control.Meta{
		ID:       modulesID,
		Category: control.SystemKernel,
		Number:   5,
		Title:    "Disable rarely used kernel modules",
		Default:  false,
		Tags:     []control.Tag{control.TagInput, control.TagCompat},
	}}})
}

type rareModule struct{ name, why string }

var rareModules = []rareModule{
	{"dccp", "Network protocol DCCP, almost never used"},
	{"sctp", "Network protocol SCTP. Some telephony software needs it"},
	{"rds", "Network protocol RDS, used by some Oracle clusters only"},
	{"tipc", "Network protocol TIPC, used in telecom clusters only"},
	{"cramfs", "Legacy filesystem for tiny devices"},
	{"freevxfs", "Legacy filesystem of old Unix systems"},
	{"hfs", "Legacy Apple filesystem"},
	{"hfsplus", "Legacy Apple filesystem"},
	{"jffs2", "Filesystem for flash chips on embedded devices"},
}

func (b *blacklistModules) Inputs(context.Context, *control.Env) ([]control.Input, error) {
	var opts []control.Option
	var def []string
	for _, m := range rareModules {
		opts = append(opts, control.Option{Value: m.name, Label: m.name, Help: m.why})
		def = append(def, m.name)
	}
	return []control.Input{{
		Key: "modules", Label: "Which kernel modules do you want to block?",
		Help: "Modules that are loaded now stay loaded until the next reboot.",
		Kind: control.MultiChoice, Options: opts, DefaultMulti: def,
	}}, nil
}

func modulesContent(mods []string) string {
	var b strings.Builder
	b.WriteString(managed(modulesID))
	b.WriteString("\n")
	for _, m := range mods {
		fmt.Fprintf(&b, "blacklist %s\ninstall %s /bin/false\n", m, m)
	}
	return b.String()
}

func (b *blacklistModules) Check(_ context.Context, env *control.Env) (control.State, error) {
	if !hasMarker(env, modulesFile, modulesID) {
		return control.NotApplied, nil
	}
	rec, _, _ := env.Rec.Get(modulesID, "modules")
	content, _ := files.ReadOptional(env.Path(modulesFile))
	for _, m := range strings.Fields(rec) {
		if !strings.Contains(string(content), "install "+m+" /bin/false") {
			return control.Partial, nil
		}
	}
	return control.Applied, nil
}

func (b *blacklistModules) Apply(_ context.Context, env *control.Env, in control.Values) error {
	known := map[string]bool{}
	for _, m := range rareModules {
		known[m.name] = true
	}
	seen := map[string]bool{}
	var mods []string
	for _, m := range in.List("modules") {
		if !known[m] {
			return fmt.Errorf("%q is not a module this control offers", m)
		}
		if !seen[m] {
			seen[m] = true
			mods = append(mods, m)
		}
	}
	sort.Strings(mods)
	if len(mods) == 0 {
		env.Log.Infof("no module chosen, nothing blocked")
		return nil
	}
	if err := env.Rec.Put(modulesID, "modules", strings.Join(mods, " ")); err != nil {
		return err
	}
	if err := putFile(env, modulesID, modulesFile, modulesContent(mods), 0o644); err != nil {
		return err
	}
	if loaded, err := os.ReadFile(env.Path("/proc/modules")); err == nil {
		for l := range strings.SplitSeq(string(loaded), "\n") {
			if f := strings.Fields(l); len(f) > 0 && seen[f[0]] {
				env.Log.Warnf("%s is loaded now and stays loaded until the next reboot", f[0])
			}
		}
	}
	return nil
}

func (b *blacklistModules) Revert(_ context.Context, env *control.Env) error {
	if !env.Rec.Has(modulesID) {
		env.Log.Warnf("%s: no record, leaving the module settings alone", modulesID)
		return nil
	}
	if err := restoreFile(env, modulesID, modulesFile); err != nil {
		return err
	}
	return env.Rec.Delete(modulesID)
}
