// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Danang Galuh Tegar Prasetyo

package controls

import (
	"context"
	"strings"
	"testing"

	"github.com/danang-id/server-hardening/internal/control"
)

func modulesControl() *blacklistModules {
	return &blacklistModules{control.Base{M: control.Meta{ID: modulesID}}}
}

func TestModulesDefaultsAndApply(t *testing.T) {
	ctx := context.Background()
	env, _, _ := sysEnv(t)
	c := modulesControl()
	in, _ := c.Inputs(ctx, env)
	if len(in[0].DefaultMulti) != len(rareModules) || len(in[0].Options) != len(rareModules) {
		t.Fatalf("all modules are ticked at first: %+v", in[0])
	}
	for _, o := range in[0].Options {
		if o.Value == "iso9660" || o.Value == "udf" {
			t.Fatal("cloud-init may need iso9660 and udf: they must not be offered")
		}
	}
	if state(t, c, env) != control.NotApplied {
		t.Fatal("should start not applied")
	}
	must(t, c.Apply(ctx, env, control.Values{"modules": {"sctp", "dccp", "dccp"}}))
	got := read(t, env, modulesFile)
	wantContains(t, got, managed(modulesID), "blacklist dccp\ninstall dccp /bin/false\n", "blacklist sctp\ninstall sctp /bin/false\n")
	if strings.Count(got, "blacklist dccp") != 1 || strings.Contains(got, "cramfs") {
		t.Fatalf("only the chosen modules, each once: %s", got)
	}
	if state(t, c, env) != control.Applied {
		t.Fatal("should be applied")
	}
	writeFile(t, env, modulesFile, managed(modulesID)+"\nblacklist dccp\n")
	if state(t, c, env) != control.Partial {
		t.Fatal("a file that lost a rule is partial")
	}
	must(t, c.Revert(ctx, env))
	noFile(t, env, modulesFile)
}

func TestModulesLoadedWarningAndRefusals(t *testing.T) {
	env, _, _ := sysEnv(t)
	writeFile(t, env, "/proc/modules", "sctp 123 0 - Live 0x0\nlibcrc32c 1 1 sctp, Live 0x0\n")
	var warned []string
	env.Log = &memLog{warns: &warned}
	c := modulesControl()
	must(t, c.Apply(context.Background(), env, control.Values{"modules": {"sctp"}}))
	if !strings.Contains(strings.Join(warned, "\n"), "sctp is loaded now") {
		t.Fatalf("warnings: %v", warned)
	}
	if err := c.Apply(context.Background(), env, control.Values{"modules": {"ext4"}}); err == nil {
		t.Fatal("a module outside the list must be refused")
	}
	if err := c.Apply(context.Background(), env, control.Values{"modules": {"sctp\ninstall ext4 /bin/true"}}); err == nil {
		t.Fatal("an injected line must be refused")
	}
}

func TestModulesNoneChosen(t *testing.T) {
	env, _, _ := sysEnv(t)
	must(t, modulesControl().Apply(context.Background(), env, control.Values{}))
	noFile(t, env, modulesFile)
}
