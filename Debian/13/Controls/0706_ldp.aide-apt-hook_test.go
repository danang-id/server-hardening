// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Danang Galuh Tegar Prasetyo

package controls

import (
	"context"
	"strings"
	"testing"

	"github.com/danang-id/server-hardening/internal/control"
)

func hookControl() *aideAptHook { return &aideAptHook{control.Base{M: control.Meta{ID: aideHookID}}} }

func TestAIDEHookWithAndWithoutCheck(t *testing.T) {
	ctx := context.Background()
	env, _, _ := sysEnv(t)
	c := hookControl()
	if state(t, c, env) != control.NotApplied {
		t.Fatal("should start not applied")
	}
	if err := c.Apply(ctx, env, control.Values{"before": {"yes"}}); err == nil {
		t.Fatal("without the script from ldp.aide the hook would call nothing")
	}
	noFile(t, env, aideHookFile)

	writeFile(t, env, aideRunPath, "#!/bin/sh\n")
	must(t, c.Apply(ctx, env, control.Values{"before": {"yes"}}))
	got := read(t, env, aideHookFile)
	wantContains(t, got, "Managed by github.com/danang-id/server-hardening (ldp.aide-apt-hook)",
		"DPkg::Pre-Invoke { \""+aideRunPath+" pre || true\"; };",
		"DPkg::Post-Invoke { \""+aideRunPath+" update || true\"; };")
	if !strings.HasPrefix(got, "// Managed") {
		t.Fatalf("the marker must be an apt comment: %q", got)
	}
	if state(t, c, env) != control.Applied {
		t.Fatal("should be applied")
	}

	must(t, c.Apply(ctx, env, control.Values{"before": {"no"}}))
	if got := read(t, env, aideHookFile); strings.Contains(got, "Pre-Invoke") || !strings.Contains(got, "Post-Invoke") {
		t.Fatalf("without the check only the update stays: %q", got)
	}

	must(t, c.Revert(ctx, env))
	noFile(t, env, aideHookFile)
	if env.Rec.Has(aideHookID) {
		t.Fatal("record should be gone")
	}
}

func TestAIDEHookIsPartialWithoutScript(t *testing.T) {
	env, _, _ := sysEnv(t)
	writeFile(t, env, aideRunPath, "#!/bin/sh\n")
	c := hookControl()
	must(t, c.Apply(context.Background(), env, control.Values{"before": {"yes"}}))
	noFileAt(t, env, aideRunPath)
	if state(t, c, env) != control.Partial {
		t.Fatal("a hook that calls a missing script is partial")
	}
}
