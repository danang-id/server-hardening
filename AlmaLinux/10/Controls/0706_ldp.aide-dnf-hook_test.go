// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Danang Galuh Tegar Prasetyo

package controls

import (
	"context"
	"testing"

	"github.com/danang-id/server-hardening/internal/control"
)

func hookControl() *aideDnfHook { return &aideDnfHook{control.Base{M: control.Meta{ID: aideHookID}}} }

func TestAIDEHookUpdatesAfterDnf(t *testing.T) {
	ctx := context.Background()
	env, _, s := sysEnv(t)
	c := hookControl()
	if state(t, c, env) != control.NotApplied {
		t.Fatal("should start not applied")
	}
	if err := c.Apply(ctx, env, control.Values{}); err == nil {
		t.Fatal("without the script from ldp.aide the hook would call nothing")
	}
	noFile(t, env, aideHookFile)

	writeFile(t, env, aideRunPath, "#!/bin/sh\n")
	must(t, c.Apply(ctx, env, control.Values{}))
	if !s.installed[aideHookPlugin] {
		t.Fatal("the post-transaction-actions plugin must be installed")
	}
	wantContains(t, read(t, env, aideHookFile),
		"# Managed by github.com/danang-id/server-hardening (ldp.aide-dnf-hook)",
		"*:any:"+aideRunPath+" update\n")
	if state(t, c, env) != control.Applied {
		t.Fatal("should be applied")
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
	must(t, c.Apply(context.Background(), env, control.Values{}))
	noFileAt(t, env, aideRunPath)
	if state(t, c, env) != control.Partial {
		t.Fatal("a hook that calls a missing script is partial")
	}
}
