// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Danang Galuh Tegar Prasetyo

package controls

import (
	"context"
	"strings"
	"testing"

	"github.com/danang-id/server-hardening/internal/control"
)

func TestKexec(t *testing.T) {
	ctx := context.Background()
	env, _, k := sysctlEnv(t, map[string]string{"kernel.kexec_load_disabled": "0"})
	var warned []string
	env.Log = &memLog{warns: &warned}
	c := &disableKexec{control.Base{M: control.Meta{ID: kexecID}}}
	must(t, c.Apply(ctx, env, nil))
	if k.get("kernel.kexec_load_disabled") != "1" || state(t, c, env) != control.Applied {
		t.Fatal("kexec should be off")
	}
	k.locked["kernel.kexec_load_disabled"] = true
	must(t, c.Revert(ctx, env))
	noFile(t, env, sysctlFile("kexec"))
	if !strings.Contains(strings.Join(warned, "\n"), "until the next reboot") {
		t.Fatalf("both Apply and Revert must say that a reboot is needed: %v", warned)
	}
}
