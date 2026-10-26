// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Danang Galuh Tegar Prasetyo

package controls

import (
	"context"
	"testing"

	"github.com/danang-id/server-hardening/internal/control"
)

func TestVMTuning(t *testing.T) {
	ctx := context.Background()
	env, _, k := sysctlEnv(t, map[string]string{"vm.swappiness": "60", "vm.vfs_cache_pressure": "100"})
	c := &vmTuning{control.Base{M: control.Meta{ID: vmID}}}
	must(t, c.Apply(ctx, env, control.Values{"swappiness": {"10"}, "pressure": {"50"}}))
	wantContains(t, read(t, env, sysctlFile("vm")), "vm.swappiness = 10", "vm.vfs_cache_pressure = 50")
	if k.get("vm.swappiness") != "10" || state(t, c, env) != control.Applied {
		t.Fatal("values should be set")
	}
	must(t, c.Revert(ctx, env))
	if k.get("vm.swappiness") != "60" || k.get("vm.vfs_cache_pressure") != "100" {
		t.Fatalf("revert: %v", k.running)
	}
	for _, v := range []control.Values{
		{"swappiness": {"101"}, "pressure": {"50"}},
		{"swappiness": {"10"}, "pressure": {"0"}},
		{"swappiness": {"x"}, "pressure": {"50"}},
	} {
		if err := c.Apply(ctx, env, v); err == nil {
			t.Fatalf("%v must be refused", v)
		}
	}
}
