// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Danang Galuh Tegar Prasetyo

package controls

import (
	"context"
	"strings"
	"testing"

	"github.com/danang-id/server-hardening/internal/control"
)

func TestTimezoneRoundTrip(t *testing.T) {
	ctx := context.Background()
	env, run := testEnv(t)
	run.out["timedatectl show -p Timezone --value"] = "Etc/UTC\n"
	run.hook = func(f *fakeRunner, c string) {
		if z, ok := strings.CutPrefix(c, "timedatectl set-timezone "); ok {
			f.out["timedatectl show -p Timezone --value"] = z + "\n"
		}
	}
	c := &timezone{control.Base{M: control.Meta{ID: tzID}}}

	if state(t, c, env) != control.NotApplied {
		t.Fatal("applied before apply")
	}
	must(t, c.Apply(ctx, env, control.Values{"timezone": {"Asia/Jakarta"}}))
	if state(t, c, env) != control.Applied {
		t.Fatal("not applied after apply")
	}
	must(t, c.Revert(ctx, env))
	if state(t, c, env) != control.NotApplied {
		t.Fatal("still applied after revert")
	}
	if last := run.calls[len(run.calls)-1]; last != "timedatectl set-timezone Etc/UTC" {
		t.Fatalf("revert command: %q", last)
	}
}

func TestTimezoneRejectsUnknownZone(t *testing.T) {
	env, run := testEnv(t)
	c := &timezone{control.Base{M: control.Meta{ID: tzID}}}
	for _, bad := range []string{"Mars/Base", "../etc/passwd", "/etc/passwd", ""} {
		if err := c.Apply(context.Background(), env, control.Values{"timezone": {bad}}); err == nil {
			t.Errorf("%q should be rejected", bad)
		}
	}
	if run.did("set-timezone") {
		t.Fatal("a command ran for an invalid zone")
	}
}
