// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Danang Galuh Tegar Prasetyo

package controls

import (
	"context"
	"strings"
	"testing"

	"github.com/danang-id/server-hardening/internal/control"
)

func mirrorControl() *aptMirror { return &aptMirror{control.Base{M: control.Meta{ID: mirrorID}}} }

func TestAptMirrorRoundTrip(t *testing.T) {
	ctx := context.Background()
	env, run := testEnv(t)
	c := mirrorControl()
	in := control.Values{"mirror": {"https://mirror.example/debian/"}, "components": {"non-free-firmware", "main", "contrib"}}

	must(t, c.Apply(ctx, env, in))
	got := read(t, env, sourcesFile)
	for _, want := range []string{
		"URIs: https://mirror.example/debian\n",
		"Suites: trixie trixie-updates\n",
		"Components: main contrib non-free-firmware\n",
		"Suites: trixie-security\n",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("sources file lacks %q:\n%s", want, got)
		}
	}
	if strings.Contains(got, "deb-src") {
		t.Error("deb-src must not appear")
	}
	if legacy := read(t, env, legacySources); strings.Contains(legacy, "\ndeb ") || strings.HasPrefix(legacy, "deb ") {
		t.Errorf("legacy entries are still active: %q", legacy)
	}
	if !run.did("install ca-certificates") || !run.did("apt-get update") {
		t.Fatalf("calls: %v", run.calls)
	}
	if state(t, c, env) != control.Applied {
		t.Fatal("not applied")
	}

	must(t, c.Revert(ctx, env))
	if got := read(t, env, sourcesFile); !strings.Contains(got, "old.example") {
		t.Fatalf("sources not restored: %q", got)
	}
	if got := read(t, env, legacySources); !strings.HasPrefix(got, "deb http://old.example") {
		t.Fatalf("legacy file not restored: %q", got)
	}
	if state(t, c, env) != control.NotApplied {
		t.Fatal("still applied")
	}
}

func TestAptMirrorRejectsBadInput(t *testing.T) {
	env, _ := testEnv(t)
	c := mirrorControl()
	cases := []control.Values{
		{"mirror": {"http://insecure.example/debian"}, "components": {"main"}},
		{"mirror": {"https://ok.example/debian"}, "components": {"contrib"}},
	}
	for _, in := range cases {
		if err := c.Apply(context.Background(), env, in); err == nil {
			t.Errorf("%v should be rejected", in)
		}
	}
	if got := read(t, env, sourcesFile); !strings.Contains(got, "old.example") {
		t.Fatal("a rejected apply changed the sources")
	}
}

func TestAptMirrorPutsSourcesBackWhenUpdateFails(t *testing.T) {
	env, run := testEnv(t)
	run.fail["apt-get update"] = true
	c := mirrorControl()
	err := c.Apply(context.Background(), env, control.Values{"mirror": {"https://bad.example/debian"}, "components": {"main"}})
	if err == nil {
		t.Fatal("expected an error")
	}
	if got := read(t, env, sourcesFile); !strings.Contains(got, "old.example") {
		t.Fatalf("sources not put back: %q", got)
	}
	if state(t, c, env) != control.NotApplied {
		t.Fatal("recorded as applied")
	}
}
