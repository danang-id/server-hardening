// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Danang Galuh Tegar Prasetyo

package controls

import (
	"context"
	"strings"
	"testing"

	"github.com/danang-id/server-hardening/internal/control"
)

func removeControl() *removeUnneeded {
	return &removeUnneeded{control.Base{M: control.Meta{ID: removeID}}}
}

func TestRemoveOffersOnlyInstalledPackages(t *testing.T) {
	env, _, s := sysEnv(t)
	s.installed["telnet"] = true
	s.installed["postfix"] = true
	s.alsoGoes["postfix"] = []string{"postfix-extras", "postfix-config"}
	in, err := removeControl().Inputs(context.Background(), env)
	must(t, err)
	if len(in) != 1 || len(in[0].Options) != 2 {
		t.Fatalf("want one input with two options, got %+v", in)
	}
	if got := strings.Join(in[0].DefaultMulti, ","); got != "telnet" {
		t.Fatalf("a mail agent must not be ticked at first, got %q", got)
	}
	var exim control.Option
	for _, o := range in[0].Options {
		if o.Value == "postfix" {
			exim = o
		}
	}
	wantContains(t, exim.Help, "local mail delivery", "Removed with it: postfix-extras, postfix-config")
}

func TestRemoveNothingInstalled(t *testing.T) {
	env, _, _ := sysEnv(t)
	in, _ := removeControl().Inputs(context.Background(), env)
	if in != nil {
		t.Fatalf("no candidates, no question: %+v", in)
	}
	// An action: with nothing to remove it is still offered, and running it
	// says so instead of claiming it was applied before.
	if state(t, removeControl(), env) != control.NotApplied {
		t.Fatal("a removal job is never already applied")
	}
	run := env.Run.(*fakeRunner)
	must(t, removeControl().Apply(context.Background(), env, control.Values{}))
	if run.did("dnf -y remove") {
		t.Fatal("nothing should be removed")
	}
}

func TestRemoveUnneededIsAnAction(t *testing.T) {
	c, ok := System.Get(removeID)
	if !ok || !c.Meta().Action {
		t.Fatal("remove-unneeded-packages must be an action")
	}
}

func TestRemovePurgesChosenPackages(t *testing.T) {
	env, run, s := sysEnv(t)
	s.installed["telnet"] = true
	s.installed["avahi"] = true
	s.alsoGoes["avahi"] = []string{"avahi-libs"}
	c := removeControl()
	if state(t, c, env) != control.NotApplied {
		t.Fatal("should start not applied")
	}
	must(t, c.Apply(context.Background(), env, control.Values{"packages": {"avahi"}}))
	if s.installed["avahi"] || s.installed["avahi-libs"] {
		t.Fatalf("avahi should be gone: %v", s.installed)
	}
	if !s.installed["telnet"] {
		t.Fatal("telnet was not chosen")
	}
	if !run.did("dnf -y remove avahi") {
		t.Fatalf("calls: %v", run.calls)
	}
	if state(t, c, env) != control.NotApplied {
		t.Fatal("telnet is still there")
	}
	if err := c.Revert(context.Background(), env); err != control.ErrNoRevert {
		t.Fatalf("want ErrNoRevert, got %v", err)
	}
}

func TestRemoveRefusesWhatTakesProtectedPackages(t *testing.T) {
	env, run, s := sysEnv(t)
	s.installed["cups"] = true
	s.alsoGoes["cups"] = []string{"openssh-server"}
	err := removeControl().Apply(context.Background(), env, control.Values{"packages": {"cups"}})
	if err == nil || !strings.Contains(err.Error(), "openssh-server") {
		t.Fatalf("want a refusal that names openssh-server, got %v", err)
	}
	if run.did("dnf -y remove") {
		t.Fatal("nothing may be removed")
	}
	if !s.installed["cups"] {
		t.Fatal("cups must still be installed")
	}
}

func TestRemoveRefusesUnknownPackage(t *testing.T) {
	env, _, s := sysEnv(t)
	s.installed["sudo"] = true
	err := removeControl().Apply(context.Background(), env, control.Values{"packages": {"sudo"}})
	if err == nil {
		t.Fatal("a package outside the list must be refused")
	}
	if !s.installed["sudo"] {
		t.Fatal("sudo must stay")
	}
}

func TestRemoveEmptyChoice(t *testing.T) {
	env, run, s := sysEnv(t)
	s.installed["telnet"] = true
	must(t, removeControl().Apply(context.Background(), env, control.Values{}))
	if run.did("dnf -y remove") {
		t.Fatalf("no choice, no removal: %v", run.calls)
	}
}

func TestRemoveIsIdleOnlyWhenNothingIsInstalled(t *testing.T) {
	ctx := context.Background()
	env, _, s := sysEnv(t)
	c := removeControl()
	if got := c.Idle(ctx, env); got != "nothing to remove" {
		t.Fatalf("idle = %q on a server without these packages", got)
	}
	s.installed["telnet"] = true
	if got := c.Idle(ctx, env); got != "" {
		t.Fatalf("idle = %q with telnet installed", got)
	}
	// An action is never checked, so it is never "applied", idle or not.
	real, ok := System.Get(removeID)
	if !ok || !real.Meta().Action {
		t.Fatal("remove-unneeded-packages is an action")
	}
}
