// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Danang Galuh Tegar Prasetyo

package controls

import (
	"context"
	"strings"
	"testing"

	"github.com/danang-id/server-hardening/internal/control"
)

// The questions are asked before anything runs, so the administrator account
// that aaa.admin-user is about to create is not in /etc/passwd yet. These tests
// answer that control first, as the engine does, and look at the later questions.

func plannedAnswers(name string) map[string]control.Values {
	return map[string]control.Values{adminUserID: {"username": {name}, "password": {""}}}
}

func optionValues(in control.Input) string {
	var l []string
	for _, o := range in.Options {
		l = append(l, o.Value)
	}
	return strings.Join(l, ",")
}

func TestZshOffersTheAdminAccountThatWillBeCreated(t *testing.T) {
	env, _, _ := zshEnv(t)
	env.Answered = plannedAnswers("dan")
	in, err := zshControl().Inputs(context.Background(), env)
	must(t, err)
	if got := optionValues(in[0]); got != "root,alice,dan" {
		t.Fatalf("offered: %s", got)
	}
	if strings.Join(in[0].DefaultMulti, ",") != "dan" {
		t.Fatalf("the new administrator is ticked at first: %v", in[0].DefaultMulti)
	}
	if !strings.Contains(in[0].Options[2].Label, "to be created") {
		t.Fatalf("the label says the account does not exist yet: %q", in[0].Options[2].Label)
	}
}

// The account of that name may exist already: it is listed once.
func TestZshListsAnExistingAdminOnce(t *testing.T) {
	env, _, _ := zshEnv(t)
	env.Answered = plannedAnswers("alice")
	in, _ := zshControl().Inputs(context.Background(), env)
	if got := optionValues(in[0]); got != "root,alice" {
		t.Fatalf("offered: %s", got)
	}
}

func TestZshAsksAboutTheSystemWhenNoAdminIsPlanned(t *testing.T) {
	env, _, _ := zshEnv(t)
	env.Answered = map[string]control.Values{adminUserID: {"username": {"not valid!"}}}
	in, _ := zshControl().Inputs(context.Background(), env)
	if got := optionValues(in[0]); got != "root,alice" {
		t.Fatalf("an invalid name is not offered: %s", got)
	}
}

func TestOhMyZshOffersTheAdminAccountThatWillBeCreated(t *testing.T) {
	env, _, _ := omzEnv(t)
	env.Answered = plannedAnswers("dan")
	in, err := omzControl().Inputs(context.Background(), env)
	must(t, err)
	if !strings.HasSuffix(optionValues(in[0]), ",dan") || strings.Join(in[0].DefaultMulti, ",") != "dan" {
		t.Fatalf("offered %s, ticked %v", optionValues(in[0]), in[0].DefaultMulti)
	}
}

func TestAllowUsersSuggestsTheAdminAccountThatWillBeCreated(t *testing.T) {
	env, _, _ := sshEnv(t)
	env.Answered = plannedAnswers("dan")
	ins, _ := allowControl().Inputs(context.Background(), env)
	if ins[0].Default != "dan" {
		t.Fatalf("default: %q", ins[0].Default)
	}
}

func TestHidepidSuggestsTheAdminAccountThatWillBeCreated(t *testing.T) {
	env, _, _ := hidepidEnv(t)
	env.Answered = plannedAnswers("dan")
	in, _ := hidepidControl().Inputs(context.Background(), env)
	if in[2].Default != "dan" {
		t.Fatalf("members default: %q", in[2].Default)
	}
}
