// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Danang Galuh Tegar Prasetyo

package controls

import (
	"context"
	"strings"
	"testing"

	"github.com/danang-id/server-hardening/internal/control"
)

func journaldControl() *journaldPersistent {
	return &journaldPersistent{control.Base{M: control.Meta{ID: journaldID}}}
}

func TestJournaldPersistent(t *testing.T) {
	ctx := context.Background()
	env, run, _ := sysEnv(t)
	c := journaldControl()
	if state(t, c, env) != control.NotApplied {
		t.Fatal("should start not applied")
	}
	must(t, c.Apply(ctx, env, control.Values{"max": {"1G"}, "days": {"30"}}))
	wantContains(t, read(t, env, journaldFile), managed(journaldID), "Storage=persistent", "SystemMaxUse=1G", "MaxRetentionSec=30day")
	if read(t, env, journalDir+"/.") == "<missing>" && !run.did("systemd-tmpfiles --create --prefix /var/log/journal") {
		t.Fatal("the log directory must be created")
	}
	if !run.did("systemctl restart systemd-journald") {
		t.Fatalf("the journal must restart: %v", run.calls)
	}
	if state(t, c, env) != control.Applied {
		t.Fatal("should be applied")
	}

	must(t, c.Revert(ctx, env))
	noFile(t, env, journaldFile)
	if env.Rec.Has(journaldID) {
		t.Fatal("record should be gone")
	}
}

func TestJournaldRejectsBadInput(t *testing.T) {
	env, _, _ := sysEnv(t)
	c := journaldControl()
	for _, v := range []control.Values{
		{"max": {"lots"}, "days": {"90"}},
		{"max": {"500M"}, "days": {"0"}},
		{"max": {"500M"}, "days": {"x"}},
		{"max": {"500M\nStorage=volatile"}, "days": {"90"}},
	} {
		if err := c.Apply(context.Background(), env, v); err == nil {
			t.Fatalf("%v must be refused", v)
		}
	}
	noFile(t, env, journaldFile)
}

func TestJournaldRestartFailureRestoresFile(t *testing.T) {
	env, run, _ := sysEnv(t)
	run.fail["systemctl restart systemd-journald"] = true
	if err := journaldControl().Apply(context.Background(), env, control.Values{"max": {"500M"}, "days": {"90"}}); err == nil {
		t.Fatal("expected an error")
	}
	noFile(t, env, journaldFile)
}

func TestJournaldWarnsAboutOverride(t *testing.T) {
	env, _, _ := sysEnv(t)
	writeFile(t, env, "/etc/systemd/journald.conf.d/99-mine.conf", "[Journal]\nStorage=volatile\n")
	var warned []string
	env.Log = &memLog{warns: &warned}
	must(t, journaldControl().Apply(context.Background(), env, control.Values{"max": {"500M"}, "days": {"90"}}))
	if !strings.Contains(strings.Join(warned, "\n"), "99-mine.conf sets Storage=volatile") {
		t.Fatalf("warnings: %v", warned)
	}
}
