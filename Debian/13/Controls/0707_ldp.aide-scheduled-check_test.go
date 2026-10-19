// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Danang Galuh Tegar Prasetyo

package controls

import (
	"context"
	"testing"

	"github.com/danang-id/server-hardening/internal/control"
)

func schedControl() *aideScheduledCheck {
	return &aideScheduledCheck{control.Base{M: control.Meta{ID: aideSchedID}}}
}

const timerName = aideSchedUnit + ".timer"

func TestAIDEScheduleWeekly(t *testing.T) {
	ctx := context.Background()
	env, run, s := sysEnv(t)
	writeFile(t, env, aideRunPath, "#!/bin/sh\n")
	// The package has its own daily check, enabled and running.
	s.enabled[aidePkgTimer], s.active[aidePkgTimer] = true, true
	writeFile(t, env, aideDefault, "# aide defaults\nCRON_DAILY_RUN=yes\nQUIET=no\n")
	c := schedControl()
	if state(t, c, env) != control.NotApplied {
		t.Fatal("should start not applied")
	}
	must(t, c.Apply(ctx, env, control.Values{"every": {"weekly"}, "at": {"04:30"}}))
	wantContains(t, read(t, env, aideTimer), "OnCalendar=Sun *-*-* 04:30:00", "Persistent=true", "WantedBy=timers.target")
	wantContains(t, read(t, env, aideService), "Type=oneshot", "ExecStart="+aideRunPath+" check")
	wantContains(t, read(t, env, aideDefault), "CRON_DAILY_RUN=no", "QUIET=no")
	if !s.enabled[timerName] || !s.active[timerName] {
		t.Fatal("the timer should be enabled and running")
	}
	if s.enabled[aidePkgTimer] || s.active[aidePkgTimer] {
		t.Fatal("the package's own check must be off")
	}
	if !run.did("systemctl daemon-reload") {
		t.Fatal("systemd must read the new units")
	}
	if state(t, c, env) != control.Applied {
		t.Fatal("should be applied")
	}

	must(t, c.Revert(ctx, env))
	noFile(t, env, aideTimer)
	noFile(t, env, aideService)
	wantContains(t, read(t, env, aideDefault), "CRON_DAILY_RUN=yes")
	if s.enabled[timerName] || s.active[timerName] {
		t.Fatal("the timer must be off")
	}
	if !s.enabled[aidePkgTimer] || !s.active[aidePkgTimer] {
		t.Fatal("the package's check must come back")
	}
	if env.Rec.Has(aideSchedID) {
		t.Fatal("record should be gone")
	}
}

func TestAIDEScheduleDailyWithoutPackageTimer(t *testing.T) {
	env, run, s := sysEnv(t)
	writeFile(t, env, aideRunPath, "#!/bin/sh\n")
	run.fail["systemctl cat "+aidePkgTimer] = true // the package has no such timer
	c := schedControl()
	must(t, c.Apply(context.Background(), env, control.Values{"every": {"daily"}, "at": {"03:00"}}))
	wantContains(t, read(t, env, aideTimer), "OnCalendar=*-*-* 03:00:00")
	if run.did("disable --now " + aidePkgTimer) {
		t.Fatal("a timer that does not exist is left alone")
	}
	must(t, c.Revert(context.Background(), env))
	if run.did("--now " + aidePkgTimer) {
		t.Fatalf("revert must not touch it either: %v", run.calls)
	}
	_ = s
}

func TestAIDEScheduleRejectsBadInput(t *testing.T) {
	env, _, _ := sysEnv(t)
	writeFile(t, env, aideRunPath, "#!/bin/sh\n")
	for _, v := range []control.Values{
		{"every": {"hourly"}, "at": {"03:00"}},
		{"every": {"daily"}, "at": {"25:00"}},
		{"every": {"daily"}, "at": {"3am"}},
		{"every": {"daily"}, "at": {"03:00\n[Service]"}},
	} {
		if err := schedControl().Apply(context.Background(), env, v); err == nil {
			t.Fatalf("%v must be refused", v)
		}
	}
	noFile(t, env, aideTimer)
}

func TestAIDEScheduleNeedsScript(t *testing.T) {
	env, _, _ := sysEnv(t)
	if err := schedControl().Apply(context.Background(), env, control.Values{"every": {"daily"}, "at": {"03:00"}}); err == nil {
		t.Fatal("without ldp.aide the timer would call nothing")
	}
}
