// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Danang Galuh Tegar Prasetyo

package controls

import (
	"context"
	"strings"
	"testing"

	"github.com/danang-id/server-hardening/internal/control"
)

func pwqControl() *passwordQuality {
	return &passwordQuality{control.Base{M: control.Meta{ID: pwqID}}}
}

func TestPasswordQualityRoundTrip(t *testing.T) {
	ctx := context.Background()
	env, run := accountsEnv(t)
	c := pwqControl()
	if state(t, c, env) != control.NotApplied {
		t.Fatal("should start not applied")
	}

	must(t, c.Apply(ctx, env, control.Values{"minlen": {"16"}, "minclass": {"4"}}))
	got := read(t, env, pwqFile)
	for _, want := range []string{pwqMarker, "minlen = 16", "minclass = 4", "dictcheck = 1", "usercheck = 1", "enforce_for_root"} {
		if !strings.Contains(got, want) {
			t.Errorf("drop-in lacks %q:\n%s", want, got)
		}
	}
	if !run.did("install libpam-pwquality") || !run.did("pam-auth-update --package --enable pwquality") {
		t.Fatalf("calls: %v", run.calls)
	}
	if state(t, c, env) != control.Applied {
		t.Fatal("should be applied")
	}

	must(t, c.Revert(ctx, env))
	if read(t, env, pwqFile) != "<missing>" {
		t.Fatal("drop-in should be gone")
	}
	if !run.did("pam-auth-update --package --remove pwquality") {
		t.Fatal("the module was not in the stack before, so it must come out")
	}
	if state(t, c, env) != control.NotApplied {
		t.Fatal("should be not applied after revert")
	}
	if env.Rec.Has(pwqID) {
		t.Fatal("record should be gone")
	}
}

func TestPasswordQualityLeavesModuleThatWasThereBefore(t *testing.T) {
	ctx := context.Background()
	env, run := accountsEnv(t)
	appendLine(t, env, "/etc/pam.d/common-password", "password\trequisite\tpam_pwquality.so retry=3")
	c := pwqControl()
	// An older drop-in of this tool must come back on revert.
	writeFile(t, env, pwqFile, "# somebody's own rules\nminlen = 9\n")

	must(t, c.Apply(ctx, env, control.Values{"minlen": {"14"}, "minclass": {"3"}}))
	// Applying again must not turn "was there before" into "added by this tool".
	must(t, c.Apply(ctx, env, control.Values{"minlen": {"15"}, "minclass": {"3"}}))
	must(t, c.Revert(ctx, env))

	if run.did("--remove pwquality") {
		t.Fatal("a module that was there before must stay in the stack")
	}
	if got := read(t, env, pwqFile); got != "# somebody's own rules\nminlen = 9\n" {
		t.Fatalf("previous file not restored: %q", got)
	}
}

func TestPasswordQualityReapplyDoesNotForgetWhatWasThere(t *testing.T) {
	ctx := context.Background()
	env, run := accountsEnv(t)
	c := pwqControl()
	must(t, c.Apply(ctx, env, control.Values{"minlen": {"14"}, "minclass": {"3"}}))
	must(t, c.Apply(ctx, env, control.Values{"minlen": {"20"}, "minclass": {"3"}}))
	if !strings.Contains(read(t, env, pwqFile), "minlen = 20") {
		t.Fatal("second run should update the value")
	}
	must(t, c.Revert(ctx, env))
	if !run.did("--remove pwquality") {
		t.Fatal("added by us on the first run, so it must be removed")
	}
}

func TestPasswordQualityCheckStates(t *testing.T) {
	env, _ := accountsEnv(t)
	c := pwqControl()
	// Only the PAM line (the package's own default): not this control's work.
	appendLine(t, env, "/etc/pam.d/common-password", "password\trequisite\tpam_pwquality.so retry=3")
	if state(t, c, env) != control.NotApplied {
		t.Fatal("PAM line alone is not applied")
	}
	// A drop-in of this tool, but with the PAM line commented out.
	writeFile(t, env, "/etc/pam.d/common-password", "# password requisite pam_pwquality.so\n")
	writeFile(t, env, pwqFile, pwqContent(14, 3))
	if state(t, c, env) != control.Partial {
		t.Fatal("drop-in without the module should be partial")
	}
}

func TestPasswordQualityRejectsBadInput(t *testing.T) {
	ctx := context.Background()
	env, run := accountsEnv(t)
	c := pwqControl()
	for _, v := range []control.Values{
		{"minlen": {"7"}, "minclass": {"3"}},
		{"minlen": {"129"}, "minclass": {"3"}},
		{"minlen": {"abc"}, "minclass": {"3"}},
		{"minlen": {"14"}, "minclass": {"0"}},
		{"minlen": {"14"}, "minclass": {"5"}},
		{"minlen": {""}, "minclass": {"3"}},
	} {
		if err := c.Apply(ctx, env, v); err == nil {
			t.Errorf("%v should be refused", v)
		}
	}
	if run.did("apt-get") || read(t, env, pwqFile) != "<missing>" {
		t.Fatal("a refused request must change nothing")
	}
}

func TestPasswordQualityFailedPAMUpdateIsReported(t *testing.T) {
	env, run := accountsEnv(t)
	run.fail["pam-auth-update --package --enable pwquality"] = true
	if err := pwqControl().Apply(context.Background(), env, control.Values{"minlen": {"14"}, "minclass": {"3"}}); err == nil {
		t.Fatal("a failing pam-auth-update must fail the control")
	}
}

func TestPasswordQualityRevertWithoutRecordLeavesThingsAlone(t *testing.T) {
	env, run := accountsEnv(t)
	writeFile(t, env, pwqFile, "minlen = 9\n")
	must(t, pwqControl().Revert(context.Background(), env))
	if read(t, env, pwqFile) != "minlen = 9\n" || run.did("pam-auth-update") {
		t.Fatal("no record means no change")
	}
}
