// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Danang Galuh Tegar Prasetyo

package engine

import (
	"context"
	"errors"
	"time"

	"github.com/danang-id/server-hardening/internal/control"
	"github.com/danang-id/server-hardening/internal/registry"
)

// ErrBack is returned by a screen when the user asks to go back to the
// selection. The run starts the selection again, with the same ticks.
var ErrBack = errors.New("back to the selection")

// ErrSkip is returned by WarnIrreversibleLockout when the user does not want
// that one control after the warning. The run skips it, and the controls that
// need it, and carries on with the rest. Any other error ends the run.
var ErrSkip = errors.New("skip this control")

// Preset is the first choice in an apply run.
type Preset int

const (
	Recommended Preset = iota // tick the defaults
	Customize                 // tick category by category
)

// Entry is one row in the tick list.
type Entry struct {
	Control control.Control
	State   control.State
	// Disabled is a written reason when the row cannot be ticked (for
	// example an irreversible control in the revert list). Empty if tickable.
	Disabled string
	Doc      registry.Doc // short description, for the detail pane
}

// Summary is shown at the end of a run.
type Summary struct {
	Revert  bool
	Done    []string
	Added   []string
	Skipped []Skipped
	Failed  []Skipped
	Partial []string // reverted only in part
	Reboot  bool
	Dry     bool
	Elapsed string
}

// UI is everything the engine needs from the screen. internal/tui implements
// it with huh. Tests use a fake.
type UI interface {
	PickPreset(ctx context.Context) (Preset, error)
	// PickControls asks which controls of one category to tick. na is the
	// written reason when the whole category is N/A on this system.
	PickControls(ctx context.Context, cat control.Category, entries []Entry, preselected map[string]bool, na string) ([]string, error)
	ConfirmSelection(ctx context.Context, titles []string, revert bool) (bool, error)
	// ConfirmDependencies shows all extra controls at once. In a revert, the
	// extras are dependents and RequiredBy lists what they depend on.
	ConfirmDependencies(ctx context.Context, extra []Dep, revert bool) (bool, error)
	AskInputs(ctx context.Context, c control.Control, inputs []control.Input) (control.Values, error)
	// ConfirmLockout asks the user to open a new session and confirm it works
	// while the current session stays open. window is the time left before the
	// change is undone automatically.
	ConfirmLockout(ctx context.Context, c control.Control, window time.Duration) (bool, error)
	// WarnIrreversibleLockout warns about a lockout control that cannot be
	// undone, and asks the user to keep the provider console open. It returns
	// ErrSkip when the user declines this control: the rest of the run goes on.
	WarnIrreversibleLockout(ctx context.Context, c control.Control) error
	ShowSummary(s Summary)
}

// Group is one category in the selection screen.
type Group struct {
	Category control.Category
	NA       string // reason when the whole category is N/A on this system
	Entries  []Entry
}

// Menu is everything the one-screen selection needs.
type Menu struct {
	Revert bool
	Groups []Group
}

// ReviewItem is one control in the review, in run order.
type ReviewItem struct {
	Control control.Control
	Added   bool     // added as a dependency (apply) or dependent (revert)
	Values  []string // one line per answered input, ready to show
}

// Review is the last screen before anything changes.
type Review struct {
	Revert bool
	Items  []ReviewItem
}

// ReviewAction is the user's answer to the review.
type ReviewAction int

const (
	ReviewApply   ReviewAction = iota // go ahead
	ReviewEdit                        // back to the selection
	ReviewAnswers                     // ask the questions again, with the answers so far filled in
)

// Guided is implemented by a UI that shows the whole selection on one screen
// and a review before the run. When the UI has it, the engine uses it instead
// of PickPreset, PickControls and ConfirmSelection.
type Guided interface {
	// Select returns the IDs the user ticked. ticked holds the ticks to start
	// from: the recommended ones, or the earlier choice after an edit.
	Select(ctx context.Context, m Menu, ticked map[string]bool) ([]string, error)
	Review(ctx context.Context, r Review) (ReviewAction, error)
}

// Outcome is how one step of a run ended.
type Outcome int

// The outcomes of a step.
const (
	StepDone Outcome = iota
	StepFailed
	StepSkipped // not run, because the user declined it or something it needs did not run
)

// Progress is implemented by a UI that shows the steps of a run as they go.
type Progress interface {
	// Begin is called once, before the first step, with the steps in order.
	Begin(items []control.Control, revert bool)
	// Step is called when step i (from 0) starts.
	Step(i int)
	// End is called when step i is over. note says why it failed.
	End(i int, o Outcome, note string)
}
