// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Danang Galuh Tegar Prasetyo

package engine

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/danang-id/server-hardening/internal/control"
	"github.com/danang-id/server-hardening/internal/registry"
)

// Run drives one complete run against sys. It reads the state of every
// control, lets the user choose controls and answer their questions, shows the
// review, and then applies the chosen controls, or reverts them when revert is
// true. With env.DryRun it presents the plan and changes nothing.
func Run(ctx context.Context, env *control.Env, ui UI, sys *registry.System, revert bool) error {
	start := time.Now()
	state, idle := checkAll(ctx, env, sys)

	plan, answers, asked, err := negotiate(ctx, env, ui, sys, state, idle, revert)
	if err != nil || plan == nil {
		return err
	}

	sum := Summary{Revert: revert, Added: plan.Added, Skipped: plan.Skipped, Dry: env.DryRun}
	if env.DryRun || len(plan.Items) == 0 {
		for _, c := range plan.Items {
			sum.Done = append(sum.Done, c.Meta().ID)
		}
		ui.ShowSummary(sum)
		return nil
	}

	r := &runner{
		env: env, ui: ui, sys: sys, plan: plan, revert: revert,
		answers: answers, asked: asked,
		blocked: map[string]bool{}, sum: sum,
	}
	r.prog, _ = ui.(Progress)
	if r.prog != nil {
		r.prog.Begin(plan.Items, revert)
	}
	for i, c := range plan.Items {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := r.step(ctx, i, c); err != nil {
			return err
		}
	}
	r.sum.Elapsed = time.Since(start).Round(time.Second).String()
	ui.ShowSummary(r.sum)
	return nil
}

// checkAll reads the state of every control once, without changing anything.
// An action is a job rather than a setting, so it is always reported as not
// applied; idle holds the reason for each action that has nothing to do.
func checkAll(ctx context.Context, env *control.Env, sys *registry.System) (state map[string]control.State, idle map[string]string) {
	state = map[string]control.State{}
	idle = map[string]string{}
	for _, c := range sys.Controls() {
		m := c.Meta()
		if m.Action {
			state[m.ID] = control.NotApplied
			if i, ok := c.(control.Idler); ok {
				if why := i.Idle(ctx, env); why != "" {
					idle[m.ID] = why
				}
			}
			continue
		}
		st, err := c.Check(ctx, env)
		if err != nil {
			env.Log.Warnf("%s: check failed: %v", m.ID, err)
		}
		state[m.ID] = st
	}
	return state, idle
}

// counts says whether a control in state st counts as applied. A control that
// is applied in part has work left in an apply, so it does not count there, but
// it counts in a revert, which undoes whatever is in place.
func counts(st control.State, revert bool) bool {
	switch st {
	case control.Applied, control.Pending:
		return true
	case control.Partial:
		return revert
	}
	return false
}

// negotiate repeats selection, questions and review until the user accepts the
// review. A UI that has no review accepts at once. It returns a nil plan when
// the user chose nothing. The returned inputs and answers belong to the
// accepted pass.
func negotiate(ctx context.Context, env *control.Env, ui UI, sys *registry.System, state map[string]control.State, idle map[string]string, revert bool) (*Plan, map[string]control.Values, map[string][]control.Input, error) {
	applied := func(id string) bool { return counts(state[id], revert) }
	consent := func(extra []Dep) (bool, error) { return ui.ConfirmDependencies(ctx, extra, revert) }

	var (
		plan    *Plan
		answers map[string]control.Values
		asked   map[string][]control.Input
		ticked  map[string]bool
		// session holds what the user has answered in this run, secrets
		// included. It outlives a return to the selection, so no answer is lost.
		session = map[string]control.Values{}
		// again is set when the user asked to change the answers: the
		// selection and the plan stay, and only the questions come back.
		again bool
	)
	for {
		if !again {
			selected, err := choose(ctx, ui, sys, state, idle, revert, ticked)
			if err != nil || len(selected) == 0 {
				return nil, nil, nil, err
			}
			ticked = map[string]bool{}
			for _, id := range selected {
				ticked[id] = true
			}
			build := BuildApply
			if revert {
				build = BuildRevert
			}
			if plan, err = build(sys, selected, applied, consent); err != nil {
				return nil, nil, nil, err
			}
			if env.DryRun || len(plan.Items) == 0 {
				return plan, answers, asked, nil
			}
		}

		var (
			back bool
			err  error
		)
		answers, asked, back, err = askInputs(ctx, env, ui, plan, session, again, revert)
		if err != nil {
			return nil, nil, nil, err
		}
		again = false
		if back {
			continue
		}

		g, ok := ui.(Guided)
		if !ok {
			return plan, answers, asked, nil
		}
		act, err := g.Review(ctx, buildReview(plan, revert, asked, answers))
		if err != nil {
			return nil, nil, nil, err
		}
		if act == ReviewApply {
			return plan, answers, asked, nil
		}
		again = act == ReviewAnswers
	}
}

// askInputs asks the questions of every control in the plan before anything
// changes. Nothing is asked when reverting. A control that was answered
// earlier in this run is not asked again, unless the user asked to change the
// answers, in which case its answers are filled in. Otherwise the suggestions
// are what was answered when the control was last applied. back reports that
// the user returned to the selection.
func askInputs(ctx context.Context, env *control.Env, ui UI, plan *Plan, session map[string]control.Values, again, revert bool) (answers map[string]control.Values, asked map[string][]control.Input, back bool, err error) {
	answers = map[string]control.Values{}
	asked = map[string][]control.Input{}
	if revert {
		return answers, asked, false, nil
	}
	for _, c := range plan.Items {
		id := c.Meta().ID
		in, err := c.Inputs(ctx, env)
		if err != nil {
			return nil, nil, false, fmt.Errorf("%s: inputs: %w", id, err)
		}
		if len(in) == 0 {
			continue
		}
		asked[id] = in
		if v, ok := session[id]; ok && !again {
			answers[id] = v
			continue
		}
		prev := session[id]
		if prev == nil {
			prev = loadAnswers(env, id, in)
		}
		v, err := ui.AskInputs(ctx, c, withAnswers(in, prev))
		if errors.Is(err, ErrBack) {
			return answers, asked, true, nil
		}
		if err != nil {
			return nil, nil, false, err
		}
		session[id] = v
		answers[id] = v
	}
	return answers, asked, false, nil
}

// runner executes the steps of an accepted plan and collects the summary.
type runner struct {
	env    *control.Env
	ui     UI
	sys    *registry.System
	plan   *Plan
	revert bool
	prog   Progress // nil when the UI shows no progress

	answers map[string]control.Values
	asked   map[string][]control.Input

	// blocked holds the controls that did not take effect: declined, failed
	// or undone. A control that needs one of them must not run on top of
	// nothing.
	blocked map[string]bool
	sum     Summary
}

// end reports the outcome of step i to the progress display.
func (r *runner) end(i int, o Outcome, note string) {
	if r.prog != nil {
		r.prog.End(i, o, note)
	}
}

// skip records that step i was not run.
func (r *runner) skip(i int, m control.Meta, reason string) {
	r.blocked[m.ID] = true
	r.sum.Skipped = append(r.sum.Skipped, Skipped{m.ID, reason})
	r.env.Log.Warnf("%s: skipped: %s", m.ID, reason)
	r.end(i, StepSkipped, reason)
}

// fail records that step i ran but did not take effect.
func (r *runner) fail(i int, m control.Meta, reason string) {
	r.blocked[m.ID] = true
	r.sum.Failed = append(r.sum.Failed, Skipped{m.ID, reason})
	r.end(i, StepFailed, reason)
}

// step applies or reverts one control. A control that fails or is declined is
// recorded in the summary and does not stop the run; only an error from the
// UI does.
func (r *runner) step(ctx context.Context, i int, c control.Control) error {
	env, m := r.env, c.Meta()
	if r.prog != nil {
		r.prog.Step(i)
	}
	env.Log.Infof("Step %d / %d: %s", i+1, len(r.plan.Items), m.Title)

	if !r.revert {
		if dep, ok := blockedNeed(r.sys, m, r.blocked); ok {
			r.skip(i, m, "needs "+dep+", which did not run")
			return nil
		}
	}

	// A lockout control that can be undone is guarded by a timer that is armed
	// before the change, so a dropped connection cannot leave it in place.
	guarded := !r.revert && m.Has(control.TagLockout) && m.Revertible()
	var disarm func(context.Context) error
	if guarded {
		disarm = armGuard(ctx, env, m.ID)
	}

	var err error
	if r.revert {
		err = c.Revert(ctx, env)
	} else {
		if m.Has(control.TagLockout) && !m.Revertible() {
			if werr := r.ui.WarnIrreversibleLockout(ctx, c); werr != nil {
				if errors.Is(werr, ErrSkip) {
					r.skip(i, m, "you chose not to continue")
					return nil
				}
				return werr
			}
		}
		err = c.Apply(ctx, env, r.answers[m.ID])
	}
	if err != nil {
		if disarm != nil {
			_ = disarm(ctx)
		}
		env.Log.Warnf("%s failed: %v", m.ID, err)
		r.fail(i, m, err.Error())
		return nil
	}
	if guarded {
		undone, err := lockoutCheck(ctx, env, r.ui, c, disarm)
		if err != nil {
			return err
		}
		if undone != "" {
			r.fail(i, m, undone)
			return nil
		}
	}
	if f, ok := c.(control.Finalizer); ok && !r.revert {
		if err := f.Finalize(ctx, env); err != nil {
			env.Log.Warnf("%s: last step failed: %v", m.ID, err)
		}
	}
	r.sum.Done = append(r.sum.Done, m.ID)
	if !r.revert {
		saveAnswers(env, m.ID, r.asked[m.ID], r.answers[m.ID])
	}
	r.end(i, StepDone, "")
	if m.Has(control.TagReboot) && !r.revert {
		r.sum.Reboot = true
	}
	if r.revert && m.RevertLimits != "" {
		r.sum.Partial = append(r.sum.Partial, m.ID)
	}
	return nil
}

// blockedNeed returns the title of a control that m requires and that did not
// take effect in this run.
func blockedNeed(sys *registry.System, m control.Meta, blocked map[string]bool) (string, bool) {
	for _, id := range m.Requires {
		if blocked[id] {
			if r, ok := sys.Get(id); ok {
				return r.Meta().Title, true
			}
			return id, true
		}
	}
	return "", false
}

// LockoutWindow is how long the user has to confirm a lockout control. After
// that, the change is undone automatically.
const LockoutWindow = 10 * time.Minute

// armGuard starts the automatic undo of a lockout control. It returns nil when
// that is not possible, and then only this session can undo the change.
func armGuard(ctx context.Context, env *control.Env, id string) func(context.Context) error {
	if env.Guard == nil {
		env.Log.Warnf("%s: no automatic undo is available on this system. Keep your provider's console open", id)
		return nil
	}
	disarm, err := env.Guard.Arm(ctx, id, LockoutWindow)
	if err != nil {
		env.Log.Warnf("%s: could not arm the automatic undo (%v). Keep your provider's console open", id, err)
		return nil
	}
	env.Log.Infof("%s: if you do not confirm within %d minutes, the change is undone automatically", id, int(LockoutWindow.Minutes()))
	return disarm
}

// lockoutCheck pauses after a lockout control until the user has logged in
// from a new session. It returns a reason when the change did not stay: the
// user did not confirm, or the timer undid it first.
//
// If the prompt ends without an answer (the user pressed Ctrl-C, or the
// connection is gone), the timer is left armed on purpose.
func lockoutCheck(ctx context.Context, env *control.Env, ui UI, c control.Control, disarm func(context.Context) error) (string, error) {
	m := c.Meta()
	ok, err := ui.ConfirmLockout(ctx, c, LockoutWindow)
	if err != nil {
		if disarm != nil {
			env.Log.Warnf("%s: not confirmed, so it is undone automatically within %d minutes", m.ID, int(LockoutWindow.Minutes()))
		}
		return "", err
	}
	timerFired := false
	if disarm != nil {
		if derr := disarm(ctx); derr != nil {
			// The timer has already run, or its unit is gone. The state of the control
			// tells which.
			if st, _ := c.Check(ctx, env); st == control.NotApplied {
				timerFired = true
			} else {
				env.Log.Warnf("%s: could not stop the automatic undo: %v", m.ID, derr)
			}
		}
	}
	if timerFired {
		env.Log.Warnf("%s: the automatic undo already ran", m.ID)
		return "the automatic undo ran before you confirmed", nil
	}
	if ok {
		return "", nil
	}
	env.Log.Warnf("%s: not confirmed, reverting", m.ID)
	if err := c.Revert(ctx, env); err != nil && !errors.Is(err, control.ErrNoRevert) {
		return "", fmt.Errorf("%s: revert after failed lockout check: %w", m.ID, err)
	}
	return "not confirmed, so it was undone", nil
}

// choose runs the selection screens and returns the chosen IDs. prev holds the
// ticks of an earlier pass, or nil on the first.
func choose(ctx context.Context, ui UI, sys *registry.System, state map[string]control.State, idle map[string]string, revert bool, prev map[string]bool) ([]string, error) {
	var groups []Group
	pre := map[string]bool{}
	for _, cat := range control.Categories() {
		g := Group{Category: cat, NA: sys.NotApplicable[cat]}
		for _, c := range sys.Controls() {
			m := c.Meta()
			if m.Category != cat {
				continue
			}
			st := state[m.ID]
			e := Entry{Control: c, State: st, Doc: sys.Doc(m.ID)}
			switch {
			case revert && st == control.NotApplied:
				continue // the revert list shows only applied controls
			case revert && !m.Revertible():
				e.Disabled = revertDisabledReason(m)
			case !revert && st == control.Applied:
				e.Disabled = "already applied"
			case !revert && st == control.Pending:
				e.Disabled = "applied, waiting to take effect"
			case !revert && idle[m.ID] != "":
				e.Disabled = idle[m.ID]
			}
			if !revert && m.Default && e.Disabled == "" {
				pre[m.ID] = true
			}
			g.Entries = append(g.Entries, e)
		}
		if len(g.Entries) == 0 && g.NA == "" {
			continue
		}
		groups = append(groups, g)
	}

	// A UI with a one-screen selection and a review takes over the whole dialog.
	if g, ok := ui.(Guided); ok {
		start := pre
		if prev != nil {
			start = prev
		}
		return g.Select(ctx, Menu{Revert: revert, Groups: groups}, start)
	}

	preset := Customize
	if !revert {
		p, err := ui.PickPreset(ctx)
		if err != nil {
			return nil, err
		}
		preset = p
	}
	var chosen, titles []string
	for _, g := range groups {
		if !revert && preset == Recommended {
			for _, e := range g.Entries {
				if pre[e.Control.Meta().ID] {
					chosen = append(chosen, e.Control.Meta().ID)
					titles = append(titles, e.Control.Meta().Title)
				}
			}
			continue
		}
		ids, err := ui.PickControls(ctx, g.Category, g.Entries, pre, g.NA)
		if err != nil {
			return nil, err
		}
		for _, id := range ids {
			c, _ := sys.Get(id)
			chosen = append(chosen, id)
			titles = append(titles, c.Meta().Title)
		}
	}
	if len(chosen) == 0 {
		return nil, nil
	}
	ok, err := ui.ConfirmSelection(ctx, titles, revert)
	if err != nil || !ok {
		return nil, err
	}
	return chosen, nil
}

func revertDisabledReason(m control.Meta) string {
	if m.Has(control.TagReadonly) {
		return "read-only: nothing to revert"
	}
	return "cannot be reverted: " + m.NoRevertReason
}
