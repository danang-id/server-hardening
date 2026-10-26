// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Danang Galuh Tegar Prasetyo

package engine

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/danang-id/server-hardening/internal/control"
	"github.com/danang-id/server-hardening/internal/records"
	"github.com/danang-id/server-hardening/internal/registry"
)

// guide is a UI with the one-screen selection, a review and step progress.
type guide struct {
	script
	selects  []map[string]bool // the ticks Select started from, per pass
	choose   [][]string        // what Select returns, per pass
	reviews  []ReviewAction    // what Review returns, per pass
	asks     int
	given    [][]control.Input // the inputs of each AskInputs call
	backOn   int               // AskInputs returns ErrBack on this call (1-based), 0 never
	reviewed []Review
	events   []string
}

func (g *guide) Select(_ context.Context, m Menu, ticked map[string]bool) ([]string, error) {
	cp := map[string]bool{}
	for k, v := range ticked {
		cp[k] = v
	}
	g.selects = append(g.selects, cp)
	n := len(g.selects) - 1
	if n >= len(g.choose) {
		return nil, nil
	}
	return g.choose[n], nil
}

func (g *guide) AskInputs(ctx context.Context, c control.Control, in []control.Input) (control.Values, error) {
	g.asks++
	g.given = append(g.given, in)
	if g.asks == g.backOn {
		return nil, ErrBack
	}
	return g.script.AskInputs(ctx, c, in)
}

func (g *guide) Review(_ context.Context, r Review) (ReviewAction, error) {
	g.reviewed = append(g.reviewed, r)
	n := len(g.reviewed) - 1
	if n >= len(g.reviews) {
		return ReviewApply, nil
	}
	return g.reviews[n], nil
}

func (g *guide) Begin(items []control.Control, _ bool) {
	for _, c := range items {
		g.events = append(g.events, "plan "+c.Meta().ID)
	}
}
func (g *guide) Step(i int) { g.events = append(g.events, "step "+string(rune('0'+i))) }
func (g *guide) End(i int, o Outcome, note string) {
	g.events = append(g.events, "end "+string(rune('0'+i))+" "+map[Outcome]string{StepDone: "ok", StepFailed: "fail"}[o]+" "+note)
}

func TestGuidedFlowReviewEditAndProgress(t *testing.T) {
	var log []string
	sys := build(&log,
		meta("baseline.host", control.Baseline, 1, true, control.TagInput),
		meta("network.fw", control.Network, 1, true),
		meta("misc.extra", control.Misc, 1, false),
	)
	g := &guide{
		choose:  [][]string{{"baseline.host", "network.fw"}, {"network.fw"}},
		reviews: []ReviewAction{ReviewEdit, ReviewApply},
	}
	if err := Run(context.Background(), env(false), g, sys, false); err != nil {
		t.Fatal(err)
	}
	// First pass starts from the recommended ticks, the second from the choice.
	if len(g.selects) != 2 || !g.selects[0]["baseline.host"] || !g.selects[0]["network.fw"] || g.selects[0]["misc.extra"] {
		t.Fatalf("first pass ticks: %v", g.selects)
	}
	if len(g.selects[1]) != 2 || !g.selects[1]["baseline.host"] {
		t.Fatalf("second pass should start from the earlier choice: %v", g.selects[1])
	}
	if got := strings.Join(log, "|"); got != "apply network.fw " {
		t.Fatalf("only the second choice runs, got %q", got)
	}
	r := g.reviewed[0]
	if len(r.Items) != 2 || r.Items[0].Control.Meta().ID != "baseline.host" || len(r.Items[0].Values) != 1 || r.Items[0].Values[0] != "v: answer-baseline.host" {
		t.Fatalf("review: %+v", r.Items)
	}
	if got := strings.Join(g.events, ","); got != "plan network.fw,step 0,end 0 ok " {
		t.Fatalf("events: %q", got)
	}
	if !g.summary.Revert && len(g.summary.Done) != 1 {
		t.Fatalf("summary: %+v", g.summary)
	}
}

func TestGuidedBackFromInputsReturnsToTheSelection(t *testing.T) {
	var log []string
	sys := build(&log, meta("baseline.host", control.Baseline, 1, true, control.TagInput))
	g := &guide{choose: [][]string{{"baseline.host"}, {"baseline.host"}}, backOn: 1}
	if err := Run(context.Background(), env(false), g, sys, false); err != nil {
		t.Fatal(err)
	}
	if len(g.selects) != 2 || len(log) != 1 {
		t.Fatalf("selects %d log %v", len(g.selects), log)
	}
}

func TestGuidedEmptySelectionEnds(t *testing.T) {
	var log []string
	sys := build(&log, meta("baseline.host", control.Baseline, 1, true))
	g := &guide{choose: [][]string{{}}}
	if err := Run(context.Background(), env(false), g, sys, false); err != nil || len(log) != 0 || len(g.reviewed) != 0 {
		t.Fatalf("err %v log %v", err, log)
	}
}

func TestValueLines(t *testing.T) {
	in := []control.Input{
		{Key: "a", Label: "Host name (short)", Kind: control.Text},
		{Key: "b", Label: "Password", Kind: control.Secret},
		{Key: "c", Label: "Mode", Kind: control.Choice, Options: []control.Option{{Value: "x", Label: "Fancy"}}},
		{Key: "d", Label: "Ports", Kind: control.TextArea},
		{Key: "e", Label: "Open", Kind: control.MultiChoice, Options: []control.Option{{Value: "1", Label: "one"}}},
		{Key: "f", Label: "Keys", Kind: control.TextArea},
	}
	v := control.Values{"a": {"web"}, "b": {"s3cret"}, "c": {"x"}, "d": {"80\n\n443\n"}, "e": {"1", "2"}, "f": {""}}
	got := strings.Join(valueLines(in, v), "|")
	want := "Host name: web|Password: hidden|Mode: Fancy|Ports: 2 lines|Open: one, 2|Keys: none"
	if got != want {
		t.Fatalf("got %q want %q", got, want)
	}
	if strings.Contains(got, "s3cret") {
		t.Fatal("a secret must never be shown")
	}
}

func TestValueLinesLeavesOutQuestionsThatWereNotAsked(t *testing.T) {
	only := &control.OnlyIf{Key: "fw", Is: []string{"omz"}}
	in := []control.Input{
		{Key: "fw", Label: "Framework", Kind: control.Choice, Options: []control.Option{{Value: "none", Label: "None"}, {Value: "omz", Label: "Oh My Zsh"}}},
		{Key: "theme", Label: "Theme", OnlyIf: only},
	}
	if got := strings.Join(valueLines(in, control.Values{"fw": {"none"}}), "|"); got != "Framework: None" {
		t.Fatalf("got %q", got)
	}
	if got := strings.Join(valueLines(in, control.Values{"fw": {"omz"}, "theme": {"agnoster"}}), "|"); got != "Framework: Oh My Zsh|Theme: agnoster" {
		t.Fatalf("got %q", got)
	}
}

func TestGuidedDeclinedDependenciesLeaveNothingToRun(t *testing.T) {
	var log []string
	sys := build(&log,
		meta("baseline.host", control.Baseline, 1, false),
		control.Meta{ID: "network.fw", Category: control.Network, Number: 1, Title: "fw", Requires: []string{"baseline.host"}},
	)
	g := &guide{choose: [][]string{{"network.fw"}}} // deps declined: script.deps is false
	if err := Run(context.Background(), env(false), g, sys, false); err != nil {
		t.Fatal(err)
	}
	if len(log) != 0 || len(g.reviewed) != 0 || len(g.summary.Skipped) != 1 {
		t.Fatalf("log %v reviewed %d summary %+v", log, len(g.reviewed), g.summary)
	}
}

func TestEditSelectionKeepsTheAnswersAlreadyGiven(t *testing.T) {
	var log []string
	sys := build(&log,
		meta("baseline.host", control.Baseline, 1, true, control.TagInput),
		meta("network.fw", control.Network, 1, true),
	)
	g := &guide{
		choose:  [][]string{{"baseline.host", "network.fw"}, {"baseline.host", "network.fw"}},
		reviews: []ReviewAction{ReviewEdit, ReviewApply},
	}
	if err := Run(context.Background(), env(false), g, sys, false); err != nil {
		t.Fatal(err)
	}
	if g.asks != 1 {
		t.Fatalf("the question must be asked once, was asked %d times", g.asks)
	}
	if got := strings.Join(log, "|"); got != "apply baseline.host answer-baseline.host|apply network.fw " {
		t.Fatalf("the earlier answer is used: %q", got)
	}
	if v := g.reviewed[1].Items[0].Values; len(v) != 1 || v[0] != "v: answer-baseline.host" {
		t.Fatalf("second review shows the answer: %v", v)
	}
}

func TestEditSelectionAsksOnlyForControlsNotAnsweredYet(t *testing.T) {
	var log []string
	sys := build(&log,
		meta("baseline.host", control.Baseline, 1, true, control.TagInput),
		meta("baseline.other", control.Baseline, 2, true, control.TagInput),
	)
	g := &guide{
		choose:  [][]string{{"baseline.host"}, {"baseline.host", "baseline.other"}},
		reviews: []ReviewAction{ReviewEdit, ReviewApply},
	}
	if err := Run(context.Background(), env(false), g, sys, false); err != nil {
		t.Fatal(err)
	}
	if g.asks != 2 {
		t.Fatalf("host once and other once, got %d", g.asks)
	}
}

func TestChangeAnswersAsksAgainWithTheAnswersFilledIn(t *testing.T) {
	var log []string
	sys := build(&log, meta("baseline.host", control.Baseline, 1, true, control.TagInput))
	g := &guide{
		choose:  [][]string{{"baseline.host"}},
		reviews: []ReviewAction{ReviewAnswers, ReviewApply},
	}
	if err := Run(context.Background(), env(false), g, sys, false); err != nil {
		t.Fatal(err)
	}
	if len(g.selects) != 1 {
		t.Fatalf("the selection is not asked again, was asked %d times", len(g.selects))
	}
	if g.asks != 2 {
		t.Fatalf("asks %d", g.asks)
	}
	if d := g.given[0][0].Default; d != "d" {
		t.Fatalf("first time the usual suggestion, got %q", d)
	}
	if d := g.given[1][0].Default; d != "answer-baseline.host" {
		t.Fatalf("second time the earlier answer, got %q", d)
	}
}

func TestAppliedAnswersAreTheDefaultsOnTheNextRun(t *testing.T) {
	dir := t.TempDir()
	e := env(false)
	e.Rec = records.New(dir)
	var log []string
	sys := build(&log, meta("baseline.host", control.Baseline, 1, true, control.TagInput))

	g := &guide{choose: [][]string{{"baseline.host"}}}
	if err := Run(context.Background(), e, g, sys, false); err != nil {
		t.Fatal(err)
	}
	if g.given[0][0].Default != "d" {
		t.Fatalf("first run starts from the suggestion: %q", g.given[0][0].Default)
	}

	// A later run, a new process: only the records are left.
	e2 := env(false)
	e2.Rec = records.New(dir)
	g2 := &guide{choose: [][]string{{"baseline.host"}}}
	if err := Run(context.Background(), e2, g2, build(&log, meta("baseline.host", control.Baseline, 1, true, control.TagInput)), false); err != nil {
		t.Fatal(err)
	}
	if got := g2.given[0][0].Default; got != "answer-baseline.host" {
		t.Fatalf("second run starts from the earlier answer, got %q", got)
	}
}

func TestAnswersOfControlsThatDidNotRunAreNotKept(t *testing.T) {
	dir := t.TempDir()
	e := env(false)
	e.Rec = records.New(dir)
	var log []string
	sys := &registry.System{ID: "t"}
	sys.Add(&rec{Base: control.Base{M: meta("baseline.host", control.Baseline, 1, true, control.TagInput)}, log: &log, applyErr: errors.New("boom")})
	g := &guide{choose: [][]string{{"baseline.host"}}}
	if err := Run(context.Background(), e, g, sys, false); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := e.Rec.Get(answersID("baseline.host"), "v"); ok {
		t.Fatal("a failed control must not keep its answers")
	}
}

func TestDryRunKeepsNoAnswers(t *testing.T) {
	e := env(true)
	e.Rec = records.New(t.TempDir())
	saveAnswers(e, "x", []control.Input{{Key: "v"}}, control.Values{"v": {"1"}})
	if _, ok, _ := e.Rec.Get(answersID("x"), "v"); ok {
		t.Fatal("dry run saved an answer")
	}
}

func TestSecretsAreNeverKept(t *testing.T) {
	e := env(false)
	e.Rec = records.New(t.TempDir())
	in := []control.Input{{Key: "pw", Kind: control.Secret}, {Key: "user"}}
	saveAnswers(e, "x", in, control.Values{"pw": {"hunter2"}, "user": {"dan"}})
	if _, ok, _ := e.Rec.Get(answersID("x"), "pw"); ok {
		t.Fatal("secret was saved")
	}
	got := loadAnswers(e, "x", in)
	if len(got) != 1 || got["user"][0] != "dan" {
		t.Fatalf("loaded %v", got)
	}
}

func TestWithAnswersIgnoresWhatNoLongerFits(t *testing.T) {
	opts := []control.Option{{Value: "a"}, {Value: "b"}}
	in := []control.Input{
		{Key: "c", Kind: control.Choice, Options: opts, Default: "a"},
		{Key: "m", Kind: control.MultiChoice, Options: opts, DefaultMulti: []string{"a"}},
		{Key: "t", Default: "x"},
	}
	out := withAnswers(in, control.Values{"c": {"gone"}, "m": {"b", "gone"}, "t": {"y"}})
	if out[0].Default != "a" {
		t.Fatalf("choice: %q", out[0].Default)
	}
	if len(out[1].DefaultMulti) != 1 || out[1].DefaultMulti[0] != "b" {
		t.Fatalf("multi: %v", out[1].DefaultMulti)
	}
	if out[2].Default != "y" {
		t.Fatalf("text: %q", out[2].Default)
	}
	if in[2].Default != "x" {
		t.Fatal("the original inputs must not change")
	}
}
