// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Danang Galuh Tegar Prasetyo

// Package control defines what a hardening control is: its metadata and the
// operations every control must implement (check, apply and revert).
package control

import (
	"context"
	"errors"
	"path/filepath"
	"time"
)

// Category is a fixed area of hardening. Numbers are the same for every
// system and are never renumbered. New categories are appended.
type Category int

// The hardening categories, in number order. The README describes each one.
const (
	Baseline Category = iota + 1
	AAA
	RemoteAccess
	Network
	ASR
	MAC
	LDP
	SystemKernel
	Filesystem
	Misc
)

var categories = map[Category][2]string{
	Baseline:     {"baseline", "Operating System Baseline"},
	AAA:          {"aaa", "Accounts, Authentication and Authorization (AAA)"},
	RemoteAccess: {"remote-access", "Remote Access"},
	Network:      {"network", "Network Exposure"},
	ASR:          {"asr", "Attack-Surface Reduction (ASR)"},
	MAC:          {"mac", "Mandatory Access Control (MAC)"},
	LDP:          {"ldp", "Logging, Detection and Prevention"},
	SystemKernel: {"system-kernel", "System and Kernel"},
	Filesystem:   {"filesystem", "Filesystem and Storage"},
	Misc:         {"misc", "Miscellaneous"},
}

// Categories returns every category in number order.
func Categories() []Category {
	out := make([]Category, 0, len(categories))
	for c := Baseline; c <= Misc; c++ {
		out = append(out, c)
	}
	return out
}

// Number returns the category number.
func (c Category) Number() int { return int(c) }

// Slug returns the short name that starts every control ID of the category.
func (c Category) Slug() string { return categories[c][0] }

// Name returns the full title of the category.
func (c Category) Name() string { return categories[c][1] }

// Tag is a metadata label. See the README for the meaning of each one.
type Tag string

// The tags a control can carry. The README explains each one.
const (
	TagLockout      Tag = "lockout"
	TagReboot       Tag = "reboot"
	TagInput        Tag = "input"
	TagCompat       Tag = "compat"
	TagExternal     Tag = "external"
	TagReadonly     Tag = "readonly"
	TagIrreversible Tag = "irreversible"
)

// DefaultWeight is the weight of a control that does not set one.
const DefaultWeight = 500

// Meta describes a control. It must match the control's entry in the
// system's REFERENCES.md (a test checks this).
type Meta struct {
	ID       string   // "<category-slug>.<name>", for example "remote-access.sftp"
	Category Category // must match the ID prefix
	Number   int      // control number inside the category, from 1
	Title    string   // short description, as in the REFERENCES.md index
	Default  bool     // ticked in "recommended defaults" mode (only a suggestion)
	// Weight is the universal run priority, 1 to 999. Zero means DefaultWeight.
	Weight   int
	Requires []string // hard prerequisites, by control ID
	Tags     []Tag
	// Action marks a control that is a job, not a setting: it runs every time
	// it is chosen. The tool never checks it and never reports it as already
	// applied, because "nothing left to do" says nothing about what chosen
	// today would do (new updates, newly installed packages).
	Action bool
	// NoRevertReason is required for controls tagged irreversible.
	NoRevertReason string
	// RevertLimits describes what a revert cannot restore, if anything.
	RevertLimits string
}

func (m Meta) EffectiveWeight() int {
	if m.Weight == 0 {
		return DefaultWeight
	}
	return m.Weight
}

func (m Meta) Has(t Tag) bool {
	for _, x := range m.Tags {
		if x == t {
			return true
		}
	}
	return false
}

// Revertible reports whether the revert list may offer this control.
func (m Meta) Revertible() bool {
	return !m.Has(TagIrreversible) && !m.Has(TagReadonly)
}

// State is the result of a control's check.
type State int

// The states a check can report.
//
// Partial means that only part of the control's effect is in place, so that
// applying it again has work to do. Pending means that Apply has nothing left
// to do and only time is missing: a reboot, or a clock that is still
// synchronizing. For every other control a check reports Applied when Apply
// would change nothing.
const (
	NotApplied State = iota
	Applied
	Partial
	Pending
)

// InputKind selects how an input is asked.
type InputKind int

// The kinds of input. Secret hides what is typed. Choice picks one option and
// MultiChoice picks several.
const (
	Text InputKind = iota
	Secret
	Choice
	MultiChoice
	TextArea // several lines of text; the answer keeps its line breaks
)

// Option is one entry of a Choice or MultiChoice input.
type Option struct {
	Value string
	Label string
	Help  string
}

// Input is one question a control asks. Default is a suggestion that the
// user can change. Prompts show it and Enter accepts it.
type Input struct {
	Key          string
	Label        string
	Help         string
	Kind         InputKind
	Default      string   // Text, Secret, Choice
	DefaultMulti []string // MultiChoice
	Options      []Option // Choice, MultiChoice
	Optional     bool     // an empty answer is allowed
	Confirm      bool     // Secret only: ask twice, both answers must match
	Validate     func(string) error
}

// Values holds the answers to a control's inputs.
type Values map[string][]string

func (v Values) String(key string) string {
	if l := v[key]; len(l) > 0 {
		return l[0]
	}
	return ""
}
func (v Values) List(key string) []string { return v[key] }

// ErrNoRevert is returned by Revert of a control that has nothing to revert
// or must not be reverted automatically (tags irreversible and readonly).
var ErrNoRevert = errors.New("this control has no revert")

// Control is one atomic, self-checking, revertible hardening unit.
// Revert is part of the interface on purpose: a control without it does not
// compile.
type Control interface {
	Meta() Meta
	// Inputs returns the questions to ask, with suggestions detected from the
	// running system. It returns nil when the control asks nothing.
	Inputs(ctx context.Context, env *Env) ([]Input, error)
	Check(ctx context.Context, env *Env) (State, error)
	Apply(ctx context.Context, env *Env, in Values) error
	Revert(ctx context.Context, env *Env) error
}

// Idler is implemented by an action (see Meta.Action) that can tell, without
// changing anything, that choosing it now would do nothing: for example, none
// of the packages it removes is installed. The tool then shows the action as
// not available, with the reason, instead of offering a choice that does
// nothing. It never says "already applied": an action is a job, not a setting.
type Idler interface {
	// Idle returns a few words, such as "nothing to remove", when there is
	// nothing to do, and "" when the action has work.
	Idle(ctx context.Context, env *Env) string
}

// Finalizer is implemented by a control that has a last step to take once the
// user has confirmed that the change works. For example, remote-access.ssh-port
// listens on the old and the new port until then. Finalize runs after the
// lockout confirmation and never when the change was undone.
type Finalizer interface {
	Finalize(ctx context.Context, env *Env) error
}

// Guard arms an automatic undo for a risky change. If the user does not
// confirm in time, the control is reverted even when the tool itself is gone,
// for example because the connection dropped.
type Guard interface {
	// Arm schedules the revert of control id after window. The returned
	// disarm function cancels it. Disarm returns an error when the timer has
	// already fired.
	Arm(ctx context.Context, id string, window time.Duration) (disarm func(ctx context.Context) error, err error)
}

// Base supplies Meta and a default Inputs. Controls embed it.
type Base struct{ M Meta }

func (b Base) Meta() Meta                                  { return b.M }
func (Base) Inputs(context.Context, *Env) ([]Input, error) { return nil, nil }

// Logger receives the live log lines of a run.
type Logger interface {
	Infof(format string, a ...any)
	Warnf(format string, a ...any)
}

// Runner runs external commands. Controls use it instead of os/exec so they
// can be tested.
type Runner interface {
	Run(ctx context.Context, name string, args ...string) ([]byte, error)
	// RunStdin is Run with data on the standard input. It is how passwords
	// reach a command without appearing in its arguments or in any log.
	RunStdin(ctx context.Context, stdin string, name string, args ...string) ([]byte, error)
}

// Records stores what a control needs to revert itself: previous values and
// backups of files it replaced. Keys are per control ID.
type Records interface {
	Has(id string) bool
	Get(id, key string) (string, bool, error)
	Put(id, key, value string) error
	Delete(id string) error
	// Backup copies the file at path into the records for id. A missing file
	// is recorded as "did not exist".
	Backup(id, path string) error
	// Restore puts the backed-up file back (or removes the file if it did not
	// exist). It returns false when there is no backup.
	Restore(id, path string) (bool, error)
}

// Env is everything a control may touch.
type Env struct {
	Root   string // "/" in production; a temp directory in tests
	Run    Runner
	Rec    Records
	Log    Logger
	Guard  Guard // nil when no automatic undo is available
	DryRun bool

	// Answered holds the answers given so far in this run, by control ID. The
	// engine fills it while it asks the questions, which all come before any
	// control runs, so that a question can offer what an earlier control is about
	// to create. It is nil at any other time.
	Answered map[string]Values
}

// Path maps an absolute system path below Root.
func (e *Env) Path(abs string) string {
	return filepath.Join(e.Root, filepath.FromSlash(abs))
}
