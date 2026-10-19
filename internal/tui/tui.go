// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Danang Galuh Tegar Prasetyo

// Package tui implements the simple one-question prompts with Charm's huh.
// They are what --plain uses, and the fallback when the terminal is not
// interactive or not UTF-8. The full-screen interface is internal/screen (the
// screens) and internal/app (the terminal loop).
//
// Every input shows its suggested value already filled in. The user presses
// Enter to accept it or edits it first.
package tui

import (
	"context"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/charmbracelet/huh"

	"github.com/danang-id/server-hardening/internal/control"
	"github.com/danang-id/server-hardening/internal/engine"
)

// ErrAborted is returned when the user presses Ctrl-C in a prompt.
var ErrAborted = huh.ErrUserAborted

// UI implements engine.UI.
type UI struct{ Out io.Writer }

// New returns a UI that writes to the standard output.
func New() *UI { return &UI{Out: os.Stdout} }

var _ engine.UI = (*UI)(nil)

func (u *UI) PickPreset(ctx context.Context) (engine.Preset, error) {
	var v int
	err := huh.NewSelect[int]().
		Title("How do you want to choose?").
		Options(
			huh.NewOption("Recommended defaults (you confirm the list)", int(engine.Recommended)),
			huh.NewOption("Customize (tick controls category by category)", int(engine.Customize)),
		).
		Value(&v).Run()
	return engine.Preset(v), err
}

func (u *UI) PickControls(ctx context.Context, cat control.Category, entries []engine.Entry, pre map[string]bool, na string) ([]string, error) {
	title := fmt.Sprintf("%02d %s", cat.Number(), cat.Name())
	if na != "" {
		fmt.Fprintf(u.Out, "%s: not applicable on this system. %s\n", title, na)
		return nil, nil
	}
	var opts []huh.Option[string]
	var sel []string
	for _, e := range entries {
		m := e.Control.Meta()
		if e.Disabled != "" {
			fmt.Fprintf(u.Out, "  - %s (%s)\n", m.Title, e.Disabled)
			continue
		}
		label := m.Title
		if len(m.Tags) > 0 {
			label += " [" + joinTags(m.Tags) + "]"
		}
		opts = append(opts, huh.NewOption(label, m.ID))
		if pre[m.ID] {
			sel = append(sel, m.ID)
		}
	}
	if len(opts) == 0 {
		return nil, nil
	}
	err := huh.NewMultiSelect[string]().Title(title).Options(opts...).Value(&sel).Run()
	return sel, err
}

func (u *UI) ConfirmSelection(ctx context.Context, titles []string, revert bool) (bool, error) {
	verb := "Apply"
	if revert {
		verb = "Revert"
	}
	ok := true
	err := huh.NewConfirm().
		Title(fmt.Sprintf("%s these %d controls?", verb, len(titles))).
		Description("- " + strings.Join(titles, "\n- ")).
		Affirmative("Yes").Negative("No").Value(&ok).Run()
	return ok, err
}

func (u *UI) ConfirmDependencies(ctx context.Context, extra []engine.Dep, revert bool) (bool, error) {
	var b strings.Builder
	for _, d := range extra {
		fmt.Fprintf(&b, "- %s (%s), because of: %s\n", d.Control.Meta().Title, d.Control.Meta().ID, strings.Join(d.RequiredBy, ", "))
	}
	title := "These controls are needed too. Add them?"
	no := "No, skip the controls that need them"
	if revert {
		title = "These applied controls depend on what you ticked. Revert them too?"
		no = "No, skip the controls that others depend on"
	}
	ok := true
	err := huh.NewConfirm().Title(title).Description(b.String()).
		Affirmative("Yes").Negative(no).Value(&ok).Run()
	return ok, err
}

func (u *UI) AskInputs(ctx context.Context, c control.Control, inputs []control.Input) (control.Values, error) {
	out := control.Values{}
	fmt.Fprintf(u.Out, "\n%s\n", c.Meta().Title)
	for _, in := range inputs {
		switch in.Kind {
		case control.Choice:
			v := in.Default
			opts := make([]huh.Option[string], 0, len(in.Options))
			for _, o := range in.Options {
				opts = append(opts, huh.NewOption(o.Label, o.Value))
			}
			if err := huh.NewSelect[string]().Title(in.Label).Description(in.Help).Options(opts...).Value(&v).Run(); err != nil {
				return nil, err
			}
			out[in.Key] = []string{v}
		case control.MultiChoice:
			v := append([]string(nil), in.DefaultMulti...)
			opts := make([]huh.Option[string], 0, len(in.Options))
			for _, o := range in.Options {
				opts = append(opts, huh.NewOption(o.Label, o.Value))
			}
			if err := huh.NewMultiSelect[string]().Title(in.Label).Description(in.Help).Options(opts...).Value(&v).Run(); err != nil {
				return nil, err
			}
			out[in.Key] = v
		case control.TextArea:
			v := in.Default
			f := huh.NewText().Title(in.Label).Description(in.Help).Value(&v).
				Validate(func(s string) error {
					if strings.TrimSpace(s) == "" && !in.Optional {
						return fmt.Errorf("a value is required")
					}
					if strings.TrimSpace(s) != "" && in.Validate != nil {
						return in.Validate(s)
					}
					return nil
				})
			if err := f.Run(); err != nil {
				return nil, err
			}
			out[in.Key] = []string{v}
		default:
			v := in.Default
			f := huh.NewInput().Title(in.Label).Description(in.Help).Value(&v)
			if in.Kind == control.Secret {
				f = f.EchoMode(huh.EchoModePassword)
			}
			f = f.Validate(func(s string) error {
				if s == "" && !in.Optional {
					return fmt.Errorf("a value is required")
				}
				if s != "" && in.Validate != nil {
					return in.Validate(s)
				}
				return nil
			})
			if in.Kind == control.Secret && in.Confirm {
				again := ""
				g := huh.NewInput().Title("Repeat to confirm").Value(&again).EchoMode(huh.EchoModePassword).
					Validate(func(s string) error {
						if s != v {
							return fmt.Errorf("the two entries differ")
						}
						return nil
					})
				if err := huh.NewForm(huh.NewGroup(f, g)).Run(); err != nil {
					return nil, err
				}
			} else if err := f.Run(); err != nil {
				return nil, err
			}
			out[in.Key] = []string{v}
		}
	}
	return out, nil
}

func (u *UI) ConfirmLockout(ctx context.Context, c control.Control, window time.Duration) (bool, error) {
	ok := false
	err := huh.NewConfirm().
		Title("Keep this session open. Open a NEW terminal and log in now.").
		Description(fmt.Sprintf("Could you log in from the new terminal after: %s?\nYou have %d minutes. If you answer No, or do not answer in time, the change is undone, even if this connection is lost.",
			c.Meta().Title, int(window.Minutes()))).
		Affirmative("Yes, it works").Negative("No").Value(&ok).Run()
	return ok, err
}

func (u *UI) WarnIrreversibleLockout(ctx context.Context, c control.Control) error {
	ok := false
	err := huh.NewConfirm().
		Title("This change cannot be undone and can cut your connection.").
		Description(c.Meta().Title + "\nKeep your provider's web console open before you continue.").
		Affirmative("Continue").Negative("Skip this one").Value(&ok).Run()
	if err == nil && !ok {
		return engine.ErrSkip
	}
	return err
}

func (u *UI) ShowSummary(s engine.Summary) {
	w := u.Out
	verb := "Applied"
	if s.Revert {
		verb = "Reverted"
	}
	if s.Dry {
		verb = "Would run (dry run, nothing changed)"
	}
	fmt.Fprintf(w, "\n%s: %d\n", verb, len(s.Done))
	for _, id := range s.Done {
		fmt.Fprintf(w, "  + %s\n", id)
	}
	if len(s.Added) > 0 {
		fmt.Fprintf(w, "Added as dependencies: %s\n", strings.Join(s.Added, ", "))
	}
	for _, k := range s.Skipped {
		fmt.Fprintf(w, "  - skipped %s: %s\n", k.ID, k.Reason)
	}
	for _, k := range s.Failed {
		fmt.Fprintf(w, "  ! failed %s: %s\n", k.ID, k.Reason)
	}
	for _, id := range s.Partial {
		fmt.Fprintf(w, "  ~ %s was reverted only in part (see its revert limits)\n", id)
	}
	if s.Reboot {
		fmt.Fprintln(w, "A reboot is needed to finish some changes.")
	}
}

func joinTags(t []control.Tag) string {
	s := make([]string, len(t))
	for i, x := range t {
		s[i] = string(x)
	}
	return strings.Join(s, ", ")
}

// Logger prints the live log lines.
type Logger struct{ W io.Writer }

func (l Logger) Infof(f string, a ...any) { fmt.Fprintf(l.W, f+"\n", a...) }
func (l Logger) Warnf(f string, a ...any) { fmt.Fprintf(l.W, "WARNING: "+f+"\n", a...) }
