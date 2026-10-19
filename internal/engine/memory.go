// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Danang Galuh Tegar Prasetyo

package engine

import (
	"encoding/json"
	"slices"

	"github.com/danang-id/server-hardening/internal/control"
)

// What the user answered is kept in the records, per control, so that the next
// run starts from the same answers. Secrets are never kept: a password typed
// into a form lives in memory for this run and nowhere else.

// answersID is the record that holds the answers to a control's questions.
func answersID(id string) string { return "answers." + id }

// loadAnswers reads the answers saved for a control. It returns nil when there
// are none, or when the records cannot be read: a lost memory only means the
// questions start from their usual suggestions.
func loadAnswers(env *control.Env, id string, inputs []control.Input) control.Values {
	if env.Rec == nil {
		return nil
	}
	var v control.Values
	for _, in := range inputs {
		if in.Kind == control.Secret {
			continue
		}
		raw, ok, err := env.Rec.Get(answersID(id), in.Key)
		if err != nil || !ok {
			continue
		}
		var l []string
		if json.Unmarshal([]byte(raw), &l) != nil {
			continue
		}
		if v == nil {
			v = control.Values{}
		}
		v[in.Key] = l
	}
	return v
}

// saveAnswers keeps the answers to a control that was applied, except secrets.
func saveAnswers(env *control.Env, id string, inputs []control.Input, v control.Values) {
	if env.Rec == nil || env.DryRun {
		return
	}
	for _, in := range inputs {
		l, ok := v[in.Key]
		if in.Kind == control.Secret || !ok {
			continue
		}
		b, err := json.Marshal(l)
		if err != nil {
			continue
		}
		if err := env.Rec.Put(answersID(id), in.Key, string(b)); err != nil {
			env.Log.Warnf("%s: could not keep your answer for next time: %v", id, err)
			return
		}
	}
}

// withAnswers returns the inputs with their suggestions replaced by earlier
// answers. An answer that no longer fits, such as a choice that is gone, is
// ignored.
func withAnswers(inputs []control.Input, v control.Values) []control.Input {
	if len(v) == 0 {
		return inputs
	}
	out := make([]control.Input, len(inputs))
	copy(out, inputs)
	for i, in := range out {
		l, ok := v[in.Key]
		if !ok {
			continue
		}
		has := func(val string) bool {
			return slices.ContainsFunc(in.Options, func(o control.Option) bool { return o.Value == val })
		}
		switch in.Kind {
		case control.Choice:
			if len(l) == 1 && has(l[0]) {
				out[i].Default = l[0]
			}
		case control.MultiChoice:
			var keep []string
			for _, x := range l {
				if has(x) {
					keep = append(keep, x)
				}
			}
			out[i].DefaultMulti = keep
		default: // Text, TextArea, Secret
			if len(l) > 0 {
				out[i].Default = l[0]
			}
		}
	}
	return out
}
