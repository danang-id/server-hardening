// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Danang Galuh Tegar Prasetyo

package engine

import (
	"fmt"
	"strings"

	"github.com/danang-id/server-hardening/internal/control"
)

// buildReview prepares the review screen from the plan and the answers.
func buildReview(plan *Plan, revert bool, asked map[string][]control.Input, answers map[string]control.Values) Review {
	added := map[string]bool{}
	for _, id := range plan.Added {
		added[id] = true
	}
	r := Review{Revert: revert}
	for _, c := range plan.Items {
		id := c.Meta().ID
		r.Items = append(r.Items, ReviewItem{
			Control: c,
			Added:   added[id],
			Values:  valueLines(asked[id], answers[id]),
		})
	}
	return r
}

// valueLines shows the answers to a control's inputs, one line each. A secret
// is never shown.
func valueLines(inputs []control.Input, v control.Values) []string {
	var out []string
	for _, in := range inputs {
		if !in.ShownFor(v) {
			continue
		}
		label := strings.TrimSpace(in.Label)
		if i := strings.IndexAny(label, "(:"); i > 0 {
			label = strings.TrimSpace(label[:i])
		}
		var val string
		switch in.Kind {
		case control.Secret:
			if v.String(in.Key) == "" {
				val = "none"
			} else {
				val = "hidden"
			}
		case control.Choice:
			val = optionLabel(in, v.String(in.Key))
		case control.MultiChoice:
			var l []string
			for _, x := range v.List(in.Key) {
				l = append(l, optionLabel(in, x))
			}
			if len(l) == 0 {
				val = "none"
			} else {
				val = strings.Join(l, ", ")
			}
		case control.TextArea:
			var lines []string
			for ln := range strings.SplitSeq(v.String(in.Key), "\n") {
				if strings.TrimSpace(ln) != "" {
					lines = append(lines, strings.TrimSpace(ln))
				}
			}
			switch len(lines) {
			case 0:
				val = "none"
			case 1:
				val = lines[0]
			default:
				val = fmt.Sprintf("%d lines", len(lines))
			}
		default:
			val = v.String(in.Key)
			if val == "" {
				val = "none"
			}
		}
		out = append(out, label+": "+val)
	}
	return out
}

func optionLabel(in control.Input, value string) string {
	for _, o := range in.Options {
		if o.Value == value {
			return o.Label
		}
	}
	return value
}
