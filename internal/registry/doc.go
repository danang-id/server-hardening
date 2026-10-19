// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Danang Galuh Tegar Prasetyo

package registry

import (
	"regexp"
	"strings"
	"sync"
)

// Doc is the short description of a control, taken from its entry in the
// system's REFERENCES.md.
type Doc struct {
	What string // "What it does."
	Why  string // "Why."
}

var (
	docSync sync.Mutex
	docs    = map[*System]map[string]Doc{}
)

// Doc returns the description of a control. It is empty when the reference
// has no entry for it.
func (s *System) Doc(id string) Doc {
	docSync.Lock()
	defer docSync.Unlock()
	m, ok := docs[s]
	if !ok {
		m = ParseReference(s.Reference)
		docs[s] = m
	}
	return m[id]
}

var (
	mdLink = regexp.MustCompile(`\[([^\]]*)\]\([^)]*\)`)
	mdMark = regexp.MustCompile("[`*]")
)

// ParseReference reads the "What it does." and "Why." paragraphs of every
// control entry in a REFERENCES.md. An entry starts with "### <id>".
func ParseReference(md string) map[string]Doc {
	out := map[string]Doc{}
	id := ""
	for line := range strings.SplitSeq(strings.ReplaceAll(md, "\r\n", "\n"), "\n") {
		switch {
		case strings.HasPrefix(line, "### "):
			id = strings.TrimSpace(strings.TrimPrefix(line, "### "))
		case id == "":
		case strings.HasPrefix(line, "**What it does.**"):
			d := out[id]
			d.What = plain(strings.TrimPrefix(line, "**What it does.**"))
			out[id] = d
		case strings.HasPrefix(line, "**Why.**"):
			d := out[id]
			d.Why = plain(strings.TrimPrefix(line, "**Why.**"))
			out[id] = d
		}
	}
	return out
}

// plain removes the Markdown marks from one paragraph.
func plain(s string) string {
	s = mdLink.ReplaceAllString(s, "$1")
	s = mdMark.ReplaceAllString(s, "")
	return strings.Join(strings.Fields(s), " ")
}
