// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Danang Galuh Tegar Prasetyo

// Package tests holds the repository-wide checks that run in GitHub Actions
// on every push and pull request, and again before a release is built.
package tests

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/danang-id/server-hardening/internal/control"
	"github.com/danang-id/server-hardening/internal/registry"

	// Every system is linked in so it can be checked.
	_ "github.com/danang-id/server-hardening/AlmaLinux/10/Controls"
	_ "github.com/danang-id/server-hardening/Debian/13/Controls"
)

const root = ".."

func TestEverySystemFollowsTheRules(t *testing.T) {
	for _, s := range registry.Systems() {
		for _, err := range registry.Validate(s) {
			t.Errorf("%s: %v", s.ID, err)
		}
		for _, err := range registry.ValidateCoverage(s) {
			t.Errorf("%s: %v", s.ID, err)
		}
	}
}

var fileName = regexp.MustCompile(`^(\d{2})(\d{2})_([a-z-]+)\.([a-z0-9-]+)\.go$`)

// Each control file must be named after its own metadata.
func TestFilenamesMatchMetadata(t *testing.T) {
	for _, s := range registry.Systems() {
		entries, err := os.ReadDir(filepath.Join(root, filepath.FromSlash(s.Dir)))
		if err != nil {
			t.Fatalf("%s: %v", s.ID, err)
		}
		seen := map[string]bool{}
		for _, e := range entries {
			n := e.Name()
			if !strings.HasSuffix(n, ".go") || strings.HasSuffix(n, "_test.go") || n == "system.go" {
				continue
			}
			// Shared helpers do not start with a number. A file that does is a
			// control and must follow the rule below.
			if n[0] < '0' || n[0] > '9' {
				continue
			}
			m := fileName.FindStringSubmatch(n)
			if m == nil {
				t.Errorf("%s/%s: name must be <CC><NN>_<category>.<control-name>.go", s.Dir, n)
				continue
			}
			cat, _ := strconv.Atoi(m[1])
			num, _ := strconv.Atoi(m[2])
			id := m[3] + "." + m[4]
			c, ok := s.Get(id)
			if !ok {
				t.Errorf("%s/%s: no control %q is registered", s.Dir, n, id)
				continue
			}
			seen[id] = true
			if got := c.Meta(); int(got.Category) != cat || got.Number != num {
				t.Errorf("%s/%s: metadata says category %02d number %02d", s.Dir, n, got.Category, got.Number)
			}
		}
		for _, c := range s.Controls() {
			if !seen[c.Meta().ID] {
				t.Errorf("%s: control %s has no file in %s", s.ID, c.Meta().ID, s.Dir)
			}
		}
	}
}

type indexRow struct {
	no       string
	deflt    string
	weight   int
	requires []string
	tags     []string
}

// readIndex reads the control index table of a REFERENCES.md. It accepts both
// Windows and Unix line endings.
func readIndex(t *testing.T, path string) map[string]indexRow {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	rows := map[string]indexRow{}
	for line := range strings.SplitSeq(strings.ReplaceAll(string(b), "\r\n", "\n"), "\n") {
		if !regexp.MustCompile(`^\| \d{4} \| `).MatchString(line) {
			continue
		}
		c := strings.Split(strings.Trim(strings.TrimSpace(line), "|"), "|")
		for i := range c {
			c[i] = strings.TrimSpace(c[i])
		}
		if len(c) != 7 {
			t.Fatalf("%s: index row has %d cells: %s", path, len(c), line)
		}
		w := control.DefaultWeight
		if c[4] != "" {
			w, _ = strconv.Atoi(c[4])
		}
		r := indexRow{no: c[0], deflt: c[3], weight: w}
		for _, m := range regexp.MustCompile("`([^`]+)`").FindAllStringSubmatch(c[5], -1) {
			r.requires = append(r.requires, m[1])
		}
		for x := range strings.SplitSeq(c[6], ",") {
			if x = strings.TrimSpace(x); x != "" {
				r.tags = append(r.tags, x)
			}
		}
		rows[strings.Trim(c[1], "`")] = r
	}
	return rows
}

// The index in REFERENCES.md and the Go metadata must agree, and every
// indexed control must be implemented.
func TestReferencesIndexMatchesMetadata(t *testing.T) {
	for _, s := range registry.Systems() {
		ref := filepath.Join(root, filepath.Dir(filepath.FromSlash(s.Dir)), "REFERENCES.md")
		rows := readIndex(t, ref)
		for _, c := range s.Controls() {
			m := c.Meta()
			r, ok := rows[m.ID]
			if !ok {
				t.Errorf("%s: %s is not in the REFERENCES.md index", s.ID, m.ID)
				continue
			}
			if want := m.Category.Number()*100 + m.Number; r.no != strconv.Itoa(want) && r.no != pad4(want) {
				t.Errorf("%s: number %s, code says %s", m.ID, r.no, pad4(want))
			}
			if (r.deflt == "Yes") != m.Default {
				t.Errorf("%s: default is %s in REFERENCES.md", m.ID, r.deflt)
			}
			if r.weight != m.EffectiveWeight() {
				t.Errorf("%s: weight is %d in REFERENCES.md, %d in code", m.ID, r.weight, m.EffectiveWeight())
			}
			if !sameSet(r.requires, m.Requires) {
				t.Errorf("%s: requires %v in REFERENCES.md, %v in code", m.ID, r.requires, m.Requires)
			}
			var tags []string
			for _, tg := range m.Tags {
				tags = append(tags, string(tg))
			}
			if !sameSet(r.tags, tags) {
				t.Errorf("%s: tags %v in REFERENCES.md, %v in code", m.ID, r.tags, tags)
			}
		}
		for id := range rows {
			if _, ok := s.Get(id); !ok {
				t.Errorf("%s: %s is in REFERENCES.md but not implemented", s.ID, id)
			}
		}
	}
}

func pad4(n int) string { return fmt.Sprintf("%04d", n) }

func sameSet(a, b []string) bool {
	a, b = append([]string(nil), a...), append([]string(nil), b...)
	sort.Strings(a)
	sort.Strings(b)
	return strings.Join(a, ",") == strings.Join(b, ",")
}
