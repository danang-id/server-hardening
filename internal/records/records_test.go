// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Danang Galuh Tegar Prasetyo

package records

import (
	"os"
	"path/filepath"
	"testing"
)

func TestValuesAndBackups(t *testing.T) {
	dir := t.TempDir()
	s := New(filepath.Join(dir, "rec"))
	if s.Has("x.y") {
		t.Fatal("empty store has a record")
	}
	if err := s.Put("x.y", "k", "v"); err != nil {
		t.Fatal(err)
	}
	if v, ok, _ := s.Get("x.y", "k"); !ok || v != "v" || !s.Has("x.y") {
		t.Fatalf("got %q %v", v, ok)
	}

	f := filepath.Join(dir, "conf")
	os.WriteFile(f, []byte("old"), 0o640)
	missing := filepath.Join(dir, "created")
	if err := s.Backup("x.y", f); err != nil {
		t.Fatal(err)
	}
	if err := s.Backup("x.y", missing); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(f, []byte("new"), 0o640)
	os.WriteFile(missing, []byte("made by the control"), 0o640)
	// A second backup must not replace the original state.
	if err := s.Backup("x.y", f); err != nil {
		t.Fatal(err)
	}

	if ok, err := s.Restore("x.y", f); !ok || err != nil {
		t.Fatal(ok, err)
	}
	if b, _ := os.ReadFile(f); string(b) != "old" {
		t.Fatalf("got %q", b)
	}
	if ok, _ := s.Restore("x.y", missing); !ok {
		t.Fatal("no backup for missing file")
	}
	if _, err := os.Stat(missing); err == nil {
		t.Fatal("file the control created should be removed")
	}
	if ok, _ := s.Restore("x.y", filepath.Join(dir, "unknown")); ok {
		t.Fatal("unknown file reported as restored")
	}
	if err := s.Delete("x.y"); err != nil || s.Has("x.y") {
		t.Fatal("delete failed")
	}
}
