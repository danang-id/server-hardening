// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Danang Galuh Tegar Prasetyo

// Package records keeps what a control needs to revert itself.
//
// On Linux the records live in /var/lib/server-hardening, writable by root
// only. They are deliberately not kept in the user's data folder, because the
// tool runs as root and must be able to trust them.
package records

import (
	"encoding/json"
	"errors"
	"io/fs"
	"net/url"
	"os"
	"path/filepath"

	"github.com/danang-id/server-hardening/internal/files"
)

// Store is a file-based implementation of control.Records.
type Store struct{ Dir string }

// New returns a store that keeps its files in dir.
func New(dir string) *Store { return &Store{Dir: dir} }

type doc struct {
	Values map[string]string `json:"values"`
}

func (s *Store) docPath(id string) string { return filepath.Join(s.Dir, "state", id+".json") }
func (s *Store) backupPath(id, path string) string {
	return filepath.Join(s.Dir, "backups", id, url.PathEscape(path))
}

func (s *Store) load(id string) (doc, error) {
	d := doc{Values: map[string]string{}}
	b, err := os.ReadFile(s.docPath(id))
	if errors.Is(err, fs.ErrNotExist) {
		return d, nil
	}
	if err != nil {
		return d, err
	}
	if err := json.Unmarshal(b, &d); err != nil {
		return d, err
	}
	if d.Values == nil {
		d.Values = map[string]string{}
	}
	return d, nil
}

func (s *Store) Has(id string) bool { return files.Exists(s.docPath(id)) }

func (s *Store) Get(id, key string) (string, bool, error) {
	d, err := s.load(id)
	if err != nil {
		return "", false, err
	}
	v, ok := d.Values[key]
	return v, ok, nil
}

func (s *Store) Put(id, key, value string) error {
	if err := os.MkdirAll(filepath.Join(s.Dir, "state"), 0o700); err != nil {
		return err
	}
	d, err := s.load(id)
	if err != nil {
		return err
	}
	d.Values[key] = value
	b, err := json.MarshalIndent(d, "", "  ")
	if err != nil {
		return err
	}
	return files.WriteAtomic(s.docPath(id), b, 0o600)
}

// Delete removes the state and all backups of a control.
func (s *Store) Delete(id string) error {
	if err := os.Remove(s.docPath(id)); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return os.RemoveAll(filepath.Join(s.Dir, "backups", id))
}

const missingMark = ".missing"

// Backup copies the file into the records. A file that does not exist is
// recorded as missing, so a revert removes what the control created.
func (s *Store) Backup(id, path string) error {
	dst := s.backupPath(id, path)
	if files.Exists(dst) || files.Exists(dst+missingMark) {
		return nil // keep the first backup: it holds the original state
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
		return err
	}
	b, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return files.WriteAtomic(dst+missingMark, nil, 0o600)
	}
	if err != nil {
		return err
	}
	perm := fs.FileMode(0o600)
	if st, err := os.Stat(path); err == nil {
		perm = st.Mode().Perm()
	}
	return files.WriteAtomic(dst, b, perm)
}

func (s *Store) Restore(id, path string) (bool, error) {
	src := s.backupPath(id, path)
	if files.Exists(src + missingMark) {
		if err := os.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return true, err
		}
		return true, nil
	}
	b, err := os.ReadFile(src)
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	perm := fs.FileMode(0o644)
	if st, err := os.Stat(src); err == nil {
		perm = st.Mode().Perm()
	}
	return true, files.WriteAtomic(path, b, perm)
}
