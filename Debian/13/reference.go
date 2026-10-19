// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Danang Galuh Tegar Prasetyo

// Package debian13 carries the reference text of Debian 13, so the program can
// show the description of a control without the file being next to it.
package debian13

import _ "embed"

// Reference is the text of REFERENCES.md.
//
//go:embed REFERENCES.md
var Reference string
