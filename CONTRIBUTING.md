# Contributing

Thank you for helping. Server Hardening is free software, licensed under the GNU General Public License, version 3 or (at your option) any later version (`GPL-3.0-or-later`).

## Before you start

This is general-purpose hardening. Server roles (web, mail, database) and private networking such as Tailscale are out of scope, as the README says. The [roadmap](ROADMAP.md) lists what is wanted next. For a larger change, open an issue first so the idea can be discussed before you write the code.

## The license of your contribution

By contributing you agree that your contribution is licensed under `GPL-3.0-or-later`, and that you have the right to submit it. You confirm this by signing off every commit:

    git commit -s

That adds a `Signed-off-by: Your Name <you@example.com>` line and means you accept the Developer Certificate of Origin, version 1.1: <https://developercertificate.org>

Every source file starts with a license line and a copyright line. A new file gets the same two lines, with the year and your name:

    // SPDX-License-Identifier: GPL-3.0-or-later
    // Copyright (C) 2026 Your Name

Use `#` instead of `//` in shell, PowerShell and YAML files. Keep the lines that are already there when you edit a file.

## Checks

Run these before you open a pull request. They are the same checks that run on every push.

    gofmt -l .
    go vet ./...
    go test -race ./...
    shellcheck -s sh hardening.sh

`gofmt -l .` prints nothing when every file is formatted. The Go version is in `go.mod`.

## Conventions

- Range over a split with `strings.SplitSeq`.
- Give each piece its own `WriteString` call instead of joining strings with `+` inside one.
- Keep dependencies minimal. `DEPENDENCIES` lists the libraries and why each is there. The controls use only the Go standard library.
- A control's check reports `Applied` when applying it again would change nothing, and `Partial` when applying it again has work to do. `Pending` is for a control that is done and only waits, for a reboot or for the clock to synchronize. An audit stays `Partial` while it has findings, so that picking it again checks them again. A test breaks the control, applies it again and expects `Applied`.
- `hardening.sh` and `hardening.ps1` stay ASCII. `hardening.ps1` keeps Windows line endings, which `.gitattributes` sets.
