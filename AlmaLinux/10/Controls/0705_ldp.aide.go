// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Danang Galuh Tegar Prasetyo

package controls

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/danang-id/server-hardening/internal/control"
	"github.com/danang-id/server-hardening/internal/dnf"
	"github.com/danang-id/server-hardening/internal/files"
)

const (
	aideID = "ldp.aide"
	// AIDE reads one file, /etc/aide.conf, and has no drop-in folder. Our file
	// includes it and adds the exclusions, and the run script uses ours.
	aideConf    = "/etc/aide/server-hardening.conf"
	aideBaseCfg = "/etc/aide.conf"
	aideDB      = "/var/lib/aide/aide.db.gz"
	aideDBNew   = "/var/lib/aide/aide.db.new.gz"
	aideRunPath = libexecDir + "/aide-run"
)

type aide struct{ control.Base }

func init() {
	System.Add(&aide{control.Base{M: control.Meta{
		ID:           aideID,
		Category:     control.LDP,
		Number:       5,
		Title:        "Build the file integrity baseline (AIDE)",
		Default:      true,
		Weight:       930,
		Tags:         []control.Tag{control.TagInput},
		RevertLimits: "Removes the baseline database. The AIDE package stays installed.",
	}}})
}

// Paths whose content changes all the time and tells nothing.
var aideAlwaysExcluded = []string{
	"/proc", "/sys", "/dev", "/run", "/tmp", "/var/tmp", "/var/log", "/var/cache", "/var/spool",
	"/var/lib/aide", "/var/lib/dnf", "/var/lib/rpm", "/usr/lib/sysimage/rpm", "/var/lib/NetworkManager",
	"/var/lib/systemd", "/var/lib/fail2ban", "/var/lib/server-hardening", "/var/lib/chrony",
}

var aidePath = regexp.MustCompile(`^/[A-Za-z0-9/._-]*$`)

func aideExtraPaths(s string) ([]string, error) {
	var out []string
	for _, p := range listItems(s) {
		p = strings.TrimRight(p, "/")
		if p == "" || !aidePath.MatchString(p) || strings.Contains(p, "..") {
			return nil, fmt.Errorf("%q is not an absolute path (letters, digits and / . _ - only)", p)
		}
		out = append(out, p)
	}
	return out, nil
}

// aideConfContent is the configuration the run script uses. It is the
// distribution's own file plus the exclusions. AIDE picks the rule of the
// deepest matching path, so an exclusion works wherever it stands in the file.
func aideConfContent(extra []string) string {
	var b strings.Builder
	b.WriteString(managed(aideID))
	b.WriteString("\n")
	b.WriteString("# The distribution's rules and database locations.\n")
	b.WriteString("@@include ")
	b.WriteString(aideBaseCfg)
	b.WriteString("\n\n")
	b.WriteString("# Paths that change all the time and are left out of the baseline.\n")
	for _, p := range append(append([]string(nil), aideAlwaysExcluded...), extra...) {
		b.WriteString("!")
		b.WriteString(regexp.QuoteMeta(p))
		b.WriteString("\n")
	}
	return b.String()
}

// aideRunScript is the one program that the dnf hook and the timer call.
const aideRunScript = `#!/bin/sh
# Managed by github.com/danang-id/server-hardening (ldp.aide)
#
# aide-run check   Compare the system with the baseline. Exits 1 on differences.
# aide-run update  Accept the current state as the new baseline. Always exits 0.
#
# The result goes to the system log. If the notify helper exists (misc.notify),
# it is called as: notify EVENT SEVERITY TITLE MESSAGE

: "${AIDE_CONF:=/etc/aide/server-hardening.conf}"
: "${AIDE_DB:=/var/lib/aide/aide.db.gz}"
: "${AIDE_DB_NEW:=/var/lib/aide/aide.db.new.gz}"
: "${AIDE_NOTIFY:=/usr/local/libexec/server-hardening/notify}"
: "${AIDE_LOCK:=/run/server-hardening-aide.lock}"
TAG=server-hardening-aide
mode=${1:-check}

say() { logger -t "$TAG" -p "$1" -- "$2"; }
# tell EVENT TITLE FILE: the first lines of FILE are the details.
tell() {
    if [ -x "$AIDE_NOTIFY" ]; then "$AIDE_NOTIFY" "$1" warning "$2" "$(head -n 20 "$3")" || true; fi
}

# One run at a time: a dnf run and the timer can overlap.
exec 9>"$AIDE_LOCK"
flock 9

case "$mode" in
check)
    if [ ! -f "$AIDE_DB" ]; then
        say user.warning "no baseline database at $AIDE_DB, nothing to compare"
        exit 1
    fi
    out=$(mktemp) || exit 0
    aide --config "$AIDE_CONF" --check >"$out" 2>&1
    rc=$?
    if [ "$rc" -eq 0 ]; then
        say user.info "no differences from the baseline"
        rm -f "$out"
        exit 0
    fi
    if [ "$rc" -ge 14 ]; then
        say user.err "AIDE failed with exit code $rc"
    else
        say authpriv.warning "differences from the baseline (exit code $rc)"
        tell ldp.aide-scheduled-check.differences "AIDE found differences on $(hostname)" "$out"
    fi
    logger -t "$TAG" -p user.notice -f "$out"
    rm -f "$out"
    exit 1
    ;;
update)
    [ -f "$AIDE_DB" ] || exit 0
    aide --config "$AIDE_CONF" --update >/dev/null 2>&1
    rc=$?
    # 1 to 7 only say that there were differences, which is why we update.
    if [ "$rc" -ge 14 ]; then
        say user.err "AIDE could not update the baseline (exit code $rc)"
        exit 0
    fi
    if [ -f "$AIDE_DB_NEW" ]; then
        mv -f "$AIDE_DB_NEW" "$AIDE_DB"
        say user.info "baseline updated"
    fi
    exit 0
    ;;
*)
    echo "usage: $0 check|update" >&2
    exit 2
    ;;
esac
`

func (a *aide) Inputs(context.Context, *control.Env) ([]control.Input, error) {
	return []control.Input{{
		Key: "exclude", Label: "More paths to leave out of the baseline", Optional: true,
		Help: "Absolute paths, separated by spaces. These are already left out: " + strings.Join(aideAlwaysExcluded, " "),
		Validate: func(s string) error {
			_, err := aideExtraPaths(s)
			return err
		},
	}}, nil
}

func (a *aide) Check(_ context.Context, env *control.Env) (control.State, error) {
	if !hasMarker(env, aideConf, aideID) {
		return control.NotApplied, nil
	}
	if !files.Exists(env.Path(aideDB)) || !files.Exists(env.Path(aideRunPath)) {
		return control.Partial, nil
	}
	return control.Applied, nil
}

func (a *aide) Apply(ctx context.Context, env *control.Env, in control.Values) error {
	extra, err := aideExtraPaths(in.String("exclude"))
	if err != nil {
		return err
	}
	if err := dnf.Install(ctx, env, "aide"); err != nil {
		return err
	}
	if err := putFile(env, aideID, aideConf, aideConfContent(extra), 0o644); err != nil {
		return err
	}
	if err := putFile(env, aideID, aideRunPath, aideRunScript, 0o755); err != nil {
		return err
	}
	undo := func() {
		_ = restoreFile(env, aideID, aideConf)
		_ = restoreFile(env, aideID, aideRunPath)
		_ = os.Remove(env.Path(aideDBNew))
	}
	// A database that was there before is kept in the records.
	if err := env.Rec.Backup(aideID, env.Path(aideDB)); err != nil {
		undo()
		return err
	}
	env.Log.Infof("building the baseline. This reads the whole filesystem and takes a few minutes")
	if out, err := env.Run.Run(ctx, "aide", "--init", "--config", aideConf); err != nil {
		undo()
		return fmt.Errorf("aide --init failed: %w: %s", err, strings.TrimSpace(string(out)))
	}
	// --init writes the database under the "new" name. It becomes the baseline.
	if err := os.Rename(env.Path(aideDBNew), env.Path(aideDB)); err != nil {
		undo()
		return fmt.Errorf("aide --init finished, but there is no database at %s", aideDBNew)
	}
	b, err := os.ReadFile(env.Path(aideDB))
	if err != nil {
		undo()
		return err
	}
	sum := sha256.Sum256(b)
	if err := env.Rec.Put(aideID, "sha256", hex.EncodeToString(sum[:])); err != nil {
		return err
	}
	env.Log.Infof("baseline: %s, SHA-256 %s", aideDB, hex.EncodeToString(sum[:]))
	env.Log.Warnf("keep a copy of the database and this checksum off the server: someone with root on the server can rebuild the baseline to hide a change")
	return nil
}

func (a *aide) Revert(ctx context.Context, env *control.Env) error {
	if !env.Rec.Has(aideID) {
		env.Log.Warnf("%s: no record, leaving AIDE alone", aideID)
		return nil
	}
	for _, f := range []string{aideConf, aideRunPath, aideDB} {
		if err := restoreFile(env, aideID, f); err != nil {
			return err
		}
	}
	_ = os.Remove(env.Path(aideDBNew))
	return env.Rec.Delete(aideID)
}
