// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Danang Galuh Tegar Prasetyo

package controls

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/danang-id/server-hardening/internal/control"
)

func aideControl() *aide { return &aide{control.Base{M: control.Meta{ID: aideID}}} }

// aideEnv makes aideinit write a database file.
func aideEnv(t *testing.T) (*control.Env, *fakeRunner, *sysSim) {
	env, run, s := sysEnv(t)
	prev := run.hook
	run.hook = func(f *fakeRunner, cmd string) {
		prev(f, cmd)
		if cmd == "aideinit -y -f" && !f.fail[cmd] {
			writeFile(t, env, aideDB, "database v1")
		}
	}
	return env, run, s
}

func TestAIDEBuildsBaseline(t *testing.T) {
	ctx := context.Background()
	env, run, s := aideEnv(t)
	c := aideControl()
	if state(t, c, env) != control.NotApplied {
		t.Fatal("should start not applied")
	}
	must(t, c.Apply(ctx, env, control.Values{"exclude": {"/srv/cache /data/tmp.d"}}))
	if !s.installed["aide"] || !s.installed["aide-common"] {
		t.Fatal("aide must be installed")
	}
	ex := read(t, env, aideExclude)
	wantContains(t, ex, managed(aideID), "!/proc", "!/var/log", "!/var/lib/aide", "!/srv/cache", `!/data/tmp\.d`)
	script := read(t, env, aideRunPath)
	wantContains(t, script, "aide-run check", "flock")
	if fi, _ := os.Stat(env.Path(aideRunPath)); fi.Mode().Perm() != 0o755 {
		t.Fatalf("the script must be executable: %v", fi.Mode())
	}
	i, j := strings.Index(strings.Join(run.calls, "\n"), "update-aide.conf"), strings.Index(strings.Join(run.calls, "\n"), "aideinit")
	if i < 0 || j < 0 || i > j {
		t.Fatalf("update-aide.conf must run before aideinit: %v", run.calls)
	}
	sum := sha256.Sum256([]byte("database v1"))
	if got, _, _ := env.Rec.Get(aideID, "sha256"); got != hex.EncodeToString(sum[:]) {
		t.Fatalf("checksum: %q", got)
	}
	if state(t, c, env) != control.Applied {
		t.Fatal("should be applied")
	}

	must(t, c.Revert(ctx, env))
	noFile(t, env, aideExclude)
	noFile(t, env, aideRunPath)
	noFile(t, env, aideDB)
	if env.Rec.Has(aideID) {
		t.Fatal("record should be gone")
	}
}

func TestAIDEKeepsEarlierDatabaseForRevert(t *testing.T) {
	env, _, _ := aideEnv(t)
	writeFile(t, env, aideDB, "database from before")
	c := aideControl()
	must(t, c.Apply(context.Background(), env, control.Values{}))
	if read(t, env, aideDB) != "database v1" {
		t.Fatal("the new baseline should be in place")
	}
	must(t, c.Revert(context.Background(), env))
	if read(t, env, aideDB) != "database from before" {
		t.Fatalf("the earlier database must come back: %q", read(t, env, aideDB))
	}
}

func TestAIDEFailureLeavesNothingBehind(t *testing.T) {
	env, run, _ := aideEnv(t)
	run.fail["aideinit -y -f"] = true
	if err := aideControl().Apply(context.Background(), env, control.Values{}); err == nil {
		t.Fatal("expected an error")
	}
	noFile(t, env, aideExclude)
	noFile(t, env, aideRunPath)
}

func TestAIDERejectsBadPaths(t *testing.T) {
	env, _, _ := aideEnv(t)
	for _, p := range []string{"relative/path", "/a/../etc", "/a b$(x)", "/x\n!/etc"} {
		if err := aideControl().Apply(context.Background(), env, control.Values{"exclude": {p}}); err == nil {
			t.Fatalf("%q must be refused", p)
		}
	}
	noFile(t, env, aideExclude)
}

// The script, run for real with stand-in programs

type scriptRig struct {
	dir    string
	script string
	log    string
	notify string
	db     string
}

func newScriptRig(t *testing.T) *scriptRig {
	t.Helper()
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("no sh")
	}
	if _, err := exec.LookPath("flock"); err != nil {
		t.Skip("no flock")
	}
	dir := t.TempDir()
	bin := filepath.Join(dir, "bin")
	must(t, os.MkdirAll(bin, 0o755))
	r := &scriptRig{dir: dir, script: filepath.Join(dir, "aide-run"), log: filepath.Join(dir, "log"),
		notify: filepath.Join(dir, "notify"), db: filepath.Join(dir, "aide.db")}
	must(t, os.WriteFile(r.script, []byte(aideRunScript), 0o755))
	// logger writes "priority message" or the content of the file given with -f.
	must(t, os.WriteFile(filepath.Join(bin, "logger"), []byte(`#!/bin/sh
p=""; f=""
while [ $# -gt 0 ]; do case "$1" in -t) shift;; -p) p=$2; shift;; -f) f=$2; shift;; --) shift; break;; esac; shift; done
if [ -n "$f" ]; then sed "s/^/$p: /" "$f" >> "$LOGFILE"; else echo "$p: $*" >> "$LOGFILE"; fi
`), 0o755))
	// aide prints a line, exits with FAKE_RC, and --update writes the .new file.
	must(t, os.WriteFile(filepath.Join(bin, "aide"), []byte(`#!/bin/sh
echo "aide $*" >> "$CALLS"
case "$*" in *--update*) echo new > "$AIDE_DB.new";; esac
echo "changed: /usr/bin/x"
exit ${FAKE_RC:-0}
`), 0o755))
	must(t, os.WriteFile(r.notify, []byte("#!/bin/sh\necho \"notify: $*\" >> \"$LOGFILE\"\n"), 0o755))
	return r
}

func (r *scriptRig) run(t *testing.T, rc string, withDB bool, notify bool, mode string) (int, string, string) {
	t.Helper()
	if withDB {
		must(t, os.WriteFile(r.db, []byte("db"), 0o644))
	} else {
		_ = os.Remove(r.db)
	}
	_ = os.Remove(r.log)
	_ = os.Remove(r.db + ".new")
	calls := filepath.Join(r.dir, "calls")
	_ = os.Remove(calls)
	cmd := exec.Command("sh", r.script, mode)
	cmd.Env = []string{
		"PATH=" + filepath.Join(r.dir, "bin") + ":/usr/bin:/bin",
		"AIDE_CONF=" + filepath.Join(r.dir, "aide.conf"), "AIDE_DB=" + r.db,
		"AIDE_LOCK=" + filepath.Join(r.dir, "lock"), "LOGFILE=" + r.log, "CALLS=" + calls, "FAKE_RC=" + rc,
		"AIDE_NOTIFY=" + map[bool]string{true: r.notify, false: filepath.Join(r.dir, "nonexistent")}[notify],
	}
	err := cmd.Run()
	code := 0
	if ee, ok := err.(*exec.ExitError); ok {
		code = ee.ExitCode()
	} else if err != nil {
		t.Fatal(err)
	}
	logged, _ := os.ReadFile(r.log)
	c, _ := os.ReadFile(calls)
	return code, string(logged), string(c)
}

func TestAIDEScriptSyntax(t *testing.T) {
	r := newScriptRig(t)
	if out, err := exec.Command("sh", "-n", r.script).CombinedOutput(); err != nil {
		t.Fatalf("syntax: %v: %s", err, out)
	}
}

func TestAIDEScriptCheck(t *testing.T) {
	r := newScriptRig(t)

	code, logged, _ := r.run(t, "0", true, true, "check")
	if code != 0 || !strings.Contains(logged, "no differences") || strings.Contains(logged, "notify") {
		t.Fatalf("clean check: code %d, log %q", code, logged)
	}

	code, logged, calls := r.run(t, "4", true, true, "check")
	if code != 1 {
		t.Fatalf("differences must give exit code 1, got %d", code)
	}
	wantContains(t, logged, "authpriv.warning: differences from the baseline", "changed: /usr/bin/x", "notify: ldp.aide-scheduled-check.differences warning AIDE found differences", "changed: /usr/bin/x")
	wantContains(t, calls, "--check")

	code, logged, _ = r.run(t, "4", true, false, "check")
	if code != 1 || strings.Contains(logged, "notify") {
		t.Fatalf("without the helper nobody is notified: code %d log %q", code, logged)
	}

	code, logged, _ = r.run(t, "17", true, true, "check")
	if code != 1 || !strings.Contains(logged, "user.err: AIDE failed with exit code 17") || strings.Contains(logged, "notify") {
		t.Fatalf("an AIDE error is logged but is not a finding: code %d log %q", code, logged)
	}

	code, logged, calls = r.run(t, "0", false, true, "check")
	if code != 1 || !strings.Contains(logged, "no baseline database") || strings.Contains(calls, "--check") {
		t.Fatalf("no database: code %d log %q", code, logged)
	}
}

func TestAIDEScriptPreNeverFails(t *testing.T) {
	r := newScriptRig(t)
	code, logged, _ := r.run(t, "4", true, true, "pre")
	if code != 0 {
		t.Fatalf("pre must not fail apt, got %d", code)
	}
	wantContains(t, logged, "BEFORE a package operation", "notify: ldp.aide-apt-hook.differences warning AIDE found differences before a package operation")
	if code, _, _ := r.run(t, "17", true, false, "pre"); code != 0 {
		t.Fatalf("pre must not fail apt on an AIDE error, got %d", code)
	}
	if code, _, _ := r.run(t, "0", false, false, "pre"); code != 0 {
		t.Fatalf("pre without a database must not fail, got %d", code)
	}
}

func TestAIDEScriptUpdate(t *testing.T) {
	r := newScriptRig(t)
	code, logged, calls := r.run(t, "4", true, true, "update")
	if code != 0 {
		t.Fatalf("update must not fail apt, got %d", code)
	}
	wantContains(t, logged, "baseline updated")
	wantContains(t, calls, "--update")
	if b, _ := os.ReadFile(r.db); string(b) != "new\n" {
		t.Fatalf("the new database must replace the old: %q", b)
	}
	if _, err := os.Stat(r.db + ".new"); err == nil {
		t.Fatal("the .new file must be gone")
	}

	code, logged, _ = r.run(t, "17", true, true, "update")
	if code != 0 || !strings.Contains(logged, "could not update") {
		t.Fatalf("AIDE error: code %d log %q", code, logged)
	}
	if b, _ := os.ReadFile(r.db); string(b) != "db" {
		t.Fatalf("a failed update must keep the old database: %q", b)
	}

	// No baseline yet: updating would create one nobody asked for.
	if code, _, calls := r.run(t, "0", false, true, "update"); code != 0 || strings.Contains(calls, "--update") {
		t.Fatalf("no database: code %d calls %q", code, calls)
	}
}

func TestAIDEScriptUsage(t *testing.T) {
	r := newScriptRig(t)
	if code, _, _ := r.run(t, "0", true, false, "bogus"); code != 2 {
		t.Fatalf("unknown mode must give 2, got %d", code)
	}
}
