// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Danang Galuh Tegar Prasetyo

package controls

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/danang-id/server-hardening/internal/control"
)

func notifyControl() *notify { return &notify{control.Base{M: control.Meta{ID: notifyID}}} }

func notifyValues(u, auth, httpOK string) control.Values {
	return control.Values{"url": {u}, "auth": {auth}, "http-ok": {httpOK}}
}

func TestNotifyApplyWritesPrivateFilesAndTests(t *testing.T) {
	ctx := context.Background()
	env, run, s := sysEnv(t)
	c := notifyControl()
	if state(t, c, env) != control.NotApplied {
		t.Fatal("should start not applied")
	}
	must(t, c.Apply(ctx, env, notifyValues("https://hooks.example/x?token=it's", "Bearer a'b", "no")))
	if !s.installed["curl"] {
		t.Fatal("curl must be installed")
	}
	fi, err := os.Stat(env.Path(notifyConf))
	must(t, err)
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("conf mode %o", fi.Mode().Perm())
	}
	si, err := os.Stat(env.Path(notifyPath))
	must(t, err)
	if si.Mode().Perm() != 0o755 {
		t.Fatalf("script mode %o", si.Mode().Perm())
	}
	wantContains(t, read(t, env, notifyConf), managed(notifyID), `URL='https://hooks.example/x?token=it'\''s'`, `AUTH='Bearer a'\''b'`)
	if !run.did(notifyPath + " --test") {
		t.Fatal("must test the webhook")
	}
	// Neither the URL nor the token may reach any command line.
	for _, call := range run.calls {
		if strings.Contains(call, "hooks.example") || strings.Contains(call, "Bearer") {
			t.Fatalf("secret in a command line: %s", call)
		}
	}
	if state(t, c, env) != control.Applied {
		t.Fatal("should be applied")
	}
	must(t, c.Revert(ctx, env))
	noFile(t, env, notifyConf)
	noFile(t, env, notifyPath)
	if env.Rec.Has(notifyID) {
		t.Fatal("record must go")
	}
}

func TestNotifyEmptyURLDoesNothing(t *testing.T) {
	env, run, s := sysEnv(t)
	must(t, notifyControl().Apply(context.Background(), env, notifyValues("  ", "", "no")))
	if s.installed["curl"] || len(run.calls) != 0 || env.Rec.Has(notifyID) {
		t.Fatalf("nothing expected: %v", run.calls)
	}
	noFile(t, env, notifyConf)
}

func TestNotifyRefusals(t *testing.T) {
	ctx := context.Background()
	env, run, _ := sysEnv(t)
	c := notifyControl()
	for _, u := range []string{"ftp://x.example/", "https://", "not a url", "https://x.example/a b", "https://x.example/\nfoo"} {
		if err := c.Apply(ctx, env, notifyValues(u, "", "no")); err == nil {
			t.Errorf("%q must be refused", u)
		}
	}
	if err := c.Apply(ctx, env, notifyValues("https://x.example/", "a\nb", "no")); err == nil {
		t.Error("a newline in the header value must be refused")
	}
	var warns []string
	env.Log = &memLog{warns: &warns}
	if err := c.Apply(ctx, env, notifyValues("http://x.example/", "", "no")); err == nil {
		t.Error("plain http without acceptance must be refused")
	}
	if len(warns) == 0 {
		t.Error("plain http must warn")
	}
	if run.did("--test") {
		t.Fatal("nothing may be tested after a refusal")
	}
	noFile(t, env, notifyConf)
	must(t, c.Apply(ctx, env, notifyValues("http://x.example/", "", "yes")))
}

func TestNotifyFailedTestRollsBack(t *testing.T) {
	ctx := context.Background()
	env, run, _ := sysEnv(t)
	c := notifyControl()
	run.fail[notifyPath+" --test"] = true
	run.out[notifyPath+" --test"] = "the webhook did not accept the test (curl exit 22): The requested URL returned error: 404\n"
	err := c.Apply(ctx, env, notifyValues("https://x.example/", "", "no"))
	if err == nil || !strings.Contains(err.Error(), "404") {
		t.Fatalf("got %v", err)
	}
	noFile(t, env, notifyConf)
	noFile(t, env, notifyPath)
	if env.Rec.Has(notifyID) {
		t.Fatal("a failed first apply leaves no record")
	}

	// A failed second apply keeps the working configuration of the first.
	delete(run.fail, notifyPath+" --test")
	must(t, c.Apply(ctx, env, notifyValues("https://good.example/", "", "no")))
	run.fail[notifyPath+" --test"] = true
	if err := c.Apply(ctx, env, notifyValues("https://bad.example/", "", "no")); err == nil {
		t.Fatal("expected an error")
	}
	wantContains(t, read(t, env, notifyConf), "good.example")
	if !env.Rec.Has(notifyID) {
		t.Fatal("record stays")
	}
}

func TestNotifyCheckPartialWhenConfGone(t *testing.T) {
	ctx := context.Background()
	env, _, _ := sysEnv(t)
	c := notifyControl()
	must(t, c.Apply(ctx, env, notifyValues("https://x.example/", "", "no")))
	must(t, os.Remove(env.Path(notifyConf)))
	if state(t, c, env) != control.Partial {
		t.Fatal("missing conf is partial")
	}
}

func TestNotifyInputs(t *testing.T) {
	in, err := notifyControl().Inputs(context.Background(), nil)
	must(t, err)
	if len(in) != 3 || in[0].Validate("https://a.example") != nil || in[0].Validate("") != nil || in[0].Validate("gopher://a") == nil || in[1].Kind != control.Secret {
		t.Fatalf("inputs: %+v", in)
	}
}

// The script, run for real with a stand-in curl

type notifyRig struct {
	dir  string
	conf string
	bin  string
}

func newNotifyRig(t *testing.T, url, auth string) *notifyRig {
	t.Helper()
	for _, tool := range []string{"sh", "awk", "sed", "head", "wc", "mktemp"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skip("no " + tool)
		}
	}
	dir := t.TempDir()
	r := &notifyRig{dir: dir, conf: filepath.Join(dir, "notify.conf"), bin: filepath.Join(dir, "bin")}
	must(t, os.MkdirAll(r.bin, 0o755))
	must(t, os.WriteFile(filepath.Join(dir, "notify"), []byte(notifyScript), 0o755))
	must(t, os.WriteFile(r.conf, []byte(confContent(url, auth)), 0o600))
	// curl records its arguments and the configuration it reads from stdin,
	// copies the body file, and exits with FAKE_RC.
	must(t, os.WriteFile(filepath.Join(r.bin, "curl"), []byte(`#!/bin/sh
echo "$*" >> "$OUT/args"
cat > "$OUT/config"
f=$(sed -n 's/^data-binary = "@\(.*\)"$/\1/p' "$OUT/config")
cp "$f" "$OUT/body"
echo "curl: (22) The requested URL returned error: 500" >&2
exit ${FAKE_RC:-0}
`), 0o755))
	must(t, os.WriteFile(filepath.Join(r.bin, "logger"), []byte("#!/bin/sh\necho \"$*\" >> \"$OUT/log\"\n"), 0o755))
	must(t, os.WriteFile(filepath.Join(r.bin, "hostname"), []byte("#!/bin/sh\necho srv.example.org\n"), 0o755))
	return r
}

func (r *notifyRig) run(t *testing.T, rc string, extra []string, args ...string) (int, string) {
	t.Helper()
	for _, f := range []string{"args", "config", "body", "log"} {
		_ = os.Remove(filepath.Join(r.dir, f))
	}
	cmd := exec.Command("sh", append([]string{filepath.Join(r.dir, "notify")}, args...)...)
	cmd.Env = append([]string{
		"PATH=" + r.bin + ":/usr/bin:/bin", "NOTIFY_CONF=" + r.conf, "OUT=" + r.dir, "TMPDIR=" + r.dir,
		"FAKE_RC=" + rc, "NOTIFY_FOREGROUND=1",
	}, extra...)
	out, err := cmd.CombinedOutput()
	code := 0
	if ee, ok := err.(*exec.ExitError); ok {
		code = ee.ExitCode()
	} else if err != nil {
		t.Fatal(err)
	}
	return code, string(out)
}

func (r *notifyRig) body(t *testing.T) map[string]any {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(r.dir, "body"))
	must(t, err)
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("not valid JSON: %v\n%s", err, b)
	}
	return m
}

func (r *notifyRig) file(t *testing.T, name string) string {
	b, _ := os.ReadFile(filepath.Join(r.dir, name))
	return string(b)
}

func TestNotifyScriptSendsTheDocumentedBody(t *testing.T) {
	r := newNotifyRig(t, "https://hooks.example/a?t=s3cret", `Bearer "tok"\x`)
	code, out := r.run(t, "0", nil, "ldp.aide-scheduled-check.differences", "warning", "AIDE found differences", "changed: /usr/bin/x\nadded: /tmp/y")
	if code != 0 {
		t.Fatalf("exit %d: %s", code, out)
	}
	m := r.body(t)
	if m["schema"] != float64(1) || m["severity"] != "warning" || m["event"] != "ldp.aide-scheduled-check.differences" ||
		m["title"] != "AIDE found differences" || m["message"] != "changed: /usr/bin/x\nadded: /tmp/y" || m["hostname"] != "srv.example.org" {
		t.Fatalf("body: %v", m)
	}
	if _, err := time.Parse(time.RFC3339, m["time"].(string)); err != nil || !strings.HasSuffix(m["time"].(string), "Z") {
		t.Fatalf("time: %v", m["time"])
	}
	cfg := r.file(t, "config")
	wantContains(t, cfg, `url = "https://hooks.example/a?t=s3cret"`, `header = "Authorization: Bearer \"tok\"\\x"`, "Content-Type: application/json")
	// The secrets are in the configuration on stdin, never in the arguments.
	args := r.file(t, "args")
	if strings.Contains(args, "hooks.example") || strings.Contains(args, "Bearer") || strings.Contains(args, "s3cret") {
		t.Fatalf("secret in the arguments: %s", args)
	}
	wantContains(t, args, "--fail", "--max-time", "--retry 3", "--retry-all-errors", "--proto =http,https")
}

func TestNotifyScriptEscapesAndClips(t *testing.T) {
	r := newNotifyRig(t, "https://hooks.example/a", "")
	nasty := "q\" b\\ t\t r\r bell\x01 esc\x1b é日本   end"
	if code, out := r.run(t, "0", nil, "misc.notify.test", "info", nasty, nasty+"\nline two"); code != 0 {
		t.Fatalf("exit %d: %s", code, out)
	}
	m := r.body(t)
	if m["title"] != nasty {
		t.Fatalf("title: %q want %q", m["title"], nasty)
	}
	if m["message"] != nasty+"\nline two" {
		t.Fatalf("message: %q", m["message"])
	}
	if strings.Contains(r.file(t, "config"), "Authorization") {
		t.Fatal("no auth, no header")
	}

	long := strings.Repeat("日本語", 1000) // 9000 bytes
	if code, out := r.run(t, "0", nil, "misc.notify.test", "info", long, long); code != 0 {
		t.Fatalf("exit %d: %s", code, out)
	}
	m = r.body(t) // must still be valid JSON, so valid UTF-8
	msg, title := m["message"].(string), m["title"].(string)
	if len(msg) > 2000+len("\n[shortened]") || !strings.HasSuffix(msg, "[shortened]") || len(title) > 200+len("\n[shortened]") {
		t.Fatalf("not clipped: %d %d", len(msg), len(title))
	}
}

func TestNotifyScriptSeverityEventAndSilence(t *testing.T) {
	r := newNotifyRig(t, "https://hooks.example/a", "")
	if code, _ := r.run(t, "0", nil, "x.y", "bogus", "t"); code != 0 {
		t.Fatal("exit")
	}
	if r.body(t)["severity"] != "warning" || r.body(t)["message"] != "" {
		t.Fatalf("body: %v", r.body(t))
	}
	if code, _ := r.run(t, "0", nil, "bad event!", "info", "t"); code != 0 {
		t.Fatal("a bad event name must not break the caller")
	}
	if r.file(t, "args") != "" {
		t.Fatal("a bad event name must not be sent")
	}
	if code, _ := r.run(t, "0", nil, "only", "two"); code != 2 {
		t.Fatalf("too few arguments: %d", code)
	}

	// No URL: nothing is sent, in any mode.
	must(t, os.WriteFile(r.conf, []byte(confContent("", "")), 0o600))
	for _, args := range [][]string{{"a.b", "info", "t"}, {"--send", "a.b", "info", "t"}} {
		if code, _ := r.run(t, "0", nil, args...); code != 0 || r.file(t, "args") != "" {
			t.Fatalf("%v: code %d, curl called: %q", args, code, r.file(t, "args"))
		}
	}
	if code, out := r.run(t, "0", nil, "--test"); code != 3 || !strings.Contains(out, "no webhook URL") {
		t.Fatalf("test without URL: %d %s", code, out)
	}
}

func TestNotifyScriptTestAndFailure(t *testing.T) {
	r := newNotifyRig(t, "https://hooks.example/a", "")
	code, out := r.run(t, "0", nil, "--test")
	if code != 0 || !strings.Contains(out, "accepted") || r.body(t)["event"] != "misc.notify.test" || r.body(t)["severity"] != "info" {
		t.Fatalf("test: %d %s %v", code, out, r.body(t))
	}
	if strings.Contains(r.file(t, "args"), "--retry") {
		t.Fatal("the test must not retry")
	}
	code, out = r.run(t, "22", nil, "--test")
	if code != 22 || !strings.Contains(out, "did not accept") || !strings.Contains(out, "500") {
		t.Fatalf("failed test: %d %s", code, out)
	}
	if strings.Contains(out, "hooks.example") {
		t.Fatal("the URL must not be printed")
	}
	// A failure in the background is logged without the URL.
	if code, _ := r.run(t, "7", nil, "--send", "a.b", "info", "t"); code != 7 {
		t.Fatalf("send failure exit: %d", code)
	}
	lg := r.file(t, "log")
	wantContains(t, lg, "user.err", "delivering a.b failed (curl exit 7)")
	if strings.Contains(lg, "hooks.example") {
		t.Fatal("the URL must not be logged")
	}
}

func TestNotifyScriptDispatchesInTheBackground(t *testing.T) {
	r := newNotifyRig(t, "https://hooks.example/a", "")
	// A stand-in systemd-run runs the command, as the real one would do later.
	must(t, os.WriteFile(filepath.Join(r.bin, "systemd-run"), []byte(`#!/bin/sh
echo "$*" >> "$OUT/sdrun"
while [ $# -gt 0 ]; do case "$1" in --*) shift;; *) break;; esac; done
exec "$@"
`), 0o755))
	code, out := r.run(t, "0", []string{"NOTIFY_FOREGROUND=0"}, "a.b", "critical", "t", "m")
	if code != 0 {
		t.Fatalf("exit %d: %s", code, out)
	}
	sd := r.file(t, "sdrun")
	wantContains(t, sd, "--no-block", "--collect", "--send a.b critical t m")
	if strings.Contains(sd, "hooks.example") {
		t.Fatal("the URL must not reach systemd-run")
	}
	if r.body(t)["severity"] != "critical" {
		t.Fatal("the job must send the event")
	}

	// Without systemd-run the script falls back to a detached job.
	must(t, os.Remove(filepath.Join(r.bin, "systemd-run")))
	_ = os.Remove(filepath.Join(r.dir, "body"))
	if code, out := r.run(t, "0", []string{"NOTIFY_FOREGROUND=0"}, "a.b", "info", "t"); code != 0 {
		t.Fatalf("exit %d: %s", code, out)
	}
	for i := 0; i < 100; i++ {
		if _, err := os.Stat(filepath.Join(r.dir, "body")); err == nil {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("the background job did not send")
}
