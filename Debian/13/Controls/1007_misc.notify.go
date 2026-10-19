// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Danang Galuh Tegar Prasetyo

package controls

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/danang-id/server-hardening/internal/apt"
	"github.com/danang-id/server-hardening/internal/control"
	"github.com/danang-id/server-hardening/internal/files"
)

const (
	notifyID   = "misc.notify"
	notifyConf = "/etc/server-hardening/notify.conf"
)

type notify struct{ control.Base }

func init() {
	System.Add(&notify{control.Base{M: control.Meta{
		ID:           notifyID,
		Category:     control.Misc,
		Number:       7,
		Title:        "Send event notifications to a webhook",
		Default:      false,
		Tags:         []control.Tag{control.TagInput},
		RevertLimits: "The curl package stays installed. Notifications that are already on their way may still arrive.",
	}}})
}

// notifyScript is the helper that the other controls call. The webhook URL
// and the authorization value stay in the configuration file. They are not
// given to curl as arguments, so no other user sees them in the process list,
// and they are never written to a log.
const notifyScript = `#!/bin/sh
# Managed by github.com/danang-id/server-hardening (misc.notify)
#
#   notify EVENT SEVERITY TITLE [MESSAGE]         hand the event to a background job
#   notify --send EVENT SEVERITY TITLE [MESSAGE]  send it now (the background job does this)
#   notify --test                                 send a test event now, exit 0 only if delivered
#
# Without a webhook URL in the configuration file nothing is sent.
set -u

CONF="${NOTIFY_CONF:-/etc/server-hardening/notify.conf}"
CURL="${NOTIFY_CURL:-curl}"
SELF="$0"
URL=""
AUTH=""
# shellcheck source=/dev/null
if [ -r "$CONF" ]; then . "$CONF"; fi

log() { logger -t server-hardening-notify -p "$1" -- "$2" 2>/dev/null || :; }

usage() {
    echo "usage: notify EVENT SEVERITY TITLE [MESSAGE] | notify --test" >&2
    exit 2
}

# json_string prints its argument as a JSON string.
json_string() {
    printf '%s' "$1" | awk '
        BEGIN {
            for (i = 1; i < 32; i++) ctl[sprintf("%c", i)] = i
            ORS = ""
            printf "\""
        }
        {
            if (NR > 1) printf "\\n"
            n = length($0)
            for (i = 1; i <= n; i++) {
                c = substr($0, i, 1)
                if (c == "\\") printf "\\\\"
                else if (c == "\"") printf "\\\""
                else if (c == "\t") printf "\\t"
                else if (c == "\r") printf "\\r"
                else if (c in ctl) printf "\\u%04x", ctl[c]
                else printf "%s", c
            }
        }
        END { printf "\"" }'
}

# clip prints the text, cut to at most MAX bytes, as valid UTF-8.
clip() {
    if command -v iconv >/dev/null 2>&1; then clean() { iconv -f UTF-8 -t UTF-8 -c 2>/dev/null; }; else clean() { cat; }; fi
    if [ "$(printf '%s' "$1" | wc -c)" -gt "$2" ]; then
        printf '%s' "$1" | head -c "$2" | clean
        printf '\n[shortened]'
    else
        printf '%s' "$1" | clean
    fi
}

# cfg_quote escapes a value for a curl configuration file.
cfg_quote() { printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g'; }

ERRTXT=""

# send EVENT SEVERITY TITLE [MESSAGE] delivers one event. It returns 0 when
# the receiver answered 2xx, or when no URL is set.
send() {
    [ -n "$URL" ] || return 0
    event=$1
    case "$event" in ''|*[!A-Za-z0-9._-]*) return 2 ;; esac
    sev=$2
    case "$sev" in info|warning|critical) ;; *) sev=warning ;; esac
    title=$(clip "$3" 200)
    msg=$(clip "${4:-}" 2000)
    host=$(hostname -f 2>/dev/null || hostname 2>/dev/null || echo unknown)
    now=$(date -u +%Y-%m-%dT%H:%M:%SZ)

    body=$(mktemp "${TMPDIR:-/tmp}/notify-body.XXXXXX") || return 1
    err=$(mktemp "${TMPDIR:-/tmp}/notify-err.XXXXXX") || { rm -f "$body"; return 1; }
    printf '{"schema":1,"time":%s,"hostname":%s,"severity":%s,"event":%s,"title":%s,"message":%s}\n' \
        "$(json_string "$now")" "$(json_string "$host")" "$(json_string "$sev")" \
        "$(json_string "$event")" "$(json_string "$title")" "$(json_string "$msg")" >"$body"

    # RETRY is split into words on purpose.
    # shellcheck disable=SC2086
    {
        printf 'url = "%s"\n' "$(cfg_quote "$URL")"
        printf 'header = "Content-Type: application/json; charset=utf-8"\n'
        printf 'header = "User-Agent: server-hardening-notify/1"\n'
        if [ -n "$AUTH" ]; then printf 'header = "Authorization: %s"\n' "$(cfg_quote "$AUTH")"; fi
        printf 'data-binary = "@%s"\n' "$(cfg_quote "$body")"
    } | "$CURL" --config - --silent --show-error --fail --output /dev/null --request POST \
        --connect-timeout 10 --max-time 20 --proto '=http,https' ${RETRY-"--retry 3 --retry-delay 5 --retry-all-errors"} 2>"$err"
    rc=$?
    ERRTXT=$(head -n 1 "$err")
    rm -f "$body" "$err"
    if [ "$rc" -ne 0 ]; then log user.err "delivering $event failed (curl exit $rc)"; fi
    return "$rc"
}

# dispatch runs send in the background, so the caller never waits for the
# network. A systemd unit survives the end of the caller's own unit.
dispatch() {
    [ -n "$URL" ] || return 0
    if [ "${NOTIFY_FOREGROUND:-}" = 1 ]; then send "$@"; return 0; fi
    if command -v systemd-run >/dev/null 2>&1 &&
        systemd-run --quiet --no-block --collect --no-ask-password "$SELF" --send "$@" </dev/null >/dev/null 2>&1; then
        return 0
    fi
    ( "$SELF" --send "$@" </dev/null >/dev/null 2>&1 & )
    return 0
}

case "${1:-}" in
    --send)
        shift
        [ $# -ge 3 ] || usage
        send "$@"
        exit $?
        ;;
    --test)
        if [ -z "$URL" ]; then echo "no webhook URL is set" >&2; exit 3; fi
        RETRY=""
        send misc.notify.test info "Test notification" "This is a test from server-hardening on $(hostname 2>/dev/null)."
        rc=$?
        if [ "$rc" -ne 0 ]; then
            echo "the webhook did not accept the test (curl exit $rc): $ERRTXT" >&2
            exit "$rc"
        fi
        echo "the webhook accepted the test notification"
        ;;
    ''|-h|--help)
        usage
        ;;
    *)
        [ $# -ge 3 ] || usage
        dispatch "$@"
        ;;
esac
`

// validWebhook checks the URL. It must be absolute, http or https, with a
// host, and free of spaces and control characters, which would break the
// configuration files.
func validWebhook(s string) error {
	if s == "" {
		return nil
	}
	if err := noControl(s); err != nil {
		return err
	}
	u, err := url.Parse(s)
	if err != nil {
		return fmt.Errorf("not a valid URL: %v", err)
	}
	if u.Scheme != "https" && u.Scheme != "http" {
		return fmt.Errorf("the URL must start with https:// (or http://)")
	}
	if u.Hostname() == "" {
		return fmt.Errorf("the URL has no host")
	}
	return nil
}

func noControl(s string) error {
	for _, r := range s {
		if r <= ' ' || r == 0x7f {
			return fmt.Errorf("spaces and control characters are not allowed")
		}
	}
	return nil
}

func validAuth(s string) error {
	for _, r := range s {
		if r < ' ' || r == 0x7f {
			return fmt.Errorf("control characters are not allowed")
		}
	}
	return nil
}

func shellQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }

func (n *notify) Inputs(context.Context, *control.Env) ([]control.Input, error) {
	return []control.Input{
		{Key: "url", Label: "Webhook URL (empty: send nothing)", Optional: true, Validate: validWebhook,
			Help: "The tool sends a POST request with a JSON body. See REFERENCES.md for the format. The URL may contain a secret, so it is stored for root only."},
		{Key: "auth", Label: "Authorization header value (optional)", Kind: control.Secret, Optional: true, Validate: validAuth,
			Help: "Sent as the Authorization header, for example: Bearer <token>."},
		{Key: "http-ok", Label: "Accept a plain http:// URL?", Kind: control.Choice, Default: "no",
			Help:    "Only matters if the URL starts with http://. The event text and the token would travel unencrypted.",
			Options: []control.Option{{Value: "no", Label: "No"}, {Value: "yes", Label: "Yes, I accept that"}}},
	}, nil
}

func (n *notify) Check(_ context.Context, env *control.Env) (control.State, error) {
	if !env.Rec.Has(notifyID) {
		return control.NotApplied, nil
	}
	b, err := files.ReadOptional(env.Path(notifyConf))
	if err != nil || !strings.Contains(string(b), "URL='") || !hasMarker(env, notifyPath, notifyID) {
		return control.Partial, nil
	}
	return control.Applied, nil
}

func confContent(u, auth string) string {
	return managed(notifyID) + "\nURL=" + shellQuote(u) + "\nAUTH=" + shellQuote(auth) + "\n"
}

func (n *notify) Apply(ctx context.Context, env *control.Env, in control.Values) error {
	u := strings.TrimSpace(in.String("url"))
	auth := in.String("auth")
	if u == "" {
		env.Log.Infof("no webhook URL given, so nothing will be sent")
		return nil
	}
	if err := validWebhook(u); err != nil {
		return err
	}
	if err := validAuth(auth); err != nil {
		return err
	}
	if strings.HasPrefix(strings.ToLower(u), "http://") {
		env.Log.Warnf("the URL is plain http://. The event text and the authorization value travel unencrypted")
		if in.String("http-ok") != "yes" {
			return fmt.Errorf("a plain http:// URL needs your explicit acceptance. Use https:// or answer yes to the question about http://")
		}
	}
	if err := apt.Install(ctx, env, "curl"); err != nil {
		return err
	}

	wasApplied := env.Rec.Has(notifyID)
	oldConf, err := files.ReadOptional(env.Path(notifyConf))
	if err != nil {
		return err
	}
	rollback := func() {
		if wasApplied {
			if oldConf != nil {
				_ = files.WriteAtomic(env.Path(notifyConf), oldConf, 0o600)
			}
			return
		}
		_ = restoreFile(env, notifyID, notifyConf)
		_ = restoreFile(env, notifyID, notifyPath)
		_ = os.Remove(env.Path(filepath.Dir(notifyConf)))
		_ = env.Rec.Delete(notifyID)
	}
	if err := os.MkdirAll(env.Path(filepath.Dir(notifyConf)), 0o755); err != nil {
		return err
	}
	if err := os.MkdirAll(env.Path(libexecDir), 0o755); err != nil {
		return err
	}
	if err := putFile(env, notifyID, notifyPath, notifyScript, 0o755); err != nil {
		return err
	}
	if err := putFile(env, notifyID, notifyConf, confContent(u, auth), 0o600); err != nil {
		rollback()
		return err
	}
	if err := env.Rec.Put(notifyID, "applied", "yes"); err != nil {
		rollback()
		return err
	}
	out, err := env.Run.Run(ctx, notifyPath, "--test")
	if err != nil {
		rollback()
		return fmt.Errorf("the test notification was not delivered, so nothing was kept: %s", lastLine(string(out), err))
	}
	env.Log.Infof("the webhook accepted a test notification")
	return nil
}

func lastLine(out string, err error) string {
	if l := lines(out); len(l) > 0 {
		return l[len(l)-1]
	}
	return err.Error()
}

func (n *notify) Revert(_ context.Context, env *control.Env) error {
	if !env.Rec.Has(notifyID) {
		env.Log.Warnf("%s: no record, leaving the notification settings alone", notifyID)
		return nil
	}
	if err := restoreFile(env, notifyID, notifyConf); err != nil {
		return err
	}
	if err := restoreFile(env, notifyID, notifyPath); err != nil {
		return err
	}
	_ = os.Remove(env.Path(filepath.Dir(notifyConf))) // only when empty
	return env.Rec.Delete(notifyID)
}
