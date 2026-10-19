// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Danang Galuh Tegar Prasetyo

package controls

import (
	"context"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/danang-id/server-hardening/internal/control"
	"github.com/danang-id/server-hardening/internal/files"
)

const (
	umaskID    = "filesystem.default-umask"
	loginDefs  = "/etc/login.defs"
	pamSession = "/etc/pam.d/common-session"
	pamUmask   = "session optional pam_umask.so"
)

type defaultUmask struct{ control.Base }

func init() {
	System.Add(&defaultUmask{control.Base{M: control.Meta{
		ID:           umaskID,
		Category:     control.Filesystem,
		Number:       4,
		Title:        "Set a restrictive default umask",
		Default:      false,
		Tags:         []control.Tag{control.TagInput, control.TagCompat},
		RevertLimits: "Files already created keep their permissions. Open sessions keep their umask until the next login.",
	}}})
}

var umaskValue = regexp.MustCompile(`^0?[0-7]{3}$`)

// validUmask accepts three octal digits that keep the files of a user away from
// everyone outside the group: others must not get write permission.
func validUmask(s string) (string, error) {
	s = strings.TrimSpace(s)
	if !umaskValue.MatchString(s) {
		return "", fmt.Errorf("use three octal digits, for example 027")
	}
	if len(s) == 4 {
		s = s[1:]
	}
	n, _ := strconv.ParseUint(s, 8, 32)
	if n&0o002 == 0 {
		return "", fmt.Errorf("%s leaves new files writable for everyone. Use at least 002", s)
	}
	return s, nil
}

func (u *defaultUmask) Inputs(context.Context, *control.Env) ([]control.Input, error) {
	return []control.Input{{
		Key: "umask", Label: "Umask for new files", Default: "027",
		Help: "027 gives files 640 and directories 750. 077 keeps everything private to the owner.",
		Validate: func(s string) error {
			_, err := validUmask(s)
			return err
		},
	}}, nil
}

var umaskLine = regexp.MustCompile(`(?m)^[ \t]*UMASK[ \t]+(\S+).*$`)

func (u *defaultUmask) Check(_ context.Context, env *control.Env) (control.State, error) {
	if !env.Rec.Has(umaskID) {
		return control.NotApplied, nil
	}
	want, _, _ := env.Rec.Get(umaskID, "umask")
	defs, err := files.ReadOptional(env.Path(loginDefs))
	if err != nil {
		return control.NotApplied, err
	}
	pam, _ := files.ReadOptional(env.Path(pamSession))
	m := umaskLine.FindAllStringSubmatch(string(defs), -1)
	if len(m) == 0 || m[len(m)-1][1] != want || !strings.Contains(string(pam), "pam_umask.so") {
		return control.Partial, nil
	}
	return control.Applied, nil
}

func (u *defaultUmask) Apply(_ context.Context, env *control.Env, in control.Values) error {
	val, err := validUmask(in.String("umask"))
	if err != nil {
		return err
	}
	defs, err := files.ReadOptional(env.Path(loginDefs))
	if err != nil {
		return err
	}
	if defs == nil {
		return fmt.Errorf("%s does not exist", loginDefs)
	}
	pam, err := files.ReadOptional(env.Path(pamSession))
	if err != nil {
		return err
	}
	if pam == nil {
		return fmt.Errorf("%s does not exist", pamSession)
	}
	if err := env.Rec.Put(umaskID, "umask", val); err != nil {
		return err
	}

	// login.defs: change the first UMASK line, or add one.
	text := string(defs)
	if umaskLine.MatchString(text) {
		done := false
		text = umaskLine.ReplaceAllStringFunc(text, func(string) string {
			if done {
				return "# (replaced by server-hardening) UMASK " + val
			}
			done = true
			return "UMASK\t\t" + val
		})
	} else {
		text = strings.TrimRight(text, "\n") + "\nUMASK\t\t" + val + "\n"
	}
	if err := putFile(env, umaskID, loginDefs, text, 0o644); err != nil {
		return err
	}

	// PAM: pam_umask reads the value from login.defs for every session type.
	if !regexp.MustCompile(`(?m)^[ \t]*session[ \t]+\S+[ \t]+pam_umask\.so`).Match(pam) {
		p := strings.TrimRight(string(pam), "\n") + "\n" + managed(umaskID) + "\n" + pamUmask + "\n"
		if err := putFile(env, umaskID, pamSession, p, 0o644); err != nil {
			_ = restoreFile(env, umaskID, loginDefs)
			return err
		}
	}
	env.Log.Infof("new files get the umask %s. Files uploaded for a web server will not be readable by it unless it shares a group", val)
	return nil
}

func (u *defaultUmask) Revert(_ context.Context, env *control.Env) error {
	if !env.Rec.Has(umaskID) {
		env.Log.Warnf("%s: no record, leaving the umask alone", umaskID)
		return nil
	}
	for _, f := range []string{loginDefs, pamSession} {
		if err := restoreFile(env, umaskID, f); err != nil {
			return err
		}
	}
	return env.Rec.Delete(umaskID)
}
