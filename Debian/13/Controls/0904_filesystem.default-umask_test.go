// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Danang Galuh Tegar Prasetyo

package controls

import (
	"context"
	"strings"
	"testing"

	"github.com/danang-id/server-hardening/internal/control"
)

func umaskControl() *defaultUmask {
	return &defaultUmask{control.Base{M: control.Meta{ID: umaskID}}}
}

const stockDefs = "MAIL_DIR\t/var/mail\nUMASK\t\t022\nHOME_MODE\t0700\n"
const stockSession = "session\t[default=1]\tpam_permit.so\nsession\trequired\tpam_unix.so\n"

func umaskEnv(t *testing.T) *control.Env {
	env, _ := testEnv(t)
	writeFile(t, env, loginDefs, stockDefs)
	writeFile(t, env, pamSession, stockSession)
	return env
}

func TestUmaskApplyAndRevert(t *testing.T) {
	ctx := context.Background()
	env := umaskEnv(t)
	c := umaskControl()
	if state(t, c, env) != control.NotApplied {
		t.Fatal("should start not applied")
	}
	must(t, c.Apply(ctx, env, control.Values{"umask": {"027"}}))
	defs := read(t, env, loginDefs)
	wantContains(t, defs, "UMASK\t\t027", "MAIL_DIR\t/var/mail", "HOME_MODE\t0700")
	if strings.Contains(defs, "022") || strings.Count(defs, "UMASK") != 1 {
		t.Fatalf("login.defs: %s", defs)
	}
	wantContains(t, read(t, env, pamSession), stockSession, managed(umaskID), "session optional pam_umask.so")
	if state(t, c, env) != control.Applied {
		t.Fatal("should be applied")
	}

	writeFile(t, env, loginDefs, stockDefs)
	if state(t, c, env) != control.Partial {
		t.Fatal("a changed login.defs is partial")
	}

	must(t, c.Revert(ctx, env))
	if read(t, env, loginDefs) != stockDefs || read(t, env, pamSession) != stockSession {
		t.Fatal("both files must come back as they were")
	}
	if env.Rec.Has(umaskID) {
		t.Fatal("record should be gone")
	}
}

func TestUmaskAddsLineAndKeepsExistingPAMModule(t *testing.T) {
	env := umaskEnv(t)
	writeFile(t, env, loginDefs, "MAIL_DIR\t/var/mail\n")
	writeFile(t, env, pamSession, stockSession+"session optional pam_umask.so\n")
	must(t, umaskControl().Apply(context.Background(), env, control.Values{"umask": {"0077"}}))
	wantContains(t, read(t, env, loginDefs), "UMASK\t\t077")
	if strings.Count(read(t, env, pamSession), "pam_umask") != 1 {
		t.Fatal("pam_umask is there already: do not add it twice")
	}
}

func TestUmaskRejectsBadValues(t *testing.T) {
	env := umaskEnv(t)
	for _, v := range []string{"22", "028", "000", "0o27", "027\nUMASK 000", "xyz", "020"} {
		if err := umaskControl().Apply(context.Background(), env, control.Values{"umask": {v}}); err == nil {
			t.Fatalf("%q must be refused", v)
		}
	}
	if read(t, env, loginDefs) != stockDefs {
		t.Fatal("nothing may change after a refusal")
	}
}

func TestUmaskNeedsPAMFile(t *testing.T) {
	env := umaskEnv(t)
	noFileAt(t, env, pamSession)
	if err := umaskControl().Apply(context.Background(), env, control.Values{"umask": {"027"}}); err == nil {
		t.Fatal("expected an error")
	}
	if read(t, env, loginDefs) != stockDefs {
		t.Fatal("login.defs must stay as it was")
	}
}
