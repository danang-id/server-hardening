// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Danang Galuh Tegar Prasetyo

package controls

import (
	"context"
	"strings"
	"testing"

	"github.com/danang-id/server-hardening/internal/control"
)

func selinuxAuditControl() *selinuxAudit {
	return &selinuxAudit{control.Base{M: control.Meta{ID: selinuxAuditID}}}
}

const avcLine = `type=AVC msg=audit(10/26/2026 09:00:01.123:210) : avc:  denied  { name_bind } for  pid=900 comm=nginx src=8081 scontext=system_u:system_r:httpd_t:s0 tcontext=system_u:object_r:unreserved_port_t:s0 tclass=tcp_socket permissive=0`

func TestSELinuxAuditCleanSystem(t *testing.T) {
	ctx := context.Background()
	env, run := selinuxEnv(t, "Enforcing", "SELINUX=enforcing\n")
	run.fail["ausearch -m AVC,USER_AVC -ts boot -i"] = true // "<no matches>"
	run.out["ps -eZ --no-headers"] = "system_u:system_r:sshd_t:s0-s0:c0.c1023 800 ? 00:00:00 sshd\nunconfined_u:unconfined_r:unconfined_t:s0 900 pts/0 00:00:00 bash\n"
	c := selinuxAuditControl()
	if state(t, c, env) != control.Applied {
		t.Fatalf("findings on a clean system: %v", auditSELinux(ctx, env))
	}
	must(t, c.Apply(ctx, env, nil))
}

func TestSELinuxAuditFindings(t *testing.T) {
	ctx := context.Background()
	env, run := selinuxEnv(t, "Permissive", permissiveConfig)
	run.out["ausearch -m AVC,USER_AVC -ts boot -i"] = avcLine + "\n" + avcLine + "\n----\ntype=SYSCALL not a denial\n"
	run.out["ps -eZ --no-headers"] = "system_u:system_r:unconfined_service_t:s0 700 ? 00:00:00 myapp\nsystem_u:system_r:unconfined_service_t:s0 701 ? 00:00:00 myapp\nsystem_u:system_r:sshd_t:s0 800 ? 00:00:00 sshd\n"
	all := strings.Join(auditSELinux(ctx, env), "\n")
	wantContains(t, all,
		"SELinux is permissive",
		"asks for permissive at the next boot",
		"2 denial(s) since the boot: nginx (2)",
		"without a SELinux policy of their own: myapp")
	if strings.Contains(all, "sshd") {
		t.Fatalf("a confined service is no finding:\n%s", all)
	}
	c := selinuxAuditControl()
	if state(t, c, env) != control.Partial {
		t.Fatal("findings make it partial")
	}
	must(t, c.Apply(ctx, env, nil))
	if err := c.Revert(ctx, env); err != control.ErrNoRevert {
		t.Fatalf("want ErrNoRevert, got %v", err)
	}
}

func TestSELinuxAuditDisabled(t *testing.T) {
	env, _ := selinuxEnv(t, "Disabled", "SELINUX=disabled\n")
	f := auditSELinux(context.Background(), env)
	if len(f) != 1 || !strings.Contains(f[0], "switched off") {
		t.Fatalf("findings: %v", f)
	}
}

func TestSELinuxAuditIsReadonly(t *testing.T) {
	c, ok := System.Get(selinuxAuditID)
	if !ok || !c.Meta().Has(control.TagReadonly) {
		t.Fatal("must be a readonly control")
	}
}
