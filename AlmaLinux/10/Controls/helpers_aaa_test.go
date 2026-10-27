// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Danang Galuh Tegar Prasetyo

package controls

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/danang-id/server-hardening/internal/control"
)

func writeFile(t *testing.T, env *control.Env, p, s string) {
	t.Helper()
	full := env.Path(p)
	must(t, os.MkdirAll(filepath.Dir(full), 0o755))
	must(t, os.WriteFile(full, []byte(s), 0o644))
}

func appendLine(t *testing.T, env *control.Env, p, line string) {
	t.Helper()
	writeFile(t, env, p, read(t, env, p)+line+"\n")
}

const (
	basePasswd = "root:x:0:0:root:/root:/bin/bash\n" +
		"daemon:x:2:2:daemon:/sbin:/sbin/nologin\n" +
		"apache:x:48:48:Apache:/usr/share/httpd:/sbin/nologin\n" +
		"alice:x:1000:1000:Alice:/home/alice:/bin/bash\n"
	baseGroup  = "root:x:0:\nwheel:x:10:\nalice:x:1000:\n"
	baseShadow = "root:*:20000:0:99999:7:::\nalice:!:20000:0:99999:7:::\n"
	// What authselect writes for the "sssd" profile: the pwquality line is always
	// there, the faillock lines are not (they belong to the with-faillock feature).
	basePAMSystemAuth = "auth        required                                     pam_env.so\n" +
		"auth        sufficient                                   pam_unix.so nullok\n" +
		"auth        required                                     pam_deny.so\n" +
		"password    requisite                                    pam_pwquality.so local_users_only\n" +
		"password    sufficient                                   pam_unix.so sha512 shadow use_authtok\n"
)

// accountsEnv adds account files and PAM stacks to the fake root and makes the
// fake runner behave like useradd, usermod, chpasswd and pam-auth-update on
// those files. Commands are still recorded, so tests can assert on them.
func accountsEnv(t *testing.T) (*control.Env, *fakeRunner) {
	t.Helper()
	env, r := testEnv(t)
	writeFile(t, env, "/etc/passwd", basePasswd)
	writeFile(t, env, "/etc/group", baseGroup)
	writeFile(t, env, "/etc/shadow", baseShadow)
	writeFile(t, env, "/etc/pam.d/system-auth", basePAMSystemAuth)
	writeFile(t, env, "/etc/pam.d/password-auth", basePAMSystemAuth)
	r.out["authselect current --raw"] = "sssd with-mkhomedir"

	setShadow := func(user, hash string) {
		var out []string
		found := false
		for l := range strings.SplitSeq(strings.TrimRight(read(t, env, "/etc/shadow"), "\n"), "\n") {
			f := strings.Split(l, ":")
			if f[0] == user {
				f[1], found = hash, true
				l = strings.Join(f, ":")
			}
			out = append(out, l)
		}
		if !found {
			out = append(out, user+":"+hash+":20000:0:99999:7:::")
		}
		writeFile(t, env, "/etc/shadow", strings.Join(out, "\n")+"\n")
	}
	addToGroup := func(group, user string) {
		var out []string
		for l := range strings.SplitSeq(strings.TrimRight(read(t, env, "/etc/group"), "\n"), "\n") {
			f := strings.Split(l, ":")
			if f[0] == group {
				if f[3] == "" {
					f[3] = user
				} else {
					f[3] += "," + user
				}
				l = strings.Join(f, ":")
			}
			out = append(out, l)
		}
		writeFile(t, env, "/etc/group", strings.Join(out, "\n")+"\n")
	}
	r.hook = func(f *fakeRunner, cmd string) {
		fields := strings.Fields(cmd)
		switch {
		case strings.HasPrefix(cmd, "useradd "):
			name := fields[len(fields)-1]
			appendLine(t, env, "/etc/passwd", fmt.Sprintf("%s:x:1001:1001::/home/%s:/bin/bash", name, name))
			addToGroup("wheel", name)
			setShadow(name, "!")
			// useradd -m creates the home with the system default, here 0755.
			must(t, os.MkdirAll(env.Path("/home/"+name), 0o755))
			must(t, os.Chmod(env.Path("/home/"+name), 0o755))
		case strings.HasPrefix(cmd, "usermod -aG wheel "):
			addToGroup("wheel", fields[len(fields)-1])
		case cmd == "chpasswd":
			user, _, _ := strings.Cut(strings.TrimSpace(f.stdin[cmd]), ":")
			setShadow(user, "$y$hash-of-"+user)
		case cmd == "chpasswd -e":
			user, hash, _ := strings.Cut(strings.TrimSpace(f.stdin[cmd]), ":")
			setShadow(user, hash)
		case strings.HasPrefix(cmd, "authselect enable-feature "):
			f.out["authselect current --raw"] = withFeature(f.out["authselect current --raw"], fields[2], true)
		case strings.HasPrefix(cmd, "authselect disable-feature "):
			f.out["authselect current --raw"] = withFeature(f.out["authselect current --raw"], fields[2], false)
		}
	}
	return env, r
}

// withFeature adds or removes a feature in the output of "authselect current --raw".
func withFeature(cur, feature string, on bool) string {
	var out []string
	for _, w := range strings.Fields(cur) {
		if w != feature {
			out = append(out, w)
		}
	}
	if on {
		out = append(out, feature)
	}
	return strings.Join(out, " ")
}
