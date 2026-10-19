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

func dropLines(t *testing.T, env *control.Env, p, containing string) {
	t.Helper()
	var keep []string
	for l := range strings.SplitSeq(read(t, env, p), "\n") {
		if l != "" && !strings.Contains(l, containing) {
			keep = append(keep, l)
		}
	}
	writeFile(t, env, p, strings.Join(keep, "\n")+"\n")
}

const (
	basePasswd = "root:x:0:0:root:/root:/bin/bash\n" +
		"daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n" +
		"www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n" +
		"alice:x:1000:1000:Alice:/home/alice:/bin/bash\n"
	baseGroup   = "root:x:0:\nsudo:x:27:\nalice:x:1000:\n"
	baseShadow  = "root:*:20000:0:99999:7:::\nalice:!:20000:0:99999:7:::\n"
	basePAMAuth = "auth\t[success=1 default=ignore]\tpam_unix.so nullok\n" +
		"auth\trequisite\t\t\tpam_deny.so\nauth\trequired\t\t\tpam_permit.so\n"
	basePAMPassword = "password\t[success=1 default=ignore]\tpam_unix.so obscure yescrypt\n" +
		"password\trequisite\t\t\tpam_deny.so\n"
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
	writeFile(t, env, "/etc/pam.d/common-auth", basePAMAuth)
	writeFile(t, env, "/etc/pam.d/common-password", basePAMPassword)

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
			addToGroup("sudo", name)
			setShadow(name, "!")
			// useradd -m creates the home with the system default, here 0755.
			must(t, os.MkdirAll(env.Path("/home/"+name), 0o755))
			must(t, os.Chmod(env.Path("/home/"+name), 0o755))
		case strings.HasPrefix(cmd, "usermod -aG sudo "):
			addToGroup("sudo", fields[len(fields)-1])
		case cmd == "chpasswd":
			user, _, _ := strings.Cut(strings.TrimSpace(f.stdin[cmd]), ":")
			setShadow(user, "$y$hash-of-"+user)
		case cmd == "chpasswd -e":
			user, hash, _ := strings.Cut(strings.TrimSpace(f.stdin[cmd]), ":")
			setShadow(user, hash)
		case strings.HasPrefix(cmd, "pam-auth-update --package --enable "):
			for _, p := range fields[3:] {
				switch p {
				case "pwquality":
					if !strings.Contains(read(t, env, "/etc/pam.d/common-password"), "pam_pwquality") {
						appendLine(t, env, "/etc/pam.d/common-password", "password\trequisite\t\t\tpam_pwquality.so retry=3")
					}
				case lockProfilePre, lockProfileMain:
					if !strings.Contains(read(t, env, "/etc/pam.d/common-auth"), p) {
						appendLine(t, env, "/etc/pam.d/common-auth", "auth\trequired\tpam_faillock.so # "+p)
					}
				}
			}
		case strings.HasPrefix(cmd, "pam-auth-update --package --remove "):
			for _, p := range fields[3:] {
				switch p {
				case "pwquality":
					dropLines(t, env, "/etc/pam.d/common-password", "pam_pwquality")
				case lockProfilePre, lockProfileMain:
					dropLines(t, env, "/etc/pam.d/common-auth", p)
				}
			}
		}
	}
	return env, r
}
