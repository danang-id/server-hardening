// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Danang Galuh Tegar Prasetyo

package controls

import (
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/danang-id/server-hardening/internal/control"
)

// Public keys for tests

func sshString(b []byte) []byte {
	out := make([]byte, 4, 4+len(b))
	binary.BigEndian.PutUint32(out, uint32(len(b)))
	return append(out, b...)
}

// ed25519Key builds a valid-looking ed25519 public key. The seed makes keys differ.
func ed25519Key(seed byte, comment string) string {
	raw := make([]byte, 32)
	for i := range raw {
		raw[i] = seed + byte(i)
	}
	blob := append(sshString([]byte("ssh-ed25519")), sshString(raw)...)
	return strings.TrimSpace("ssh-ed25519 " + base64.StdEncoding.EncodeToString(blob) + " " + comment)
}

// An sshd that answers from the files under the fake root

var sshdDefaults = map[string]string{
	"port": "22", "passwordauthentication": "yes", "kbdinteractiveauthentication": "no",
	"pubkeyauthentication": "yes", "permitrootlogin": "without-password", "maxauthtries": "6",
	"logingracetime": "120", "maxstartups": "10:30:100", "clientaliveinterval": "0",
	"clientalivecountmax": "3", "x11forwarding": "no", "allowagentforwarding": "yes",
	"allowtcpforwarding": "yes", "banner": "none", "subsystem": "sftp /usr/lib/openssh/sftp-server",
}

var sshdMulti = map[string]bool{"port": true, "allowusers": true}

// sshSim emulates what the SSH controls ask of the system: sshd -t, sshd -T
// (drop-ins read in name order, first value wins), ss, ssh -Q, systemctl.
type sshSim struct {
	t   *testing.T
	env *control.Env
	run *fakeRunner

	listen   []int          // ports sshd listens on
	others   map[int]string // other services, by port
	noListen bool           // sshd never starts listening on a new port
	mainWins bool           // the main file sets values before the drop-ins are read
	lntup    []string       // extra lines of "ss -H -lntup": other listening sockets
}

func (s *sshSim) socketMode() bool { return !s.run.fail["systemctl is-active --quiet ssh.socket"] }

func (s *sshSim) files() []string {
	var out []string
	if s.mainWins {
		out = append(out, "/etc/ssh/sshd_config")
	}
	ents, _ := os.ReadDir(s.env.Path("/etc/ssh/sshd_config.d"))
	var names []string
	for _, e := range ents {
		if strings.HasSuffix(e.Name(), ".conf") {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)
	for _, n := range names {
		out = append(out, "/etc/ssh/sshd_config.d/"+n)
	}
	if !s.mainWins {
		out = append(out, "/etc/ssh/sshd_config")
	}
	return out
}

// effective returns the directives in force, as sshd -T prints them.
func (s *sshSim) effective() map[string][]string {
	eff := map[string][]string{}
	for k, v := range sshdDefaults {
		eff[k] = []string{v}
	}
	seen := map[string]bool{}
	for _, f := range s.files() {
		for _, d := range parseSSHD(read(s.t, s.env, f)) {
			k := strings.ToLower(d.Key)
			if strings.HasPrefix(d.Key, "<") || k == "include" {
				continue
			}
			if sshdMulti[k] {
				if !seen[k] {
					eff[k] = nil
					seen[k] = true
				}
				for _, v := range strings.Fields(d.Value) {
					if k == "port" || k == "allowusers" {
						eff[k] = append(eff[k], v)
					}
				}
				continue
			}
			if !seen[k] {
				eff[k] = []string{d.Value}
				seen[k] = true
			}
		}
	}
	return eff
}

func (s *sshSim) ports() []int {
	var out []int
	for _, v := range s.effective()["port"] {
		n, _ := strconv.Atoi(v)
		out = append(out, n)
	}
	return out
}

func (s *sshSim) hook(cmd string) {
	switch {
	case cmd == "sshd -t":
		for _, f := range s.files() {
			if strings.Contains(read(s.t, s.env, f), "INVALID") {
				s.run.fail[cmd] = true
				return
			}
		}
		delete(s.run.fail, cmd)
	case cmd == "sshd -T":
		eff := s.effective()
		var keys []string
		for k := range eff {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		var b strings.Builder
		for _, k := range keys {
			for _, v := range eff[k] {
				fmt.Fprintf(&b, "%s %s\n", k, v)
			}
		}
		s.run.out[cmd] = b.String()
	case cmd == "systemctl reload ssh":
		if !s.socketMode() && !s.noListen {
			s.listen = s.ports()
		}
	case cmd == "systemctl restart ssh.socket":
		if s.noListen {
			return
		}
		s.listen = []int{22}
		if b := read(s.t, s.env, portSocketFile); b != "<missing>" {
			s.listen = nil
			for l := range strings.SplitSeq(b, "\n") {
				if v, ok := strings.CutPrefix(l, "ListenStream="); ok && v != "" {
					n, _ := strconv.Atoi(v)
					s.listen = append(s.listen, n)
				}
			}
		}
	case cmd == "ss -H -lntup":
		var b strings.Builder
		for _, p := range s.listen {
			fmt.Fprintf(&b, "tcp LISTEN 0 128 0.0.0.0:%d 0.0.0.0:* users:((\"sshd\",pid=1,fd=3))\n", p)
		}
		for _, l := range s.lntup {
			b.WriteString(l)
			b.WriteString("\n")
		}
		s.run.out[cmd] = b.String()
	case cmd == "ss -H -ltnp":
		var b strings.Builder
		for _, p := range s.listen {
			fmt.Fprintf(&b, "LISTEN 0 128 0.0.0.0:%d 0.0.0.0:* users:((\"sshd\",pid=1,fd=3))\n", p)
		}
		for p, name := range s.others {
			fmt.Fprintf(&b, "LISTEN 0 128 0.0.0.0:%d 0.0.0.0:* users:((%q,pid=2,fd=4))\n", p, name)
		}
		s.run.out[cmd] = b.String()
	}
}

// sshEnv is a root with one administrator (alice, in the sudo group, with a
// password and a home), OpenSSH installed and listening on port 22.
func sshEnv(t *testing.T) (*control.Env, *fakeRunner, *sshSim) {
	t.Helper()
	env, r := accountsEnv(t)
	writeFile(t, env, "/etc/group", "root:x:0:\nsudo:x:27:alice\nalice:x:1000:\n")
	writeFile(t, env, "/etc/shadow", "root:*:20000:0:99999:7:::\nalice:$y$alicehash:20000:0:99999:7:::\n")
	writeFile(t, env, "/usr/bin/sudo", "")
	must(t, os.MkdirAll(env.Path("/home/alice"), 0o755))
	writeFile(t, env, "/etc/ssh/sshd_config", "Include /etc/ssh/sshd_config.d/*.conf\n")
	writeFile(t, env, "/etc/ssh/ssh_host_ed25519_key", "k")
	writeFile(t, env, "/etc/ssh/ssh_host_rsa_key", "k")
	must(t, os.MkdirAll(env.Path("/etc/ssh/sshd_config.d"), 0o755))

	r.out["dpkg-query -W -f=${Status} openssh-server"] = "install ok installed"
	r.fail["systemctl is-active --quiet ssh.socket"] = true // sshd runs as a service
	r.out["ssh -Q kex"] = "curve25519-sha256\ncurve25519-sha256@libssh.org\nsntrup761x25519-sha512@openssh.com\ndiffie-hellman-group14-sha1\n"
	r.out["ssh -Q cipher"] = "3des-cbc\naes128-ctr\naes192-ctr\naes256-ctr\naes128-gcm@openssh.com\naes256-gcm@openssh.com\nchacha20-poly1305@openssh.com\n"
	r.out["ssh -Q mac"] = "hmac-sha1\nhmac-sha2-256\nhmac-sha2-512\nhmac-sha2-256-etm@openssh.com\nhmac-sha2-512-etm@openssh.com\numac-128-etm@openssh.com\n"
	r.out["ssh -Q HostKeyAlgorithms"] = "ssh-ed25519\nsk-ssh-ed25519@openssh.com\nssh-rsa\nrsa-sha2-256\nrsa-sha2-512\n"

	s := &sshSim{t: t, env: env, run: r, listen: []int{22}, others: map[int]string{}}
	prev := r.hook
	r.hook = func(f *fakeRunner, cmd string) {
		if prev != nil {
			prev(f, cmd)
		}
		s.hook(cmd)
	}
	t.Setenv("SUDO_USER", "")
	portPoll.tries, portPoll.every = 2, 0
	return env, r, s
}

// withKey gives alice an authorized_keys file with one key.
func withKey(t *testing.T, env *control.Env) string {
	t.Helper()
	k := ed25519Key(1, "alice@laptop")
	writeFile(t, env, "/home/alice/.ssh/authorized_keys", k+"\n")
	return k
}

func dropIn(t *testing.T, env *control.Env, name string) string {
	t.Helper()
	return read(t, env, sshdFile(name))
}

func wantContains(t *testing.T, got string, wants ...string) {
	t.Helper()
	for _, w := range wants {
		if !strings.Contains(got, w) {
			t.Errorf("missing %q in:\n%s", w, got)
		}
	}
}

func noFile(t *testing.T, env *control.Env, p string) {
	t.Helper()
	if _, err := os.Stat(filepath.Join(env.Root, p)); err == nil {
		t.Fatalf("%s should not exist", p)
	}
}
