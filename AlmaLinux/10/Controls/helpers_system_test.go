// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Danang Galuh Tegar Prasetyo

package controls

import (
	"os"
	"strings"
	"testing"

	"github.com/danang-id/server-hardening/internal/control"
)

// sysSim pretends to be rpm, dnf and systemd well enough for the controls
// that install packages and switch services.
type sysSim struct {
	installed map[string]bool
	enabled   map[string]bool
	active    map[string]bool
	alsoGoes  map[string][]string // packages that go with a package when it is removed
	removed   []string
	units     map[string]string // description by unit, for systemctl show
}

func sysEnv(t *testing.T) (*control.Env, *fakeRunner, *sysSim) {
	t.Helper()
	env, run := testEnv(t)
	s := &sysSim{
		installed: map[string]bool{}, enabled: map[string]bool{}, active: map[string]bool{},
		alsoGoes: map[string][]string{},
	}
	run.hook = func(f *fakeRunner, cmd string) { s.hook(f, cmd) }
	return env, run, s
}

func (s *sysSim) set(f *fakeRunner, cmd string, ok bool) { f.fail[cmd] = !ok }

func (s *sysSim) hook(f *fakeRunner, cmd string) {
	fields := strings.Fields(cmd)
	switch {
	case strings.HasPrefix(cmd, "rpm -q --quiet "):
		s.set(f, cmd, s.installed[fields[len(fields)-1]])
	case strings.HasPrefix(cmd, "dnf -y install "):
		for _, p := range fields[3:] {
			s.installed[p] = true
		}
	case strings.HasPrefix(cmd, "dnf -y remove "):
		for _, p := range fields[3:] {
			delete(s.installed, p)
			s.removed = append(s.removed, p)
			for _, x := range s.alsoGoes[p] {
				delete(s.installed, x)
				s.removed = append(s.removed, x)
			}
		}
	case strings.HasPrefix(cmd, "dnf remove --assumeno "):
		// What dnf prints before it asks the question.
		var b strings.Builder
		b.WriteString("Dependencies resolved.\n================\n Package   Arch   Version   Repository   Size\n================\nRemoving:\n")
		for _, p := range fields[3:] {
			b.WriteString(" ")
			b.WriteString(p)
			b.WriteString("   x86_64   1.0-1   @baseos   1.0 k\n")
		}
		var deps []string
		for _, p := range fields[3:] {
			deps = append(deps, s.alsoGoes[p]...)
		}
		if len(deps) > 0 {
			b.WriteString("Removing dependent packages:\n")
			for _, x := range deps {
				b.WriteString(" ")
				b.WriteString(x)
				b.WriteString("   x86_64   1.0-1   @baseos   1.0 k\n")
			}
		}
		b.WriteString("\nTransaction Summary\n================\nRemove  1 Package\n\nOperation aborted.\n")
		f.out[cmd] = b.String()
		f.fail[cmd] = true // --assumeno ends with an error at the question
	case strings.HasPrefix(cmd, "systemctl is-enabled --quiet "):
		s.set(f, cmd, s.enabled[fields[len(fields)-1]])
	case strings.HasPrefix(cmd, "systemctl is-active --quiet "):
		s.set(f, cmd, s.active[fields[len(fields)-1]])
	case strings.HasPrefix(cmd, "systemctl enable --now "):
		for _, u := range fields[3:] {
			s.enabled[u], s.active[u] = true, true
		}
	case strings.HasPrefix(cmd, "systemctl disable --now "):
		for _, u := range fields[3:] {
			s.enabled[u], s.active[u] = false, false
		}
	case strings.HasPrefix(cmd, "systemctl enable "):
		for _, u := range fields[2:] {
			s.enabled[u] = true
		}
	case strings.HasPrefix(cmd, "systemctl disable "):
		for _, u := range fields[2:] {
			s.enabled[u] = false
		}
	case strings.HasPrefix(cmd, "systemctl start "), strings.HasPrefix(cmd, "systemctl restart "):
		s.active[fields[len(fields)-1]] = true
	case strings.HasPrefix(cmd, "systemctl stop "):
		s.active[fields[len(fields)-1]] = false
	case strings.HasPrefix(cmd, "systemctl show -p Description --value "):
		f.out[cmd] = s.units[fields[len(fields)-1]]
	}
}

// listEnabled makes `systemctl list-unit-files` answer with the enabled units.
func (s *sysSim) listEnabled(f *fakeRunner) {
	var b strings.Builder
	for u, on := range s.enabled {
		if on && strings.HasSuffix(u, ".service") {
			b.WriteString(u)
			b.WriteString(" enabled enabled\n")
		}
	}
	f.out["systemctl list-unit-files --type=service --state=enabled --no-legend --no-pager"] = b.String()
}

// memLog collects warnings.
type memLog struct{ warns *[]string }

func (memLog) Infof(string, ...any) {}
func (m *memLog) Warnf(f string, a ...any) {
	*m.warns = append(*m.warns, fmtSprintf(f, a...))
}

func noFileAt(t *testing.T, env *control.Env, p string) {
	t.Helper()
	if err := os.Remove(env.Path(p)); err != nil {
		t.Fatal(err)
	}
}

// mountSim keeps the mount options of mount points. A mount point that is not
// in the map is not mounted on its own.
type mountSim struct {
	t      *testing.T
	env    *control.Env
	opts   map[string]string // options by mount point
	fstype map[string]string
	sys    *sysSim
}

// mountEnv adds findmnt, mount -o remount and `systemctl reload tmp.mount`.
func mountEnv(t *testing.T) (*control.Env, *fakeRunner, *sysSim, *mountSim) {
	env, run, s := sysEnv(t)
	m := &mountSim{t: t, env: env, sys: s,
		opts:   map[string]string{"/tmp": "rw,nosuid,nodev,relatime,size=1024k", "/dev/shm": "rw,nosuid,nodev", "/proc": "rw,nosuid,nodev,noexec,relatime"},
		fstype: map[string]string{"/tmp": "tmpfs", "/dev/shm": "tmpfs", "/proc": "proc"}}
	prev := run.hook
	run.hook = func(f *fakeRunner, cmd string) {
		prev(f, cmd)
		m.hook(f, cmd)
	}
	return env, run, s, m
}

func (m *mountSim) hook(f *fakeRunner, cmd string) {
	fields := strings.Fields(cmd)
	switch {
	case strings.HasPrefix(cmd, "findmnt -n -o OPTIONS "):
		mnt := fields[len(fields)-1]
		if _, ok := m.opts[mnt]; !ok && strings.Contains(cmd, " -T ") {
			mnt = "/" // a directory that is no mount point: the file system it is on
		}
		if o, ok := m.opts[mnt]; ok {
			f.out[cmd] = o + "\n"
			delete(f.fail, cmd)
		} else {
			f.fail[cmd] = true
		}
	case strings.HasPrefix(cmd, "findmnt -n -o FSTYPE "):
		t := m.fstype[fields[len(fields)-1]]
		if t == "" && strings.Contains(cmd, " -T ") {
			t = m.fstype["/"]
		}
		f.out[cmd] = t + "\n"
	case len(fields) == 4 && fields[0] == "mount" && fields[1] == "-o" && strings.HasPrefix(fields[2], "remount"):
		if f.fail[cmd] {
			return
		}
		m.remount(fields[3], strings.Split(fields[2], ",")[1:])
	case cmd == "systemctl reload tmp.mount":
		if f.fail[cmd] {
			return
		}
		b, _ := os.ReadFile(m.env.Path("/etc/systemd/system/tmp.mount.d/99-server-hardening.conf"))
		o := "rw,nosuid,nodev,relatime,size=1024k"
		for l := range strings.SplitSeq(string(b), "\n") {
			if v, ok := strings.CutPrefix(l, "Options="); ok {
				o = "rw," + v
			}
		}
		m.opts["/tmp"] = o
	}
}

// remount applies flag changes (nosuid/suid, nodev/dev, noexec/exec, other key=value) to a mount point.
func (m *mountSim) remount(mnt string, changes []string) {
	set := map[string]bool{}
	var order []string
	for o := range strings.SplitSeq(m.opts[mnt], ",") {
		set[o] = true
		order = append(order, o)
	}
	for _, c := range changes {
		switch c {
		case "suid":
			delete(set, "nosuid")
		case "dev":
			delete(set, "nodev")
		case "exec":
			delete(set, "noexec")
		default:
			if k, _, ok := strings.Cut(c, "="); ok {
				for o := range set {
					if strings.HasPrefix(o, k+"=") {
						delete(set, o)
					}
				}
			}
			if !set[c] {
				order = append(order, c)
			}
			set[c] = true
		}
	}
	var out []string
	for _, o := range order {
		if set[o] {
			out = append(out, o)
			set[o] = false
		}
	}
	m.opts[mnt] = strings.Join(out, ",")
}

// infoLog collects informational lines.
type infoLog struct{ infos *[]string }

func (l *infoLog) Infof(f string, a ...any) { *l.infos = append(*l.infos, fmtSprintf(f, a...)) }
func (infoLog) Warnf(string, ...any)        {}
