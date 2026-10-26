// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Danang Galuh Tegar Prasetyo

package controls

import (
	"fmt"
	"sort"
	"strings"
	"testing"

	"github.com/danang-id/server-hardening/internal/control"
)

// sysctlSim keeps the running kernel parameters of the fake system. A
// parameter not in the map does not exist.
type sysctlSim struct {
	t       *testing.T
	env     *control.Env
	running map[string]string
	locked  map[string]bool // the kernel ignores writes to these
}

// sysctlEnv is the fake system with a kernel that answers sysctl -n, -w and -p.
func sysctlEnv(t *testing.T, params map[string]string) (*control.Env, *fakeRunner, *sysctlSim) {
	t.Helper()
	env, r := testEnv(t)
	s := &sysctlSim{t: t, env: env, running: map[string]string{}, locked: map[string]bool{}}
	for k, v := range params {
		s.running[k] = v
	}
	prev := r.hook
	r.hook = func(f *fakeRunner, cmd string) {
		if prev != nil {
			prev(f, cmd)
		}
		s.hook(f, cmd)
	}
	return env, r, s
}

func (s *sysctlSim) hook(f *fakeRunner, cmd string) {
	fields := strings.Fields(cmd)
	switch {
	case len(fields) == 3 && fields[0] == "sysctl" && fields[1] == "-n":
		if v, ok := s.running[fields[2]]; ok {
			f.out[cmd] = v + "\n"
			delete(f.fail, cmd)
		} else {
			f.fail[cmd] = true
		}
	case len(fields) == 3 && fields[0] == "sysctl" && fields[1] == "-w":
		k, v, _ := strings.Cut(fields[2], "=")
		if _, ok := s.running[k]; ok && !s.locked[k] {
			s.running[k] = v
		}
	case len(fields) == 3 && fields[0] == "sysctl" && fields[1] == "-p":
		for _, st := range parseSysctl(read(s.t, s.env, strings.TrimPrefix(fields[2], s.env.Root))) {
			if _, ok := s.running[st.Key]; ok && !s.locked[st.Key] {
				s.running[st.Key] = st.Value
			}
		}
	}
}

func (s *sysctlSim) get(k string) string { return s.running[k] }

func (s *sysctlSim) keys() []string {
	var out []string
	for k := range s.running {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func allOf(settings []setting, value string) map[string]string {
	m := map[string]string{}
	for _, st := range settings {
		m[st.Key] = value
	}
	return m
}

func fmtSprintf(f string, a ...any) string { return fmt.Sprintf(f, a...) }
