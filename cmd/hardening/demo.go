// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Danang Galuh Tegar Prasetyo

package main

import (
	"context"
	"fmt"
	"hash/fnv"
	"os"
	"sync"
	"time"

	debian13 "github.com/danang-id/server-hardening/Debian/13"
	controls "github.com/danang-id/server-hardening/Debian/13/Controls"
	"github.com/danang-id/server-hardening/internal/control"
	"github.com/danang-id/server-hardening/internal/records"
	"github.com/danang-id/server-hardening/internal/registry"
	"github.com/danang-id/server-hardening/internal/sysdetect"
)

// The demo runs the real screens against a pretend server, so the interface
// can be seen on any computer. It changes nothing: Apply and Revert only wait
// and write log lines.

// demoState remembers what the pretend server has applied.
type demoState struct {
	mu      sync.Mutex
	applied map[string]bool
	host    string
}

// demoHost is the name of the pretend server before the hostname is set.
const demoHost = "vps-demo"

func (s *demoState) hostName() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.host
}

func (s *demoState) setHost(h string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.host = h
}

func (s *demoState) has(id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.applied[id]
}

func (s *demoState) set(id string, on bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if on {
		s.applied[id] = true
	} else {
		delete(s.applied, id)
	}
}

// demoControl is a real control with pretend work.
type demoControl struct {
	control.Control
	st *demoState
}

var demoPartial = "ldp.auditd"

func (d demoControl) Check(context.Context, *control.Env) (control.State, error) {
	id := d.Meta().ID
	switch {
	case d.st.has(id):
		return control.Applied, nil
	case id == demoPartial:
		return control.Partial, nil
	}
	return control.NotApplied, nil
}

func (d demoControl) Inputs(ctx context.Context, env *control.Env) ([]control.Input, error) {
	if in, ok := demoInputs[d.Meta().ID]; ok {
		return in, nil
	}
	// The real questions need the real server. Where they cannot be asked
	// here, the demo goes on without them.
	var in []control.Input
	func() {
		defer func() { _ = recover() }()
		in, _ = d.Control.Inputs(ctx, env)
	}()
	return in, nil
}

func (d demoControl) Apply(ctx context.Context, env *control.Env, in control.Values) error {
	m := d.Meta()
	if err := demoWork(ctx, env, m.ID, "Writing the configuration", "Reloading the service"); err != nil {
		return err
	}
	if m.ID == "misc.swapfile" {
		return fmt.Errorf("not enough free disk space for a 2 GiB swap file (demo)")
	}
	if m.ID == "baseline.hostname" {
		if name := in.String("name"); name != "" {
			d.st.setHost(name)
		}
	}
	d.st.set(m.ID, true)
	return nil
}

func (d demoControl) Revert(ctx context.Context, env *control.Env) error {
	if err := demoWork(ctx, env, d.Meta().ID, "Restoring the saved files"); err != nil {
		return err
	}
	if d.Meta().ID == "baseline.hostname" {
		d.st.setHost(demoHost)
	}
	d.st.set(d.Meta().ID, false)
	return nil
}

// demoWork waits a moment per step, as real work would, and logs it.
func demoWork(ctx context.Context, env *control.Env, id string, steps ...string) error {
	h := fnv.New32a()
	h.Write([]byte(id))
	base := time.Duration(150+h.Sum32()%350) * time.Millisecond
	for _, s := range append([]string{"Checking the current state"}, steps...) {
		env.Log.Infof("%s: %s", id, s)
		select {
		case <-time.After(base):
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return nil
}

// demoInputs are the questions asked in the demo where the real ones need a
// real server to suggest values.
var demoInputs = map[string][]control.Input{
	// The real questions read the network of a real server. Nothing to ask here.
	"network.systemd-networkd": nil,
	"baseline.hostname": {{
		Key: "name", Label: "Host name", Help: "A short name: letters, digits and hyphens.", Default: "web-01",
		Validate: func(s string) error {
			for _, r := range s {
				if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-') {
					return fmt.Errorf("use lowercase letters, digits and hyphens only")
				}
			}
			return nil
		},
	}},
	"remote-access.ssh-port": {{
		Key: "port", Label: "New SSH port", Help: "A number from 1 to 65535, not 22. Open it in your provider's firewall too.",
		Validate: func(s string) error {
			if s == "22" {
				return fmt.Errorf("22 is the port SSH uses now")
			}
			return nil
		},
	}},
	"network.open-ports": {
		{Key: "listening", Label: "Open the ports that are listening now",
			Help: "Services listening on the server. SSH is open already. Open only what must be reachable from outside.",
			Kind: control.MultiChoice, DefaultMulti: []string{"443"},
			Options: []control.Option{{Value: "80", Label: "80/tcp   nginx"}, {Value: "443", Label: "443/tcp  nginx"}, {Value: "5432", Label: "5432/tcp postgres"}}},
		{Key: "rules", Label: "More ports to open, one per line (optional)",
			Help: "Form: PORT, PORT/PROTO, or PORT/PROTO from ADDRESS. Example: 51820/udp.",
			Kind: control.TextArea, Optional: true},
	},
	"misc.notify": {
		{Key: "url", Label: "Webhook address", Help: "Events are sent here.", Default: "https://hooks.example.com/alert"},
		{Key: "auth", Label: "Webhook token", Help: "Sent as a header. Leave empty if none.", Kind: control.Secret, Confirm: true, Optional: true},
		{Key: "http-ok", Label: "Accept answers other than 2xx?", Kind: control.Choice, Default: "no",
			Options: []control.Option{{Value: "no", Label: "No, only 2xx counts"}, {Value: "yes", Label: "Yes, any answer counts", Help: "For services that answer 3xx or 4xx."}}},
	},
}

type demoRunner struct{}

func (demoRunner) Run(context.Context, string, ...string) ([]byte, error) { return nil, nil }
func (demoRunner) RunStdin(context.Context, string, string, ...string) ([]byte, error) {
	return nil, nil
}

type demoGuard struct{}

func (demoGuard) Arm(context.Context, string, time.Duration) (func(context.Context) error, error) {
	return func(context.Context) error { return nil }, nil
}

// demoSystem builds the pretend server. In a revert, many controls start
// applied, so the list has something to show.
func demoSystem(revert bool) (*registry.System, *control.Env, func(), func() string, error) {
	st := &demoState{applied: map[string]bool{}, host: demoHost}
	for _, id := range []string{"baseline.timezone", "baseline.time-sync", "remote-access.sftp", "ldp.journald-persistent", "system-kernel.restrict-bpf"} {
		st.applied[id] = true
	}
	sys := &registry.System{
		ID: "demo", Name: "Debian 13 (Trixie) │ demo", Reference: debian13.Reference,
		NotApplicable: map[control.Category]string{},
	}
	for _, c := range controls.System.Controls() {
		m := c.Meta()
		if revert && m.Default && m.Revertible() {
			st.applied[m.ID] = true
		}
		sys.Add(demoControl{Control: c, st: st})
	}
	dir, err := os.MkdirTemp("", "hardening-demo-")
	if err != nil {
		return nil, nil, nil, nil, err
	}
	env := &control.Env{Root: dir, Run: demoRunner{}, Rec: records.New(dir), Guard: demoGuard{}}
	return sys, env, func() { _ = os.RemoveAll(dir) }, st.hostName, nil
}

// demoMachine is the pretend machine the start screen shows in the demo.
var demoMachine = sysdetect.Machine{Name: "Debian", Version: "13", OS: "Debian GNU/Linux 13 (trixie)", Kernel: "Linux 6.12.48+deb13-amd64", Arch: "amd64"}
