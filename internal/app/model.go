// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Danang Galuh Tegar Prasetyo

package app

import (
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/danang-id/server-hardening/internal/screen"
)

type (
	showMsg struct {
		s     screen.Screen
		reply chan<- screen.Event
	}
	funcMsg func(m *model)
	tickMsg time.Time
)

// model is the Bubble Tea model. It keeps the screen that is up and the
// channel that gets the answer.
type model struct {
	ui    *UI
	th    screen.Theme
	w, h  int
	now   time.Time
	cur   screen.Screen // nil: the busy screen
	reply chan<- screen.Event
	busy  *screen.Busy
	run   *screen.Run // the run screen, kept while questions appear on it
}

func tick() tea.Cmd {
	return tea.Tick(100*time.Millisecond, func(t time.Time) tea.Msg { return tickMsg(t) })
}

func (m *model) Init() tea.Cmd { return tick() }

// stamp gives the screens the current host name, so a rename shows in the
// header without waiting for the next screen.
func (m *model) stamp() {
	if m.ui.host == nil {
		return
	}
	h := m.ui.host()
	m.busy.SetHost(h)
	if hs, ok := m.cur.(screen.HostSetter); ok {
		hs.SetHost(h)
	}
	if m.run != nil {
		m.run.SetHost(h)
	}
}

func (m *model) screen() screen.Screen {
	if m.cur != nil {
		return m.cur
	}
	return m.busy
}

func (m *model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.w, m.h = msg.Width, msg.Height
	case tickMsg:
		m.now = time.Time(msg)
		m.stamp()
		m.busy.Tick(m.now)
		if m.cur != nil {
			m.cur.Tick(m.now)
		}
		return m, tick()
	case showMsg:
		m.cur, m.reply = msg.s, msg.reply
		m.stamp()
		msg.s.Tick(m.now)
	case funcMsg:
		msg(m)
	case tea.KeyMsg:
		return m.key(msg)
	}
	return m, nil
}

func (m *model) key(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	ev := m.screen().Key(keyName(msg))
	switch ev {
	case screen.Quit:
		if msg.String() == "ctrl+c" {
			m.ui.ctrlC.Store(true) // before anything is told, so the error says which
		}
		if m.reply != nil {
			m.reply <- screen.Quit
			m.reply = nil
		}
		m.ui.abort()
		return m, tea.Quit
	case screen.Done, screen.Back:
		m.busy.Msg = "Working…"
		if m.reply != nil {
			m.reply <- ev
			m.reply = nil
		}
		// The run screen stays up between questions. Any other screen gives
		// way to the busy screen until the engine shows the next one.
		if m.cur != nil && m.cur != screen.Screen(m.run) {
			m.cur = nil
		}
	}
	return m, nil
}

// keyName gives a key the name the screens expect.
func keyName(k tea.KeyMsg) string {
	if k.Paste {
		return "paste:" + string(k.Runes)
	}
	return k.String()
}

func (m *model) View() string {
	if m.w == 0 || m.h == 0 {
		return ""
	}
	if m.w < screen.MinWidth || m.h < screen.MinHeight {
		return m.th.Render(screen.TooSmall(m.w, m.h))
	}
	return m.th.Render(m.screen().View(m.w, m.h))
}
