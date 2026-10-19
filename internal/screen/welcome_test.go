// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Danang Galuh Tegar Prasetyo

package screen

import (
	"strings"
	"testing"

	"github.com/danang-id/server-hardening/internal/sysdetect"
)

var testMachine = sysdetect.Machine{OS: "Debian GNU/Linux 13 (trixie)", Kernel: "Linux 6.12.48+deb13-amd64", Arch: "amd64"}

func TestWelcomeSupported(t *testing.T) {
	c := NewWelcome(testMachine, nil)
	c.SetHost("web-01")
	v := c.View(80, 24)
	sized(t, v, 80, 24)
	contains(t, v, "danang-id/server-hardening", "web-01", "OS", "Debian GNU/Linux 13 (trixie)", "Kernel",
		"Linux 6.12.48+deb13-amd64", "Architecture", "amd64", "Support status", "✔ SUPPORTED", "Start", "Exit",
		"Interactive Server Hardening", "github.com/danang-id/server-hardening")
	lacks(t, v, "Reason", "NOT SUPPORTED", "Supported")
	if c.Key("enter") != Done || !c.Start {
		t.Fatal("enter on Start goes on")
	}
}

func TestWelcomeKeysOnSupported(t *testing.T) {
	c := NewWelcome(testMachine, nil)
	press(c, "right")
	if press(c, "enter") != Quit || c.Start {
		t.Fatal("enter on Exit leaves")
	}
	c = NewWelcome(testMachine, nil)
	if press(c, "s") != Done || !c.Start {
		t.Fatal("s starts")
	}
	for _, k := range []string{"q", "esc", "ctrl+c"} {
		if press(NewWelcome(testMachine, nil), k) != Quit {
			t.Fatalf("%s leaves", k)
		}
	}
}

func TestWelcomeUnsupportedCannotStart(t *testing.T) {
	c := NewWelcome(sysdetect.Machine{OS: "macOS 26.0", Kernel: "Darwin 25.0.0", Arch: "arm64"},
		[]string{"macOS is not supported operating system"})
	v := c.View(80, 24)
	sized(t, v, 80, 24)
	contains(t, v, "macOS 26.0", "Darwin 25.0.0", "✘ NOT SUPPORTED", "Reason", "macOS is not supported operating system", "Start", "Exit")
	lacks(t, v, "•") // one reason is a sentence, not a point
	for _, k := range []string{"left", "right", "tab", "s"} {
		if press(c, k) != None {
			t.Fatalf("%s must do nothing", k)
		}
	}
	if press(c, "enter") != Quit || c.Start {
		t.Fatal("enter leaves, never starts")
	}
	if !strings.Contains(plain(c.View(80, 24)), "enter exit") {
		t.Fatal("the hint says enter exit")
	}
}

func TestWelcomeSeveralReasonsAreListed(t *testing.T) {
	c := NewWelcome(sysdetect.Machine{OS: "macOS 26.0", Kernel: "Darwin 25.0.0", Arch: "riscv64"},
		[]string{"macOS is not supported operating system", "RISC-V is not supported processor architecture, and this phrase is long enough to wrap onto a second row of the box."})
	v := c.View(80, 24)
	sized(t, v, 80, 24)
	contains(t, v, "Reason", "• macOS is not supported operating system", "• RISC-V is not supported")
	for _, l := range v {
		if l.Width() > 80 {
			t.Fatalf("too wide: %q", l.Plain())
		}
	}
	// "Reason" is written once.
	if n := strings.Count(plain(v), "Reason"); n != 1 {
		t.Fatalf("Reason appears %d times", n)
	}
}

func TestWelcomeNarrowAndShort(t *testing.T) {
	c := NewWelcome(testMachine, nil)
	c.SetHost("a-rather-long-host-name.example.com")
	for _, sz := range [][2]int{{64, 18}, {70, 20}, {120, 40}} {
		sized(t, c.View(sz[0], sz[1]), sz[0], sz[1])
	}
}
