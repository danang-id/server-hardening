// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Danang Galuh Tegar Prasetyo

// Command hardening is the interactive server hardening tool.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"runtime"
	"strings"

	"github.com/danang-id/server-hardening/internal/app"
	"github.com/danang-id/server-hardening/internal/control"
	"github.com/danang-id/server-hardening/internal/engine"
	"github.com/danang-id/server-hardening/internal/execx"
	"github.com/danang-id/server-hardening/internal/records"
	"github.com/danang-id/server-hardening/internal/registry"
	"github.com/danang-id/server-hardening/internal/screen"
	"github.com/danang-id/server-hardening/internal/sysdetect"
	"github.com/danang-id/server-hardening/internal/tui"
)

const (
	recordsDir = "/var/lib/server-hardening"
	logPath    = "/var/log/server-hardening.log"
)

func main() {
	if err := run(); err != nil {
		// Leaving with q or Exit is a normal end: nothing to print, and the
		// exit status says all is well.
		if errors.Is(err, app.ErrExit) {
			return
		}
		// ctrl+c is a forced stop, not a choice in the program: the usual
		// status for it (128 + SIGINT), and nothing printed.
		if errors.Is(err, tui.ErrAborted) || errors.Is(err, context.Canceled) {
			os.Exit(130)
		}
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

// options holds the command-line flags.
type options struct {
	dry, revert, plain, demo, skipWelcome, printSupport bool
	undo                                                string
}

func parseFlags() options {
	var o options
	flag.BoolVar(&o.dry, "dry-run", false, "show what would run, in order, and change nothing")
	flag.BoolVar(&o.revert, "revert", false, "undo controls that were applied earlier")
	flag.StringVar(&o.undo, "undo", "", "undo one control and exit (used by the automatic undo timer)")
	flag.BoolVar(&o.plain, "plain", false, "use simple prompts instead of the full-screen interface")
	flag.BoolVar(&o.demo, "demo", false, "try the interface on a pretend server; nothing is changed")
	flag.BoolVar(&o.skipWelcome, "skip-welcome", false, "go straight on when this computer is supported (hardening.sh has already shown the start screen)")
	flag.BoolVar(&o.printSupport, "print-support", false, "print the systems this tool supports, one per line, and exit")
	flag.Parse()
	return o
}

// target is the system a run works on, with the environment it runs in.
type target struct {
	sys      *registry.System
	env      *control.Env
	machine  sysdetect.Machine
	hostName func() string
	cleanup  func()
}

func run() error {
	o := parseFlags()
	if o.printSupport {
		fmt.Print(registry.SupportList())
		return nil
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	note := fullScreenProblem(o.plain)
	interactive := note == "" && o.undo == ""

	var (
		t   *target
		err error
	)
	if o.demo {
		t, err = demoTarget(o)
	} else {
		t, err = hostTarget(ctx, cancel, o, interactive)
	}
	if err != nil {
		return err
	}
	defer t.cleanup()

	if o.undo != "" {
		t.env.Log = tui.Logger{W: os.Stdout}
		return undoOne(ctx, t.env, t.sys, o.undo)
	}
	if !o.demo {
		t.env.Guard = newGuard(t.env.Run)
	}
	if note != "" {
		return runPlain(ctx, o, t, note)
	}
	return runScreen(ctx, cancel, o, t)
}

// demoTarget is a pretend server, so the interface can be tried safely.
func demoTarget(o options) (*target, error) {
	sys, env, cleanup, host, err := demoSystem(o.revert)
	if err != nil {
		return nil, err
	}
	env.DryRun = o.dry
	return &target{sys: sys, env: env, machine: demoMachine, hostName: host, cleanup: cleanup}, nil
}

// hostTarget detects the computer the tool runs on. When the computer is not
// supported, an interactive run says so on the first screen and returns
// app.ErrExit; any other run returns the reasons as an error.
func hostTarget(ctx context.Context, cancel context.CancelFunc, o options, interactive bool) (*target, error) {
	// There is no /etc/os-release on a Mac, so it is only read on Linux: the
	// cryptic error that follows would hide the real reason.
	var (
		osr    map[string]string
		osrErr error
	)
	if runtime.GOOS == "linux" {
		osr, osrErr = sysdetect.ReadOSRelease()
	}
	machine := sysdetect.Gather(osr)
	sys, reasons := assess(runtime.GOOS, machine, osr, osrErr)
	if len(reasons) > 0 {
		if !interactive {
			return nil, reasonsError(reasons)
		}
		return nil, unsupported(ctx, cancel, machine, reasons, systemHostname)
	}
	if os.Geteuid() != 0 && !o.dry {
		return nil, fmt.Errorf("must run as root (the entry script asks for it)")
	}
	env := &control.Env{
		Root:   "/",
		Run:    execx.Runner{},
		Rec:    records.New(recordsDir),
		DryRun: o.dry,
	}
	return &target{sys: sys, env: env, machine: machine, hostName: systemHostname, cleanup: func() {}}, nil
}

// runPlain runs with simple prompts, for a terminal that cannot show the
// full-screen interface or when the user asked for them.
func runPlain(ctx context.Context, o options, t *target, note string) error {
	if !o.plain {
		fmt.Fprintln(os.Stderr, note+" Using the simple prompts.")
	}
	t.env.Log = tui.Logger{W: os.Stdout}
	fmt.Printf("%s\n", t.sys.Name)
	return engine.Run(ctx, t.env, tui.New(), t.sys, o.revert)
}

// runScreen runs with the full-screen interface and prints its summary when
// the screen is closed.
func runScreen(ctx context.Context, cancel context.CancelFunc, o options, t *target) error {
	var logw io.Writer
	path := ""
	if !o.demo && !o.dry && os.Geteuid() == 0 {
		if f, err := os.OpenFile(logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600); err == nil {
			defer f.Close()
			logw, path = f, logPath
		}
	}
	ui := app.New(app.Options{
		System: t.sys.Name, Theme: screen.DetectTheme(os.Getenv),
		Cancel: cancel, Log: logw, LogPath: path, Host: t.hostName,
	})
	t.env.Log = ui.Logger()
	if !o.skipWelcome {
		if err := ui.Welcome(ctx, t.machine, nil); err != nil {
			ui.Close()
			return ui.Ended(err)
		}
	}
	err := engine.Run(ctx, t.env, ui, t.sys, o.revert)
	ui.Close()
	ui.PrintSummary(os.Stdout)
	return ui.Ended(err)
}

// fullScreenProblem says why the full-screen interface cannot be used, or
// returns "" if it can. plain is the user's own choice.
func fullScreenProblem(plain bool) string {
	switch {
	case plain:
		return "plain"
	case !isTerminal(os.Stdin) || !isTerminal(os.Stdout):
		return "This is not an interactive terminal."
	case !utf8Locale(os.Getenv):
		return "The terminal is not set to UTF-8."
	}
	return ""
}

func isTerminal(f *os.File) bool {
	fi, err := f.Stat()
	return err == nil && fi.Mode()&os.ModeCharDevice != 0
}

// utf8Locale reports whether the locale uses UTF-8, which the screens need for
// their borders and symbols.
func utf8Locale(getenv func(string) string) bool {
	for _, k := range []string{"LC_ALL", "LC_CTYPE", "LANG"} {
		if v := getenv(k); v != "" {
			v = strings.ToLower(v)
			return strings.Contains(v, "utf-8") || strings.Contains(v, "utf8")
		}
	}
	return false
}

// undoOne is what the automatic undo timer runs: it reverts one control, once,
// without asking anything.
func undoOne(ctx context.Context, env *control.Env, sys *registry.System, id string) error {
	c, ok := sys.Get(id)
	if !ok {
		return fmt.Errorf("no control %q", id)
	}
	st, err := c.Check(ctx, env)
	if err == nil && st == control.NotApplied {
		env.Log.Infof("%s is not applied, nothing to undo", id)
		return nil
	}
	env.Log.Warnf("%s was not confirmed in time, undoing it", id)
	if err := c.Revert(ctx, env); err != nil {
		return fmt.Errorf("undoing %s: %w", id, err)
	}
	env.Log.Infof("%s is undone", id)
	return nil
}

// systemHostname is the name the header shows. It is read again while the
// screen is up, so a hostname the run has just set shows at once.
func systemHostname() string {
	h, err := os.Hostname()
	if err != nil || h == "" {
		return "unknown"
	}
	return h
}

// unsupported shows the first screen for a computer the tool cannot harden. It
// tells why, and the only way on is Exit.
func unsupported(ctx context.Context, cancel context.CancelFunc, m sysdetect.Machine, reasons []string, host func() string) error {
	ui := app.New(app.Options{Theme: screen.DetectTheme(os.Getenv), Cancel: cancel, Host: host})
	err := ui.Welcome(ctx, m, reasons)
	ui.Close()
	if errors.Is(err, app.ErrExit) {
		return err // the screen said why; leaving it is the user's choice
	}
	return ui.Ended(err)
}
