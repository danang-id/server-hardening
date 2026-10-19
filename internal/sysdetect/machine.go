// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Danang Galuh Tegar Prasetyo

package sysdetect

import (
	"os/exec"
	"runtime"
	"strings"
)

// Machine is what the start screen tells about the computer.
type Machine struct {
	Name    string // the operating system without its version: "Debian", "macOS"
	Version string // the version of it: "13", "27.0.1"; empty when there is none
	OS      string // for example "Debian GNU/Linux 13 (trixie)"
	Kernel  string // the kernel and its version, for example "Linux 6.12.48+deb13-amd64" or "Darwin 27.0.0"
	Arch    string // the processor architecture, for example "amd64" or "arm64"
}

// kernelName is the name of the kernel that goes with an operating system, so
// that the version alone never has to say which kernel it is.
func kernelName(goos string) string {
	switch goos {
	case "linux":
		return "Linux"
	case "darwin":
		return "Darwin"
	case "windows":
		return "Windows NT"
	case "freebsd":
		return "FreeBSD"
	case "openbsd":
		return "OpenBSD"
	case "netbsd":
		return "NetBSD"
	}
	return goos
}

// osName is the short name of the operating system and its version.
func osName(goos string, osr map[string]string, version string) (name, ver string) {
	switch goos {
	case "linux":
		name = strings.TrimSpace(strings.TrimSuffix(osr["NAME"], "GNU/Linux"))
		if name == "" {
			name = "Linux"
		}
		return name, osr["VERSION_ID"]
	case "darwin":
		return "macOS", version
	case "windows":
		return "Windows", version
	case "freebsd":
		return "FreeBSD", version
	case "openbsd":
		return "OpenBSD", version
	case "netbsd":
		return "NetBSD", version
	}
	return goos, version
}

// ArchName is a processor architecture in the words people use for it. Go
// names it "riscv64" and "ppc64le"; people say RISC-V and PowerPC.
func ArchName(arch string) string {
	if n, ok := archNames[arch]; ok {
		return n
	}
	return arch
}

var archNames = map[string]string{
	"amd64":    "x86-64",
	"386":      "x86 (32-bit)",
	"arm64":    "ARM64",
	"arm":      "ARM (32-bit)",
	"riscv64":  "RISC-V",
	"ppc64le":  "PowerPC 64-bit (little-endian)",
	"ppc64":    "PowerPC 64-bit",
	"s390x":    "IBM Z",
	"mips":     "MIPS",
	"mipsle":   "MIPS (little-endian)",
	"mips64":   "MIPS 64-bit",
	"mips64le": "MIPS 64-bit (little-endian)",
	"loong64":  "LoongArch",
}

// Describe puts the facts about a computer into words. osr is the parsed
// /etc/os-release (nil when there is none), release is the kernel version, and
// version is the version of a system that has no os-release, such as macOS.
func Describe(goos, arch string, osr map[string]string, release, version string) Machine {
	m := Machine{Kernel: strings.TrimSpace(kernelName(goos) + " " + release), Arch: arch}
	m.Name, m.Version = osName(goos, osr, version)
	if m.Arch == "" {
		m.Arch = "unknown"
	}
	switch goos {
	case "linux":
		switch {
		case osr["PRETTY_NAME"] != "":
			m.OS = osr["PRETTY_NAME"]
		case osr["NAME"] != "":
			m.OS = strings.TrimSpace(osr["NAME"] + " " + osr["VERSION_ID"])
		default:
			m.OS = "Linux"
		}
	case "darwin":
		m.OS = strings.TrimSpace("macOS " + version)
	case "windows":
		m.OS = strings.TrimSpace("Windows " + version)
	default:
		m.OS = goos
	}
	return m
}

// Gather looks at the computer the tool is running on.
func Gather(osr map[string]string) Machine {
	version := ""
	if runtime.GOOS == "darwin" {
		version = run("sw_vers", "-productVersion")
	}
	return Describe(runtime.GOOS, runtime.GOARCH, osr, run("uname", "-r"), version)
}

// run returns the output of a command, or "" when it cannot be run.
func run(name string, args ...string) string {
	out, err := exec.Command(name, args...).Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}
