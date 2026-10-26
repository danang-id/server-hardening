// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Danang Galuh Tegar Prasetyo

// Package firewall holds the parts of the firewall controls that do not
// depend on the system: reading port rules and writing them for nftables and
// firewalld.
package firewall

import (
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
)

// PortRule is one allowed service: a port or port range, a protocol and an
// optional source address or network.
type PortRule struct{ Port, Proto, Source string }

func (r PortRule) String() string {
	s := r.Port + "/" + r.Proto
	if r.Source != "" {
		s += " from " + r.Source
	}
	return s
}

// V6 reports whether the source of the rule is an IPv6 address or network.
func (r PortRule) V6() bool { return strings.Contains(r.Source, ":") }

var portSpec = regexp.MustCompile(`^(\d{1,5})(?:-(\d{1,5}))?$`)

// ParsePortRule reads "443", "443/tcp", "51820/udp from 203.0.113.0/24" or "8000-8010/tcp".
func ParsePortRule(line string) (PortRule, error) {
	f := strings.Fields(line)
	if len(f) == 0 {
		return PortRule{}, fmt.Errorf("empty rule")
	}
	if len(f) != 1 && !(len(f) == 3 && f[1] == "from") {
		return PortRule{}, fmt.Errorf("%q: use PORT, PORT/PROTO or PORT/PROTO from ADDRESS", line)
	}
	spec, proto, hasProto := strings.Cut(f[0], "/")
	if !hasProto {
		proto = "tcp"
	}
	if proto != "tcp" && proto != "udp" {
		return PortRule{}, fmt.Errorf("%q: the protocol is tcp or udp", line)
	}
	m := portSpec.FindStringSubmatch(spec)
	if m == nil {
		return PortRule{}, fmt.Errorf("%q: not a port or a port range such as 8000-8010", line)
	}
	lo, _ := strconv.Atoi(m[1])
	hi := lo
	if m[2] != "" {
		hi, _ = strconv.Atoi(m[2])
	}
	if lo < 1 || hi > 65535 || hi < lo {
		return PortRule{}, fmt.Errorf("%q: ports go from 1 to 65535", line)
	}
	r := PortRule{Port: spec, Proto: proto}
	if len(f) == 3 {
		if _, _, err := net.ParseCIDR(f[2]); err != nil && net.ParseIP(f[2]) == nil {
			return PortRule{}, fmt.Errorf("%q: %q is not an address or a network such as 203.0.113.0/24", line, f[2])
		}
		r.Source = f[2]
	}
	return r, nil
}

func ParsePortRules(text string) ([]PortRule, error) {
	var out []PortRule
	seen := map[string]bool{}
	for l := range strings.SplitSeq(text, "\n") {
		l = strings.TrimSpace(l)
		if l == "" || strings.HasPrefix(l, "#") {
			continue
		}
		r, err := ParsePortRule(l)
		if err != nil {
			return nil, err
		}
		if !seen[r.String()] {
			seen[r.String()] = true
			out = append(out, r)
		}
	}
	return out, nil
}

func RuleLines(rs []PortRule) string {
	var l []string
	for _, r := range rs {
		l = append(l, r.String())
	}
	return strings.Join(l, "\n")
}

func NftRender(marker, table string, ssh []int, rules []PortRule, logRate string) string {
	var b strings.Builder
	w := func(f string, a ...any) { fmt.Fprintf(&b, f+"\n", a...) }
	w("%s", marker)
	w("# Rebuilt from the records of network.firewall, network.open-ports and network.firewall-log-denied.")
	w("table inet %s", table)
	w("delete table inet %s", table)
	w("")
	w("table inet %s {", table)
	w("\tchain input {")
	w("\t\ttype filter hook input priority filter; policy drop;")
	w("\t\tct state established,related accept")
	w("\t\tct state invalid drop")
	w("\t\tiif lo accept")
	w("\t\tip protocol icmp accept")
	w("\t\tip6 nexthdr ipv6-icmp accept")
	var ps []string
	for _, p := range ssh {
		ps = append(ps, strconv.Itoa(p))
	}
	w("\t\ttcp dport { %s } accept comment \"ssh\"", strings.Join(ps, ", "))
	for _, r := range rules {
		match := ""
		if r.Source != "" {
			fam := "ip"
			if r.V6() {
				fam = "ip6"
			}
			match = fam + " saddr " + r.Source + " "
		}
		w("\t\t%s%s dport %s accept", match, r.Proto, r.Port)
	}
	if logRate != "" {
		w("\t\tlimit rate %s log prefix \"server-hardening drop: \"", logRate)
	}
	w("\t}")
	w("}")
	return b.String()
}

func FirewalldRule(r PortRule) (rich string, port string) {
	if r.Source == "" {
		return "", r.Port + "/" + r.Proto
	}
	fam := "ipv4"
	if r.V6() {
		fam = "ipv6"
	}
	return fmt.Sprintf(`rule family="%s" source address="%s" port port="%s" protocol="%s" accept`, fam, r.Source, r.Port, r.Proto), ""
}

// JoinInts writes a list of numbers as 22,2222 for the records.
func JoinInts(ns []int) string {
	var s []string
	for _, n := range ns {
		s = append(s, strconv.Itoa(n))
	}
	return strings.Join(s, ",")
}

// SplitInts reads what JoinInts wrote.
func SplitInts(s string) []int {
	var out []int
	for f := range strings.SplitSeq(s, ",") {
		if n, err := strconv.Atoi(strings.TrimSpace(f)); err == nil {
			out = append(out, n)
		}
	}
	return out
}
