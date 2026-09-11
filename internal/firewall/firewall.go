// Package firewall applies the node's inbound OS firewall using nftables. It
// manages a single dedicated table (inet hzproxy_fw) and never touches other
// tables, so it composes with (or leaves alone) whatever else is configured.
//
// Safety: the agent connects OUTBOUND to the panel, and this firewall filters
// INBOUND (plus, with Options.Forward, forwarded traffic on the same ports) — so
// applying it can never cut the agent off. Even a lock-yourself-out ruleset is
// recoverable by fixing the rules in the panel; the agent will re-apply on the
// next sync. Loopback and established/related are always accepted, so existing
// SSH sessions survive a policy change.
//
// Docker (and any other DNAT) publishes ports through the forward hook, which an
// input-only firewall never sees. With Options.Forward the same allow-list is
// enforced on a forward chain that runs before Docker's own rules (priority -10
// vs Docker's 0) and only ever drops: its policy stays accept, so it can never
// break unrelated forwarding.
package firewall

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

const tableName = "inet hzproxy_fw"

// Rule is one inbound allow rule. Source is "any", a CIDR/IP, or "@<ipset>".
type Rule struct {
	Port     string // "22", "8000-8010", or "any"
	Protocol string // "tcp" | "udp" | "icmp" | "any"
	Source   string // "any" | CIDR/IP | "@name"
}

// IPSet is a named list of CIDRs (cfips-style, e.g. Cloudflare ranges) rendered
// as an nftables named set and referenced by rules with source "@Name".
type IPSet struct {
	Name  string
	CIDRs []string
}

// Available reports whether nft is installed.
func Available() bool {
	_, err := exec.LookPath("nft")
	return err == nil
}

// Options tunes how the managed table is rendered.
type Options struct {
	// Forward also enforces the rules on forwarded traffic, so DNAT'ed /
	// Docker-published ports are covered. The forward chain's policy stays
	// accept: it only adds explicit drops for the managed ports.
	Forward bool
}

// Apply installs (enabled) or removes (disabled) the managed firewall table.
func Apply(enabled bool, rules []Rule, sets []IPSet, opts Options) error {
	if !Available() {
		if !enabled {
			return nil
		}
		return fmt.Errorf("nftables(nft) 未安装，无法启用防火墙")
	}
	script := removeScript()
	if enabled {
		script = render(rules, sets, opts)
	}
	if out, err := runNft(script, "-c", "-f", "-"); err != nil {
		return fmt.Errorf("nft 校验失败: %s", firstLine(out))
	}
	if out, err := runNft(script, "-f", "-"); err != nil {
		return fmt.Errorf("nft 应用失败: %s", firstLine(out))
	}
	return nil
}

// setInfo tracks which families a named set has elements for.
type setInfo struct{ v4, v6 bool }

// render builds an atomic-replace nft script: declare-then-delete the table (so
// the delete never fails), define named sets, then a default-drop input chain.
func render(rules []Rule, sets []IPSet, opts Options) string {
	// Partition each set into v4/v6 element lists.
	idx := make(map[string]setInfo, len(sets))
	var setDefs strings.Builder
	for _, s := range sets {
		var v4, v6 []string
		for _, c := range s.CIDRs {
			if strings.Contains(c, ":") {
				v6 = append(v6, c)
			} else {
				v4 = append(v4, c)
			}
		}
		info := setInfo{v4: len(v4) > 0, v6: len(v6) > 0}
		idx[s.Name] = info
		if info.v4 {
			setDefs.WriteString(setDef(s.Name, "ipv4_addr", v4))
		}
		if info.v6 {
			setDefs.WriteString(setDef(s.Name+"_v6", "ipv6_addr", v6))
		}
	}

	var b strings.Builder
	b.WriteString("table " + tableName + "\n")
	b.WriteString("delete table " + tableName + "\n")
	b.WriteString("table " + tableName + " {\n")
	b.WriteString(setDefs.String())
	b.WriteString("  chain input {\n")
	b.WriteString("    type filter hook input priority 0; policy drop;\n")
	b.WriteString("    iif \"lo\" accept\n")
	b.WriteString("    ct state established,related accept\n")
	b.WriteString("    ct state invalid drop\n")
	for _, r := range rules {
		for _, line := range ruleLines(r, idx) {
			b.WriteString("    " + line + "\n")
		}
	}
	b.WriteString("  }\n")

	// Forwarded traffic (Docker-published ports are DNAT'ed and never traverse
	// the input chain) gets the same allow-list, expressed as drops so this chain
	// keeps "policy accept" and can only ever block the managed ports.
	if opts.Forward {
		if fwd := forwardLines(rules, idx); len(fwd) > 0 {
			b.WriteString("  chain forward {\n")
			b.WriteString("    type filter hook forward priority -10; policy accept;\n")
			for _, line := range fwd {
				b.WriteString("    " + line + "\n")
			}
			b.WriteString("  }\n")
		}
	}
	b.WriteString("}\n")
	return b.String()
}

func setDef(name, typ string, elems []string) string {
	var b strings.Builder
	b.WriteString("  set " + name + " {\n")
	b.WriteString("    type " + typ + "; flags interval;\n")
	if len(elems) > 0 {
		b.WriteString("    elements = { " + strings.Join(elems, ", ") + " }\n")
	}
	b.WriteString("  }\n")
	return b.String()
}

func removeScript() string {
	return "table " + tableName + "\ndelete table " + tableName + "\n"
}

// portProto renders the "<proto> dport <port>" fragment (without the source).
func portProto(port, proto string) string {
	anyPort := port == "" || port == "any"
	switch proto {
	case "icmp":
		return "meta l4proto { icmp, icmpv6 }"
	case "udp":
		if anyPort {
			return "meta l4proto udp"
		}
		return "udp dport " + port
	case "any":
		if anyPort {
			return "meta l4proto { tcp, udp }"
		}
		return "meta l4proto { tcp, udp } th dport " + port
	default: // tcp
		if anyPort {
			return "meta l4proto tcp"
		}
		return "tcp dport " + port
	}
}

// ruleLines renders a rule into nft statements. The source may list several
// tokens (space/comma separated) — each becomes its own accept line, and an
// @ipset with both v4 and v6 members yields two.
func ruleLines(r Rule, idx map[string]setInfo) []string {
	pp := portProto(strings.TrimSpace(r.Port), strings.ToLower(strings.TrimSpace(r.Protocol)))
	tokens := splitSources(r.Source)

	// No source, or any token is "any" -> allow from anywhere.
	if len(tokens) == 0 || contains(tokens, "any") {
		return []string{pp + " accept"}
	}

	var out []string
	for _, src := range tokens {
		if strings.HasPrefix(src, "@") {
			name := strings.TrimPrefix(src, "@")
			info := idx[name]
			if info.v4 {
				out = append(out, "ip saddr @"+name+" "+pp+" accept")
			}
			if info.v6 {
				out = append(out, "ip6 saddr @"+name+"_v6 "+pp+" accept")
			}
		} else if strings.Contains(src, ":") {
			out = append(out, "ip6 saddr "+src+" "+pp+" accept")
		} else {
			out = append(out, "ip saddr "+src+" "+pp+" accept")
		}
	}
	return out // empty (only unknown/empty sets) -> matches nothing (fail-closed)
}

// fwKey identifies one managed port/protocol pair on the forward path.
type fwKey struct{ port, proto string }

// forwardLines renders the forward-hook drops that make the allow-list apply to
// forwarded traffic (Docker-published ports are DNAT'ed and never traverse the
// input chain). A port is only touched when a rule names it explicitly and no
// rule for it allows "any"; rules with port "any" are skipped so a single
// "@set" rule cannot accidentally drop every forwarded flow.
func forwardLines(rules []Rule, idx map[string]setInfo) []string {
	type allowed struct {
		any bool
		v4  []string // nft source terms (sets and literals)
		v6  []string
	}
	order := make([]fwKey, 0, len(rules))
	byKey := make(map[fwKey]*allowed, len(rules))

	for _, r := range rules {
		port := strings.TrimSpace(r.Port)
		if port == "" || port == "any" {
			continue
		}
		proto := strings.ToLower(strings.TrimSpace(r.Protocol))
		if proto == "icmp" {
			continue // nothing is ever published over icmp
		}
		if proto != "tcp" && proto != "udp" {
			proto = "any"
		}
		k := fwKey{port: port, proto: proto}
		a := byKey[k]
		if a == nil {
			a = &allowed{}
			byKey[k] = a
			order = append(order, k)
		}
		tokens := splitSources(r.Source)
		if len(tokens) == 0 || contains(tokens, "any") {
			a.any = true
			continue
		}
		for _, src := range tokens {
			switch {
			case strings.HasPrefix(src, "@"):
				name := strings.TrimPrefix(src, "@")
				info := idx[name]
				if info.v4 {
					a.v4 = append(a.v4, "@"+name)
				}
				if info.v6 {
					a.v6 = append(a.v6, "@"+name+"_v6")
				}
			case strings.Contains(src, ":"):
				a.v6 = append(a.v6, src)
			default:
				a.v4 = append(a.v4, src)
			}
		}
	}

	var out []string
	for _, k := range order {
		a := byKey[k]
		if a.any {
			continue // unrestricted sources: nothing to enforce on the forward path
		}
		pp := portProto(k.port, k.proto)
		switch {
		case len(a.v4) == 0 && len(a.v6) == 0:
			// Every referenced set was missing/empty: mirror the input chain and
			// fail closed for both families.
			out = append(out, "meta nfproto ipv4 "+pp+" drop")
			out = append(out, "meta nfproto ipv6 "+pp+" drop")
		default:
			if len(a.v4) == 0 {
				out = append(out, "meta nfproto ipv4 "+pp+" drop")
			} else {
				out = append(out, negated("ip saddr", a.v4)+" "+pp+" drop")
			}
			if len(a.v6) == 0 {
				out = append(out, "meta nfproto ipv6 "+pp+" drop")
			} else {
				out = append(out, negated("ip6 saddr", a.v6)+" "+pp+" drop")
			}
		}
	}
	return out
}

// negated renders "ip saddr != a ip saddr != b" — i.e. drop the packet unless
// its source matches one of the allowed terms.
func negated(kw string, terms []string) string {
	parts := make([]string, 0, len(terms))
	for _, t := range terms {
		parts = append(parts, kw+" != "+t)
	}
	return strings.Join(parts, " ")
}

func splitSources(s string) []string {
	return strings.FieldsFunc(s, func(r rune) bool {
		return r == ' ' || r == ',' || r == '\t' || r == '\n'
	})
}

func contains(ss []string, v string) bool {
	for _, s := range ss {
		if s == v {
			return true
		}
	}
	return false
}

func runNft(script string, args ...string) (string, error) {
	cmd := exec.Command("nft", args...)
	cmd.Stdin = strings.NewReader(script)
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	err := cmd.Run()
	return out.String(), err
}

// DockerPublished returns "container host:port" entries for every container with
// published ports on this host (empty when Docker is absent or publishes
// nothing). Published ports are DNAT'ed and traverse the forward hook, so they
// are covered only when Options.Forward is set.
func DockerPublished() []string {
	if _, err := exec.LookPath("docker"); err != nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "docker", "ps", "--format", "{{.Names}} {{.Ports}}").Output()
	if err != nil {
		return nil
	}
	var pubs []string
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || !strings.Contains(line, "->") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		name := fields[0]
		for _, f := range fields[1:] {
			if !strings.Contains(f, "->") {
				continue
			}
			pubs = append(pubs, name+" "+strings.SplitN(f, "->", 2)[0])
		}
	}
	return pubs
}

func firstLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}
