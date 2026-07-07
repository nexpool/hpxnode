// Package firewall applies the node's inbound OS firewall using nftables. It
// manages a single dedicated table (inet hproxy_fw) and never touches other
// tables, so it composes with (or leaves alone) whatever else is configured.
//
// Safety: the agent connects OUTBOUND to the panel, and this firewall only
// filters INBOUND — so applying it can never cut the agent off. Even a
// lock-yourself-out ruleset is recoverable by fixing the rules in the panel; the
// agent will re-apply on the next sync. Loopback and established/related are
// always accepted, so existing SSH sessions survive a policy change.
package firewall

import (
	"bytes"
	"fmt"
	"os/exec"
	"strings"
)

const tableName = "inet hproxy_fw"

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

// Apply installs (enabled) or removes (disabled) the managed firewall table.
func Apply(enabled bool, rules []Rule, sets []IPSet) error {
	if !Available() {
		if !enabled {
			return nil
		}
		return fmt.Errorf("nftables(nft) 未安装，无法启用防火墙")
	}
	script := removeScript()
	if enabled {
		script = render(rules, sets)
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
func render(rules []Rule, sets []IPSet) string {
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
	b.WriteString("  }\n}\n")
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

func firstLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}
