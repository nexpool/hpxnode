package firewall

import (
	"strings"
	"testing"
)

// forwardSection returns everything after the input chain, so tests can assert on
// the forward chain alone.
func forwardSection(t *testing.T, out string) string {
	t.Helper()
	i := strings.Index(out, "chain forward")
	if i < 0 {
		return ""
	}
	return out[i:]
}

// A rule whose IP set was not sent (deleted or disabled in the panel) must render
// no accept line: with the default-deny policy that port stays closed.
func TestRenderMissingSetFailsClosed(t *testing.T) {
	out := render([]Rule{{Port: "9088", Protocol: "tcp", Source: "@gone"}}, nil, Options{})
	if strings.Contains(out, "9088") {
		t.Fatalf("missing set must not produce an accept rule: %v", out)
	}
	if !strings.Contains(out, "policy drop") {
		t.Fatalf("chain must stay default-deny: %v", out)
	}
}

func TestRenderIPSetRule(t *testing.T) {
	out := render(
		[]Rule{{Port: "9088", Protocol: "tcp", Source: "@edge"}},
		[]IPSet{{Name: "edge", CIDRs: []string{"203.0.113.7"}}},
		Options{},
	)
	if !strings.Contains(out, "ip saddr @edge tcp dport 9088 accept") {
		t.Fatalf("unexpected script: %v", out)
	}
	if !strings.Contains(out, "elements = { 203.0.113.7 }") {
		t.Fatalf("set elements missing: %v", out)
	}
}

// A disabled managed firewall must only delete our table, never leave rules on.
func TestRenderDisabledRemovesTable(t *testing.T) {
	script := removeScript()
	if !strings.Contains(script, "delete table inet hzproxy_fw") {
		t.Fatalf("unexpected remove script: %v", script)
	}
}

func TestRenderNoForwardChainByDefault(t *testing.T) {
	out := render(
		[]Rule{{Port: "9088", Protocol: "tcp", Source: "@edge"}},
		[]IPSet{{Name: "edge", CIDRs: []string{"203.0.113.7"}}},
		Options{},
	)
	if forwardSection(t, out) != "" {
		t.Fatalf("forward chain must be opt-in: %v", out)
	}
}

// Docker-published ports are DNAT'ed and never traverse the input chain, so the
// allow-list is mirrored as explicit drops on the forward hook (policy accept).
func TestRenderForwardEnforcesAllowList(t *testing.T) {
	out := render(
		[]Rule{{Port: "9088", Protocol: "tcp", Source: "@edge"}},
		[]IPSet{{Name: "edge", CIDRs: []string{"203.0.113.7"}}},
		Options{Forward: true},
	)
	fwd := forwardSection(t, out)
	if fwd == "" {
		t.Fatalf("forward chain missing: %v", out)
	}
	if !strings.Contains(fwd, "type filter hook forward priority -10; policy accept;") {
		t.Fatalf("forward chain must stay default-accept: %v", fwd)
	}
	if !strings.Contains(fwd, "ip saddr != @edge meta l4proto tcp ct original proto-dst 9088 drop") {
		t.Fatalf("v4 drop for non-allowed sources missing: %v", fwd)
	}
	if !strings.Contains(fwd, "meta nfproto ipv6 meta l4proto tcp ct original proto-dst 9088 drop") {
		t.Fatalf("v6 must be closed when the set has no v6 members: %v", fwd)
	}
	if !strings.Contains(out, "ip saddr @edge tcp dport 9088 accept") {
		t.Fatalf("input chain accept missing: %v", out)
	}
}

// The forward hook sees the post-DNAT packet, so it must match the conntrack
// original destination port (the published host port) and never the translated
// container port.
func TestRenderForwardMatchesPublishedPortNotContainerPort(t *testing.T) {
	out := render(
		[]Rule{{Port: "9088", Protocol: "tcp", Source: "@edge"}},
		[]IPSet{{Name: "edge", CIDRs: []string{"203.0.113.7"}}},
		Options{Forward: true},
	)
	fwd := forwardSection(t, out)
	if strings.Contains(fwd, "tcp dport") || strings.Contains(fwd, "udp dport") {
		t.Fatalf("forward chain must not match the translated dport: %v", fwd)
	}
	if !strings.Contains(fwd, "ct original proto-dst 9088") {
		t.Fatalf("forward chain must match the published port: %v", fwd)
	}
}

// An "any" source allows everyone, so nothing may be dropped on the forward path.
func TestRenderForwardSkipsUnrestricted(t *testing.T) {
	out := render([]Rule{{Port: "9088", Protocol: "tcp", Source: "any"}}, nil, Options{Forward: true})
	if forwardSection(t, out) != "" {
		t.Fatalf("unrestricted rule must not add forward drops: %v", out)
	}
}

// Rules without an explicit port are ignored on the forward path so a single
// "@set" rule cannot drop every forwarded flow.
func TestRenderForwardSkipsAnyPort(t *testing.T) {
	out := render([]Rule{{Port: "any", Protocol: "tcp", Source: "@edge"}}, []IPSet{{Name: "edge", CIDRs: []string{"203.0.113.7"}}}, Options{Forward: true})
	if forwardSection(t, out) != "" {
		t.Fatalf("port=any must not produce forward drops: %v", out)
	}
}

// Literal CIDR sources are enforced on the forward path as well, and port ranges
// are spelled as two comparisons (valid on ct keys).
func TestRenderForwardLiteralSources(t *testing.T) {
	out := render(
		[]Rule{{Port: "8000-8010", Protocol: "udp", Source: "198.51.100.4 2001:db8::/32"}},
		nil,
		Options{Forward: true},
	)
	fwd := forwardSection(t, out)
	if !strings.Contains(fwd, "ip saddr != 198.51.100.4 meta l4proto udp ct original proto-dst >= 8000 ct original proto-dst <= 8010 drop") {
		t.Fatalf("v4 literal/range drop missing: %v", fwd)
	}
	if !strings.Contains(fwd, "ip6 saddr != 2001:db8::/32 meta l4proto udp ct original proto-dst >= 8000 ct original proto-dst <= 8010 drop") {
		t.Fatalf("v6 literal/range drop missing: %v", fwd)
	}
}

// tcp+udp rules keep both protocols in the forward match.
func TestRenderForwardAnyProto(t *testing.T) {
	out := render(
		[]Rule{{Port: "443", Protocol: "any", Source: "@edge"}},
		[]IPSet{{Name: "edge", CIDRs: []string{"203.0.113.7"}}},
		Options{Forward: true},
	)
	if !strings.Contains(forwardSection(t, out), "ip saddr != @edge meta l4proto { tcp, udp } ct original proto-dst 443 drop") {
		t.Fatalf("any-proto forward drop missing: %v", out)
	}
}
