package firewall

import (
	"strings"
	"testing"
)

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
	if strings.Contains(out, "chain forward") {
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
	if !strings.Contains(out, "chain forward") {
		t.Fatalf("forward chain missing: %v", out)
	}
	if !strings.Contains(out, "type filter hook forward priority -10; policy accept;") {
		t.Fatalf("forward chain must stay default-accept: %v", out)
	}
	if !strings.Contains(out, "ip saddr != @edge tcp dport 9088 drop") {
		t.Fatalf("v4 drop for non-allowed sources missing: %v", out)
	}
	if !strings.Contains(out, "meta nfproto ipv6 tcp dport 9088 drop") {
		t.Fatalf("v6 must be closed when the set has no v6 members: %v", out)
	}
	if !strings.Contains(out, "ip saddr @edge tcp dport 9088 accept") {
		t.Fatalf("input chain accept missing: %v", out)
	}
}

// An "any" source allows everyone, so nothing may be dropped on the forward path.
func TestRenderForwardSkipsUnrestricted(t *testing.T) {
	out := render([]Rule{{Port: "9088", Protocol: "tcp", Source: "any"}}, nil, Options{Forward: true})
	if strings.Contains(out, "chain forward") {
		t.Fatalf("unrestricted rule must not add forward drops: %v", out)
	}
}

// Rules without an explicit port are ignored on the forward path so a single
// "@set" rule cannot drop every forwarded flow.
func TestRenderForwardSkipsAnyPort(t *testing.T) {
	out := render([]Rule{{Port: "any", Protocol: "tcp", Source: "@edge"}}, []IPSet{{Name: "edge", CIDRs: []string{"203.0.113.7"}}}, Options{Forward: true})
	if strings.Contains(out, "chain forward") {
		t.Fatalf("port=any must not produce forward drops: %v", out)
	}
}

// Literal CIDR sources are enforced on the forward path as well.
func TestRenderForwardLiteralSources(t *testing.T) {
	out := render(
		[]Rule{{Port: "8000-8010", Protocol: "udp", Source: "198.51.100.4 2001:db8::/32"}},
		nil,
		Options{Forward: true},
	)
	if !strings.Contains(out, "ip saddr != 198.51.100.4 udp dport 8000-8010 drop") {
		t.Fatalf("v4 literal drop missing: %v", out)
	}
	if !strings.Contains(out, "ip6 saddr != 2001:db8::/32 udp dport 8000-8010 drop") {
		t.Fatalf("v6 literal drop missing: %v", out)
	}
}
