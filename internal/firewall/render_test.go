package firewall

import (
	"strings"
	"testing"
)

// forwardSection returns everything from the forward chain on, so tests can
// assert on the forward chain alone.
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
	if !strings.Contains(fwd, "ct status dnat ip saddr != @edge meta l4proto tcp ct original proto-dst 9088 drop") {
		t.Fatalf("v4 drop for non-allowed sources missing: %v", fwd)
	}
	if !strings.Contains(fwd, "ct status dnat meta nfproto ipv6 meta l4proto tcp ct original proto-dst 9088 drop") {
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

// A published (DNAT'ed) port that no rule allows is closed, exactly like an
// inbound port: "firewall enabled + only 22/80/443 allowed" must also close a
// Docker-published 9099.
func TestPublishedPortsAreDefaultDenied(t *testing.T) {
	out := render(
		[]Rule{
			{Port: "22", Protocol: "tcp", Source: "any"},
			{Port: "80", Protocol: "tcp", Source: "any"},
			{Port: "443", Protocol: "tcp", Source: "any"},
		},
		nil,
		Options{Forward: true, Published: []Endpoint{{Port: "9088", Proto: "tcp"}, {Port: "9099", Proto: "tcp"}}},
	)
	fwd := forwardSection(t, out)
	for _, want := range []string{
		"ct status dnat meta l4proto tcp ct original proto-dst 9088 drop",
		"ct status dnat meta l4proto tcp ct original proto-dst 9099 drop",
	} {
		if !strings.Contains(fwd, want) {
			t.Fatalf("published port not default-denied (%s): %v", want, fwd)
		}
	}
}

// A rule that allows the published port keeps it open.
func TestPublishedPortAllowedByRule(t *testing.T) {
	out := render(
		[]Rule{{Port: "9088", Protocol: "tcp", Source: "any"}},
		nil,
		Options{Forward: true, Published: []Endpoint{{Port: "9088", Proto: "tcp"}}},
	)
	if forwardSection(t, out) != "" {
		t.Fatalf("allowed published port must not be default-denied: %v", out)
	}
}

// A source-restricted rule for the published port already drops the other
// sources; no blanket default-deny may be added on top.
func TestPublishedPortRestrictedRuleNotDuplicated(t *testing.T) {
	out := render(
		[]Rule{{Port: "9088", Protocol: "tcp", Source: "@edge"}},
		[]IPSet{{Name: "edge", CIDRs: []string{"203.0.113.7"}}},
		Options{Forward: true, Published: []Endpoint{{Port: "9088", Proto: "tcp"}}},
	)
	fwd := forwardSection(t, out)
	if !strings.Contains(fwd, "ip saddr != @edge") {
		t.Fatalf("restricted drop missing: %v", fwd)
	}
	if strings.Contains(fwd, "ct status dnat meta l4proto tcp ct original proto-dst 9088 drop") {
		t.Fatalf("restricted port must not also get a blanket drop: %v", fwd)
	}
}

// A rule for a different protocol does not cover the published one.
func TestPublishedPortProtoNotCovered(t *testing.T) {
	out := render(
		[]Rule{{Port: "9099", Protocol: "udp", Source: "any"}},
		nil,
		Options{Forward: true, Published: []Endpoint{{Port: "9099", Proto: "tcp"}}},
	)
	if !strings.Contains(forwardSection(t, out), "ct status dnat meta l4proto tcp ct original proto-dst 9099 drop") {
		t.Fatalf("tcp must stay default-denied when only udp is allowed: %v", out)
	}
}

// An "allow everything" rule disables the published-port default deny.
func TestPublishedPortsAllowAllRule(t *testing.T) {
	out := render(
		[]Rule{{Port: "any", Protocol: "any", Source: "any"}},
		nil,
		Options{Forward: true, Published: []Endpoint{{Port: "9099", Proto: "tcp"}}},
	)
	if forwardSection(t, out) != "" {
		t.Fatalf("allow-all rule must disable published-port drops: %v", out)
	}
}

// Published port ranges are spelled as two ct comparisons.
func TestPublishedPortRange(t *testing.T) {
	out := render(nil, nil, Options{Forward: true, Published: []Endpoint{{Port: "5000-5005", Proto: "udp"}}})
	if !strings.Contains(forwardSection(t, out), "ct status dnat meta l4proto udp ct original proto-dst >= 5000 ct original proto-dst <= 5005 drop") {
		t.Fatalf("published range not rendered: %v", out)
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
	if !strings.Contains(fwd, "ct status dnat ip saddr != 198.51.100.4 meta l4proto udp ct original proto-dst >= 8000 ct original proto-dst <= 8010 drop") {
		t.Fatalf("v4 literal/range drop missing: %v", fwd)
	}
	if !strings.Contains(fwd, "ct status dnat ip6 saddr != 2001:db8::/32 meta l4proto udp ct original proto-dst >= 8000 ct original proto-dst <= 8010 drop") {
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
	if !strings.Contains(forwardSection(t, out), "ct status dnat ip saddr != @edge meta l4proto { tcp, udp } ct original proto-dst 443 drop") {
		t.Fatalf("any-proto forward drop missing: %v", out)
	}
}

func TestParsePublished(t *testing.T) {
	got := parsePublished("0.0.0.0:9088->9088/tcp, :::9088->9088/tcp, 127.0.0.1:5000->5000/udp")
	want := []Endpoint{{Port: "9088", Proto: "tcp"}, {Port: "5000", Proto: "udp"}}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %v, want %v", got, want)
		}
	}
	if p := parsePublished("8000/tcp"); len(p) != 0 {
		t.Fatalf("exposed-but-not-published port must be ignored: %v", p)
	}
	if p := parsePublished("0.0.0.0:5000-5005->5000-5005/tcp"); len(p) != 1 || p[0].Port != "5000-5005" {
		t.Fatalf("range mapping not parsed: %v", p)
	}
}

func TestSummarizeCountsPublishedDrops(t *testing.T) {
	st := Summarize(
		[]Rule{{Port: "22", Protocol: "tcp", Source: "any"}},
		nil,
		Options{Forward: true, Published: []Endpoint{{Port: "9099", Proto: "tcp"}}},
	)
	if st.Accepts != 1 || st.ForwardDrops != 1 {
		t.Fatalf("stats = %+v, want 1 accept + 1 forward drop", st)
	}
}
