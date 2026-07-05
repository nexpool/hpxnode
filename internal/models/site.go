package models

import "strings"

// Host header modes for a proxied site.
const (
	HostUpstream = "upstream" // rewrite Host to the upstream host:port
	HostKeep     = "keep"     // forward the client's Host unchanged
	HostCustom   = "custom"   // set Host to a fixed value (HostHeader)
)

// Site is the agent's view of one reverse-proxied vhost synced from the panel.
type Site struct {
	Domains    string // comma-separated, first is the primary/cert name
	Upstream   string // host:port
	HostMode   string // upstream|keep|custom
	HostHeader string // used when HostMode == custom
	Enabled    bool
}

// DomainList splits Domains into a trimmed, non-empty slice.
func (s *Site) DomainList() []string {
	parts := strings.Split(s.Domains, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if d := strings.TrimSpace(p); d != "" {
			out = append(out, d)
		}
	}
	return out
}

// Primary returns the first (primary) domain, or "" when none.
func (s *Site) Primary() string {
	list := s.DomainList()
	if len(list) == 0 {
		return ""
	}
	return list[0]
}
