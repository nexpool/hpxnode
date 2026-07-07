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

	// Node-group (CDN-style) fan-out fields.
	//   IsLeader true  -> this node issues the cert (single-node or group leader).
	//   IsLeader false -> group follower: don't issue; install CertPEM and forward
	//                     HTTP-01 challenges for these domains to AcmeLeader:80.
	IsLeader   bool
	AcmeLeader string // leader host to forward acme-challenge to (followers only)
	CertPEM    string // leader-issued cert (fullchain+key) to install (followers only)
}

// Follower reports whether this node only serves the site (its cert was issued
// elsewhere in the group and distributed here).
func (s *Site) Follower() bool { return !s.IsLeader }

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
