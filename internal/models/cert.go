package models

// CertInfo describes a deployed certificate parsed from its PEM on disk. It is a
// plain domain type (no framework deps) so both the panel and the node agent
// can use it.
type CertInfo struct {
	Domain   string   `json:"domain"`
	Exists   bool     `json:"exists"`
	NotAfter string   `json:"not_after,omitempty"`
	DaysLeft int      `json:"days_left"`
	Issuer   string   `json:"issuer,omitempty"`
	SANs     []string `json:"sans,omitempty"`
	Error    string   `json:"error,omitempty"`
}
