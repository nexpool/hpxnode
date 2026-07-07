// Package haproxy renders the local haproxy.cfg from the sites the agent syncs,
// validates it with `haproxy -c`, atomically installs it, and reloads.
package haproxy

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/nexpool/hpxnode/internal/models"
)

// Service applies desired site state to a running HAProxy instance.
type Service struct {
	Bin       string // haproxy binary (for `-c` validation)
	CfgPath   string // target haproxy.cfg
	CertDir   string // directory of SNI certificates
	ACMEPort  string // local acme.sh standalone port
	ReloadCmd string // e.g. "systemctl reload haproxy"
}

// NewFromParams builds a Service from explicit values.
func NewFromParams(bin, cfgPath, certDir, acmePort, reloadCmd string) *Service {
	if bin == "" {
		bin = "haproxy"
	}
	return &Service{Bin: bin, CfgPath: cfgPath, CertDir: certDir, ACMEPort: acmePort, ReloadCmd: reloadCmd}
}

// Generate renders the full haproxy.cfg text for the given enabled sites.
func (s *Service) Generate(sites []models.Site) string {
	var fr, be, acmeFwd, acmeBe strings.Builder
	idx := 0
	leaderIdx := 0
	for i := range sites {
		site := sites[i]
		if !site.Enabled {
			continue
		}
		domains := site.DomainList()
		if len(domains) == 0 || strings.TrimSpace(site.Upstream) == "" {
			continue
		}
		idx++
		name := fmt.Sprintf("be_%d", idx)
		fr.WriteString(fmt.Sprintf("    acl host_%d hdr(host) -i %s\n", idx, strings.Join(domains, " ")))
		fr.WriteString(fmt.Sprintf("    use_backend %s if host_%d\n", name, idx))

		// Group followers forward this site's HTTP-01 challenges to the leader, so
		// that whichever fan-out member Let's Encrypt happens to hit, the token
		// (served by the leader's acme.sh) is reachable.
		if site.Follower() && strings.TrimSpace(site.AcmeLeader) != "" {
			leaderIdx++
			lname := fmt.Sprintf("be_acme_leader_%d", leaderIdx)
			acmeFwd.WriteString(fmt.Sprintf("    acl acme_host_%d hdr(host) -i %s\n", leaderIdx, strings.Join(domains, " ")))
			acmeFwd.WriteString(fmt.Sprintf("    use_backend %s if is_acme acme_host_%d\n", lname, leaderIdx))
			acmeBe.WriteString(fmt.Sprintf("backend %s\n", lname))
			acmeBe.WriteString(fmt.Sprintf("    server leader %s:80\n\n", strings.TrimSpace(site.AcmeLeader)))
		}

		var hostLine string
		switch site.HostMode {
		case models.HostKeep:
			hostLine = "    # keep client Host"
		case models.HostCustom:
			hostLine = "    http-request set-header Host " + strings.TrimSpace(site.HostHeader)
		default: // upstream
			hostLine = "    http-request set-header Host " + site.Upstream
		}

		be.WriteString(fmt.Sprintf("backend %s\n", name))
		be.WriteString("    http-request set-header X-Real-IP %[src]\n")
		be.WriteString("    http-request set-header X-Forwarded-Proto https\n")
		be.WriteString(hostLine + "\n")
		be.WriteString("    server s1 " + site.Upstream + "\n\n")
	}

	return fmt.Sprintf(`global
    log /dev/log local0
    maxconn 20000
    ssl-default-bind-options ssl-min-ver TLSv1.2 no-tls-tickets
    tune.ssl.default-dh-param 2048

defaults
    mode http
    log global
    option httplog
    option forwardfor
    timeout connect 5s
    timeout client  60s
    timeout server  60s

frontend fe_http
    bind :80
    acl is_acme path_beg /.well-known/acme-challenge/
    http-request redirect scheme https code 301 unless is_acme
%s    use_backend be_acme if is_acme

frontend fe_https
    bind :443 ssl crt %s/
%s    default_backend be_default

%s%sbackend be_default
    http-request return status 404 content-type "text/plain" string "404 Not Found"

backend be_acme
    server acmesh 127.0.0.1:%s
`, acmeFwd.String(), s.CertDir, fr.String(), be.String(), acmeBe.String(), s.ACMEPort)
}

// Validate writes cfg to a temp file and runs `haproxy -c`. It returns the
// combined tool output on failure so the caller can surface it.
func (s *Service) Validate(cfg string) error {
	tmp, err := os.CreateTemp("", "haproxy-*.cfg")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.WriteString(cfg); err != nil {
		tmp.Close()
		return err
	}
	tmp.Close()

	out, err := exec.Command(s.Bin, "-c", "-f", tmp.Name()).CombinedOutput()
	if err != nil {
		return fmt.Errorf("haproxy -c failed: %s", strings.TrimSpace(string(out)))
	}
	return nil
}

// ValidateFile runs `haproxy -c` against the installed config file on disk.
func (s *Service) ValidateFile() error {
	out, err := exec.Command(s.Bin, "-c", "-f", s.CfgPath).CombinedOutput()
	if err != nil {
		return fmt.Errorf("haproxy -c failed: %s", strings.TrimSpace(string(out)))
	}
	return nil
}

// Apply renders, validates, atomically installs the config, then reloads.
func (s *Service) Apply(sites []models.Site) error {
	cfg := s.Generate(sites)
	if err := s.Validate(cfg); err != nil {
		return err
	}
	if err := s.write(cfg); err != nil {
		return err
	}
	return s.Reload()
}

// write installs cfg atomically (temp file in the same dir + rename).
func (s *Service) write(cfg string) error {
	dir := filepath.Dir(s.CfgPath)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".haproxy-*.cfg")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	if _, err := tmp.WriteString(cfg); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return err
	}
	tmp.Close()
	return os.Rename(tmpName, s.CfgPath)
}

// Reload runs the configured reload command. It is a no-op-safe wrapper: if the
// command is empty it does nothing.
func (s *Service) Reload() error {
	fields := strings.Fields(s.ReloadCmd)
	if len(fields) == 0 {
		return nil
	}
	out, err := exec.Command(fields[0], fields[1:]...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("reload failed: %s", strings.TrimSpace(string(out)))
	}
	return nil
}

// Running reports whether an haproxy process is active (best-effort via pgrep).
func (s *Service) Running() bool {
	if err := exec.Command("pgrep", "-x", "haproxy").Run(); err == nil {
		return true
	}
	return false
}

// Version returns the haproxy version string (first line of `haproxy -v`).
func (s *Service) Version() string {
	out, err := exec.Command(s.Bin, "-v").Output()
	if err != nil {
		return ""
	}
	line := strings.SplitN(strings.TrimSpace(string(out)), "\n", 2)[0]
	return line
}
