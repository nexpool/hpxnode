package haproxy

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nexpool/hpxnode/internal/models"
)

// TestGenerateGroupConfigs renders single-node, leader, and follower sites,
// asserts the follower forwards HTTP-01 to the leader, and (when haproxy is
// installed) validates the output with `haproxy -c`.
func TestGenerateGroupConfigs(t *testing.T) {
	certDir := t.TempDir()
	s := NewFromParams("haproxy", filepath.Join(t.TempDir(), "haproxy.cfg"), certDir, "8080", "")
	sites := []models.Site{
		{Domains: "single.com,www.single.com", Upstream: "127.0.0.1:3000", HostMode: "upstream", Enabled: true, IsLeader: true},
		{Domains: "cdn.com,www.cdn.com", Upstream: "10.0.0.5:8080", HostMode: "keep", Enabled: true, IsLeader: true},                                                            // leader
		{Domains: "cdn2.com", Upstream: "10.0.0.6:8080", HostMode: "custom", HostHeader: "origin.cdn2.com", Enabled: true, IsLeader: false, AcmeLeader: "203.0.113.7", CertPEM: "x"}, // follower
	}
	cfg := s.Generate(sites)

	for _, want := range []string{
		"acl acme_host_1 hdr(host) -i cdn2.com",
		"use_backend be_acme_leader_1 if is_acme acme_host_1",
		"server leader 203.0.113.7:80",
	} {
		if !strings.Contains(cfg, want) {
			t.Errorf("config missing %q\n---\n%s", want, cfg)
		}
	}
	// Only the one follower forwards; leader/single sites do not.
	if strings.Count(cfg, "be_acme_leader_") != 2 { // one acl-line ref + one backend def
		t.Errorf("expected exactly one follower forward, got:\n%s", cfg)
	}

	hb, err := exec.LookPath("haproxy")
	if err != nil {
		t.Skipf("haproxy not installed, skipping -c validation")
	}
	// A cert must exist for the :443 bind's crt dir.
	if err := writeSelfSigned(filepath.Join(certDir, "single.com.pem")); err != nil {
		t.Skipf("openssl unavailable (%v), skipping -c validation", err)
	}
	tmp := filepath.Join(t.TempDir(), "test.cfg")
	if err := os.WriteFile(tmp, []byte(cfg), 0o644); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command(hb, "-c", "-f", tmp).CombinedOutput(); err != nil {
		t.Fatalf("haproxy -c rejected config: %s\n---\n%s", string(out), cfg)
	}
}

func writeSelfSigned(pemPath string) error {
	dir := filepath.Dir(pemPath)
	key := filepath.Join(dir, "k.tmp")
	crt := filepath.Join(dir, "c.tmp")
	defer os.Remove(key)
	defer os.Remove(crt)
	if err := exec.Command("openssl", "req", "-x509", "-newkey", "rsa:2048",
		"-keyout", key, "-out", crt, "-days", "2", "-nodes", "-subj", "/CN=test").Run(); err != nil {
		return err
	}
	kb, err := os.ReadFile(key)
	if err != nil {
		return err
	}
	cb, err := os.ReadFile(crt)
	if err != nil {
		return err
	}
	return os.WriteFile(pemPath, append(cb, kb...), 0o600)
}
