// Package acme wraps acme.sh for certificate issuance/renewal and reads the
// deployed PEM to report expiry. HAProxy forwards /.well-known/acme-challenge/
// to acme.sh's standalone server on the configured local port, so HTTP-01
// validation works while HAProxy keeps port 80.
package acme

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/nexpool/hpxnode/internal/models"
)

// Client drives acme.sh.
type Client struct {
	Bin       string // acme.sh path
	CertDir   string
	HTTPPort  string
	Email     string
	ReloadCmd string
}

// NewFromParams builds a Client from explicit values, auto-detecting acme.sh
// when bin is empty.
func NewFromParams(bin, certDir, httpPort, email, reloadCmd string) *Client {
	if bin == "" {
		for _, cand := range []string{"/root/.acme.sh/acme.sh", os.Getenv("HOME") + "/.acme.sh/acme.sh"} {
			if fi, err := os.Stat(cand); err == nil && !fi.IsDir() {
				bin = cand
				break
			}
		}
	}
	return &Client{Bin: bin, CertDir: certDir, HTTPPort: httpPort, Email: email, ReloadCmd: reloadCmd}
}

// Available reports whether acme.sh was found.
func (c *Client) Available() bool {
	if c.Bin == "" {
		return false
	}
	fi, err := os.Stat(c.Bin)
	return err == nil && !fi.IsDir()
}

// Issue requests (or renews) a certificate for the given domains via HTTP-01,
// then deploys it into CertDir with the haproxy deploy hook (which also reloads
// HAProxy). The first domain is the primary/cert name.
func (c *Client) Issue(ctx context.Context, domains []string) error {
	if !c.Available() {
		return fmt.Errorf("acme.sh 未安装（在服务器上先运行安装脚本）")
	}
	if len(domains) == 0 {
		return fmt.Errorf("no domains")
	}
	primary := domains[0]

	args := []string{"--issue", "--standalone", "--httpport", c.HTTPPort}
	for _, d := range domains {
		args = append(args, "-d", d)
	}
	if c.Email != "" {
		args = append(args, "--accountemail", c.Email)
	}
	// acme.sh exits 2 when the cert is present and not yet due for renewal;
	// treat that as success and proceed to (re)deploy.
	if out, err := c.run(ctx, args...); err != nil && !isSkip(out) {
		return fmt.Errorf("签发失败: %s", tail(out))
	}

	deploy := []string{"--deploy", "-d", primary, "--deploy-hook", "haproxy"}
	env := []string{
		"DEPLOY_HAPROXY_PEM_PATH=" + c.CertDir,
		"DEPLOY_HAPROXY_RELOAD=" + c.ReloadCmd,
	}
	if out, err := c.runEnv(ctx, env, deploy...); err != nil {
		return fmt.Errorf("部署失败: %s", tail(out))
	}
	return nil
}

// Renew triggers acme.sh's due-renewal pass (same as the daily cron).
func (c *Client) Renew(ctx context.Context) error {
	if !c.Available() {
		return fmt.Errorf("acme.sh 未安装")
	}
	if out, err := c.run(ctx, "--cron"); err != nil {
		return fmt.Errorf("续期失败: %s", tail(out))
	}
	return nil
}

func (c *Client) run(ctx context.Context, args ...string) (string, error) {
	return c.runEnv(ctx, nil, args...)
}

func (c *Client) runEnv(ctx context.Context, extraEnv []string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, c.Bin, args...)
	cmd.Env = append(os.Environ(), extraEnv...)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func isSkip(out string) bool {
	return strings.Contains(out, "Skipping") || strings.Contains(out, "Next renewal time")
}

func tail(s string) string {
	s = strings.TrimSpace(s)
	lines := strings.Split(s, "\n")
	if len(lines) > 6 {
		lines = lines[len(lines)-6:]
	}
	return strings.Join(lines, " | ")
}

// CertInfo parses <CertDir>/<primary>.pem and reports its expiry. When the file
// is absent it returns Exists=false (no error) so a not-yet-issued site renders
// cleanly.
func CertInfo(certDir, primary string) models.CertInfo {
	info := models.CertInfo{Domain: primary}
	if primary == "" {
		return info
	}
	path := filepath.Join(certDir, primary+".pem")
	raw, err := os.ReadFile(path)
	if err != nil {
		return info // not issued yet
	}

	cert := firstCertificate(raw)
	if cert == nil {
		info.Error = "无法解析证书"
		return info
	}
	info.Exists = true
	info.NotAfter = cert.NotAfter.UTC().Format(time.RFC3339)
	info.DaysLeft = int(time.Until(cert.NotAfter).Hours() / 24)
	info.Issuer = cert.Issuer.CommonName
	if info.Issuer == "" && len(cert.Issuer.Organization) > 0 {
		info.Issuer = cert.Issuer.Organization[0]
	}
	info.SANs = cert.DNSNames
	return info
}

// firstCertificate returns the first CERTIFICATE block parsed from a PEM bundle
// (the leaf), skipping any private key blocks.
func firstCertificate(pemBytes []byte) *x509.Certificate {
	for {
		block, rest := pem.Decode(pemBytes)
		if block == nil {
			return nil
		}
		if block.Type == "CERTIFICATE" {
			if cert, err := x509.ParseCertificate(block.Bytes); err == nil {
				return cert
			}
		}
		pemBytes = rest
	}
}
