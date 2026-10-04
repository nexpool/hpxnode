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
	"log"
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
	// Server is the ACME CA: "letsencrypt" (default), "zerossl", "buypass",
	// "google", or a full directory URL. Passed explicitly on every issue so the
	// node never depends on acme.sh's persisted default CA (which is ZeroSSL and
	// requires prior email registration).
	Server string
}

// NewFromParams builds a Client from explicit values, auto-detecting acme.sh
// when bin is empty.
func NewFromParams(bin, certDir, httpPort, email, reloadCmd, server string) *Client {
	if bin == "" {
		for _, cand := range []string{"/root/.acme.sh/acme.sh", os.Getenv("HOME") + "/.acme.sh/acme.sh"} {
			if fi, err := os.Stat(cand); err == nil && !fi.IsDir() {
				bin = cand
				break
			}
		}
	}
	if server == "" {
		server = "letsencrypt"
	}
	return &Client{Bin: bin, CertDir: certDir, HTTPPort: httpPort, Email: email, ReloadCmd: reloadCmd, Server: server}
}

// Available reports whether acme.sh was found.
func (c *Client) Available() bool {
	if c.Bin == "" {
		return false
	}
	fi, err := os.Stat(c.Bin)
	return err == nil && !fi.IsDir()
}

// ForceRenewDays is how close to expiry a certificate must be before the node
// agent actively forces a renewal. acme.sh's own cron already renews around 29
// days after issuance (DEFAULT_RENEW=30, anchored to issuance), but that cron is
// a single point of failure: if it never runs, or its --home points at a
// different acme.sh store, the certificate quietly expires. This threshold is the
// agent's safety net and is deliberately looser than acme.sh's own window so the
// two do not fight over the same certificate.
const ForceRenewDays = 25

// Issue requests a certificate for the given domains via HTTP-01 and then deploys
// it into CertDir with the haproxy deploy hook (which also reloads HAProxy). The
// first domain is the primary/cert name.
func (c *Client) Issue(ctx context.Context, domains []string) error {
	if len(domains) == 0 {
		return fmt.Errorf("no domains")
	}
	if err := c.issue(ctx, domains, false); err != nil {
		return err
	}
	return c.deploy(ctx, domains[0])
}

// issue runs `acme.sh --issue` only; it never touches the deployed PEM. For a
// certificate that already exists and is not yet due, acme.sh exits 2 ("Skipping")
// and writes nothing, which is treated as success.
func (c *Client) issue(ctx context.Context, domains []string, force bool) error {
	if !c.Available() {
		return fmt.Errorf("acme.sh 未安装（在服务器上先运行安装脚本）")
	}
	server := c.Server
	if server == "" {
		server = "letsencrypt"
	}
	args := []string{"--issue", "--server", server, "--standalone", "--httpport", c.HTTPPort}
	for _, d := range domains {
		args = append(args, "-d", d)
	}
	if c.Email != "" {
		args = append(args, "--accountemail", c.Email)
	}
	if force {
		args = append(args, "--force")
	}
	out, err := c.run(ctx, args...)
	if err != nil && !isSkip(out) {
		return fmt.Errorf("签发失败: %s", tail(out))
	}
	return nil
}

// deploy installs the certificate into CertDir via acme.sh's haproxy deploy hook.
// The hook persists DEPLOY_HAPROXY_PEM_PATH and DEPLOY_HAPROXY_RELOAD into the
// domain config, so acme.sh's own cron renewals keep writing to the right place
// and keep reloading HAProxy even though cron runs with a bare environment.
func (c *Client) deploy(ctx context.Context, primary string) error {
	if !c.Available() {
		return fmt.Errorf("acme.sh 未安装")
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

// Renew force-reissues a certificate that is close to expiry, deploys it, and
// reloads HAProxy through the deploy hook. It is the agent-side safety net for a
// broken acme.sh cron, so it must not trust any single step:
//
//   - acme.sh only renews when it considers the cert due, so --force is required;
//     without it a not-yet-due cert exits 2 and nothing changes.
//   - the haproxy deploy hook writes the live PEM with an in-place truncating
//     redirect (no rename), so a reload racing that write can read an empty or
//     partial bundle. We therefore re-install the PEM atomically before reloading.
//   - a "successful" acme.sh exit does not prove the file changed, so we compare
//     the expiry before and after and fail loudly when it did not.
func (c *Client) Renew(ctx context.Context, domains []string) error {
	if len(domains) == 0 {
		return fmt.Errorf("no domains")
	}
	primary := domains[0]
	path := filepath.Join(c.CertDir, primary+".pem")
	before, _ := os.ReadFile(path)
	beforeInfo := CertInfo(c.CertDir, primary)

	if err := c.issue(ctx, domains, true); err != nil {
		return err
	}
	if err := c.deploy(ctx, primary); err != nil {
		return err
	}

	after, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("续期后读取 %s 失败: %w", path, err)
	}
	afterInfo := CertInfo(c.CertDir, primary)
	if !afterInfo.Exists {
		return fmt.Errorf("续期后 %s 不是合法证书", path)
	}
	if string(after) == string(before) {
		return fmt.Errorf("续期后证书未变化（仍是 %s 到期）", afterInfo.NotAfter)
	}

	// Re-install atomically so the reload below can never observe a truncated PEM.
	if err := writeAtomic(path, after, 0o600); err != nil {
		return fmt.Errorf("原子写入 %s 失败: %w", path, err)
	}
	log.Printf("renewed %s: %s -> %s (%d days left)", primary, beforeInfo.NotAfter, afterInfo.NotAfter, afterInfo.DaysLeft)
	if err := c.Reload(); err != nil {
		return fmt.Errorf("续期成功但 reload 失败: %w", err)
	}
	return nil
}

// writeAtomic writes data to path via a temp file + rename in the same directory.
func writeAtomic(path string, data []byte, mode os.FileMode) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".pem-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		os.Remove(name)
		return err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(name)
		return err
	}
	if err := os.Chmod(name, mode); err != nil {
		os.Remove(name)
		return err
	}
	return os.Rename(name, path)
}

// Reload runs the configured HAProxy reload command. The deploy hook already
// reloads on deploy; this is for the atomic re-install path in Renew, where the
// hook's own reload has already happened but the file has been replaced again.
func (c *Client) Reload() error {
	fields := strings.Fields(c.ReloadCmd)
	if len(fields) == 0 {
		return nil // nothing configured: nothing to do
	}
	out, err := exec.Command(fields[0], fields[1:]...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("reload 失败: %s", strings.TrimSpace(string(out)))
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
