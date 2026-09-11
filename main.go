// Command hpxnode is the HAProxy node agent. It runs on each HAProxy server,
// connects to the panel over gRPC, pulls the sites assigned to this node,
// renders/validates/reloads the local haproxy.cfg, issues Let's Encrypt
// certificates with acme.sh, and reports runtime status back.
//
// Config is via flags or env:
//   PANEL_GRPC   panel gRPC address (host:port), e.g. panel.example.com:9099
//   NODE_ID      numeric node id from the panel
//   NODE_SECRET  node secret from the panel
//   HAPROXY_CFG  /etc/haproxy/haproxy.cfg
//   CERT_DIR     /etc/haproxy/certs
//   ACME_HTTP_PORT 8080
//   RELOAD_CMD   "systemctl reload haproxy"
//   FIREWALL_FORWARD  1 (default) also filters forwarded traffic, so firewall
//                     rules cover Docker-published (DNAT'ed) ports; 0 = input only
package main

import (
	"context"
	"flag"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/nexpool/hpxnode/internal/acme"
	"github.com/nexpool/hpxnode/internal/firewall"
	"github.com/nexpool/hpxnode/internal/haproxy"
	"github.com/nexpool/hpxnode/internal/models"
	pb "github.com/nexpool/hpxnode/pb"
)

var version = "dev"

func env(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// nodeCreds attaches the node-id/node-secret metadata to every gRPC call.
type nodeCreds struct{ id, secret string }

func (c nodeCreds) GetRequestMetadata(context.Context, ...string) (map[string]string, error) {
	return map[string]string{"node-id": c.id, "node-secret": c.secret}, nil
}
func (nodeCreds) RequireTransportSecurity() bool { return false }

type agent struct {
	cli       pb.NodeServiceClient
	hp        *haproxy.Service
	ac        *acme.Client
	certDir   string
	revKnown  bool
	revision  uint64
	lastSites []models.Site
	fwErr     string            // last firewall apply error ("" = ok)
	fwNote    string            // non-fatal firewall note (e.g. Docker-published ports)
	fwForward bool              // also enforce the rules on forwarded (DNAT/Docker) traffic
	reported  map[string]string // domain -> last-uploaded cert PEM (leader)
}

func main() {
	panelAddr := flag.String("panel", env("PANEL_GRPC", ""), "panel gRPC address host:port")
	nodeID := flag.String("id", env("NODE_ID", ""), "node id")
	secret := flag.String("secret", env("NODE_SECRET", ""), "node secret")
	flag.Parse()

	if *panelAddr == "" || *nodeID == "" || *secret == "" {
		log.Fatal("需要 --panel / --id / --secret (或环境变量 PANEL_GRPC / NODE_ID / NODE_SECRET)")
	}
	if _, err := strconv.Atoi(*nodeID); err != nil {
		log.Fatalf("无效 node id: %s", *nodeID)
	}

	certDir := env("CERT_DIR", "/etc/haproxy/certs")
	reload := env("RELOAD_CMD", "systemctl reload haproxy")
	acmePort := env("ACME_HTTP_PORT", "8080")
	hp := haproxy.NewFromParams(env("HAPROXY_BIN", "haproxy"), env("HAPROXY_CFG", "/etc/haproxy/haproxy.cfg"), certDir, acmePort, reload)
	ac := acme.NewFromParams(env("ACME_SH", ""), certDir, acmePort, "", reload, env("ACME_SERVER", "letsencrypt"))

	conn, err := grpc.NewClient(*panelAddr,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithPerRPCCredentials(nodeCreds{id: *nodeID, secret: *secret}),
	)
	if err != nil {
		log.Fatalf("dial panel: %v", err)
	}
	defer conn.Close()

	a := &agent{
		cli:       pb.NewNodeServiceClient(conn),
		hp:        hp,
		ac:        ac,
		certDir:   certDir,
		reported:  map[string]string{},
		fwForward: env("FIREWALL_FORWARD", "1") != "0",
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	hbEvery := time.Duration(atoiDef(env("HEARTBEAT_SECONDS", "10"), 10)) * time.Second
	statEvery := time.Duration(atoiDef(env("STATUS_SECONDS", "30"), 30)) * time.Second

	log.Printf("hpxnode %s connected to %s (node %s)", version, *panelAddr, *nodeID)
	a.heartbeat(ctx, true) // force an initial sync
	a.report(ctx)

	hb := time.NewTicker(hbEvery)
	defer hb.Stop()
	st := time.NewTicker(statEvery)
	defer st.Stop()
	for {
		select {
		case <-ctx.Done():
			log.Println("hpxnode stopped")
			return
		case <-hb.C:
			a.heartbeat(ctx, false)
		case <-st.C:
			a.report(ctx)
		}
	}
}

// heartbeat checks in and re-syncs when the revision changed (or force).
func (a *agent) heartbeat(ctx context.Context, force bool) {
	rctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	reply, err := a.cli.Heartbeat(rctx, &pb.HeartbeatRequest{
		AgentVersion:   version,
		Os:             runtime.GOOS,
		HaproxyVersion: a.hp.Version(),
	})
	if err != nil {
		log.Printf("heartbeat: %v", err)
		return
	}
	if force || !a.revKnown || reply.GetConfigRevision() != a.revision {
		a.sync(ctx)
	}
}

// sync pulls the desired sites, applies the config, and issues missing certs.
func (a *agent) sync(ctx context.Context) {
	rctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	reply, err := a.cli.Sync(rctx, &pb.SyncRequest{})
	cancel()
	if err != nil {
		log.Printf("sync: %v", err)
		return
	}
	a.ac.Email = reply.GetAcmeEmail()

	sites := make([]models.Site, 0, len(reply.GetSites()))
	for _, s := range reply.GetSites() {
		sites = append(sites, models.Site{
			Domains:    s.GetDomains(),
			Upstream:   s.GetUpstream(),
			HostMode:   s.GetHostMode(),
			HostHeader: s.GetHostHeader(),
			Enabled:    true,
			IsLeader:   s.GetIsLeader(),
			AcmeLeader: s.GetAcmeLeader(),
			CertPEM:    s.GetCertPem(),
		})
	}

	// Install any leader-issued certs distributed to this node (group followers)
	// before rendering, so the :443 bind can load them immediately.
	a.installFollowerCerts(sites)

	// HAProxy and the inbound firewall are independent: a broken haproxy.cfg
	// must never stop the firewall from being applied (that combination used to
	// report "firewall ok" while the node had no table at all).
	hpErr := a.hp.Apply(sites)
	if hpErr != nil {
		log.Printf("apply config: %v", hpErr)
	} else {
		log.Printf("synced revision %d (%d site(s))", reply.GetConfigRevision(), len(sites))
	}

	// Apply the node's inbound firewall. A nil firewall (old panel) means "not
	// managed" -> Apply removes our table if present.
	fw := reply.GetFirewall()
	var fwRules []firewall.Rule
	for _, r := range fw.GetRules() {
		fwRules = append(fwRules, firewall.Rule{Port: r.GetPort(), Protocol: r.GetProtocol(), Source: r.GetSource()})
	}
	var fwSets []firewall.IPSet
	for _, s := range fw.GetIpsets() {
		fwSets = append(fwSets, firewall.IPSet{Name: s.GetName(), CIDRs: s.GetCidrs()})
	}
	a.applyFirewall(fw.GetEnabled(), fwRules, fwSets)

	// Remember the desired sites (also used for cert reporting) even when the
	// haproxy apply failed.
	a.lastSites = sites
	// Only mark the revision as applied once HAProxy accepted the config, so a
	// failed apply is retried on the next heartbeat.
	if hpErr == nil {
		a.revision = reply.GetConfigRevision()
		a.revKnown = true
	}

	// Issue certificates for sites that don't have one yet. Group followers never
	// issue — their cert is signed by the leader and distributed by the panel.
	// Renewals are handled by acme.sh's own cron (leader) + redistribution.
	for i := range sites {
		if sites[i].Follower() {
			continue
		}
		primary := sites[i].Primary()
		if info := acme.CertInfo(a.certDir, primary); info.Exists {
			continue
		}
		ictx, cancel := context.WithTimeout(ctx, 180*time.Second)
		if err := a.ac.Issue(ictx, sites[i].DomainList()); err != nil {
			log.Printf("issue %s: %v", primary, err)
		} else {
			log.Printf("issued cert for %s", primary)
		}
		cancel()
	}
	// Upload any freshly-issued leader certs so the panel can distribute them.
	a.pushCerts(ctx, sites)
	a.report(ctx)
}

// applyFirewall applies the desired inbound firewall and records the outcome for
// the status report. Rules whose referenced IP set was not sent by the panel
// (deleted or disabled) are called out explicitly: they render no accept line,
// so with the default-deny policy that port stays closed.
func (a *agent) applyFirewall(enabled bool, rules []firewall.Rule, sets []firewall.IPSet) {
	known := make(map[string]bool, len(sets))
	for _, s := range sets {
		known[s.Name] = true
	}
	for _, r := range rules {
		for _, tok := range splitTokens(r.Source) {
			if strings.HasPrefix(tok, "@") && !known[strings.TrimPrefix(tok, "@")] {
				log.Printf("firewall: 规则 %s/%s 引用的 IP 组 %s 未下发(已删除或被禁用)，该规则不放行任何来源",
					r.Protocol, r.Port, tok)
			}
		}
	}

	if err := firewall.Apply(enabled, rules, sets, firewall.Options{Forward: a.fwForward}); err != nil {
		a.fwErr = err.Error()
		a.fwNote = ""
		log.Printf("firewall: %v", err)
		return
	}
	a.fwErr = ""
	a.fwNote = ""
	if enabled {
		log.Printf("firewall applied (%d rule(s), forward=%v)", len(rules), a.fwForward)
		if !a.fwForward {
			// Without the forward chain, DNAT'ed (Docker-published) ports are not
			// covered — say so instead of reporting a clean status.
			if pubs := firewall.DockerPublished(); len(pubs) > 0 {
				a.fwNote = "检测到 Docker 发布端口（" + strings.Join(pubs, ", ") +
					"）：forward 处理已关闭（FIREWALL_FORWARD=0），这些端口不受本防火墙约束"
				log.Printf("firewall: %s", a.fwNote)
			}
		}
	}
}

// splitTokens splits a rule source into its space/comma separated tokens.
func splitTokens(s string) []string {
	return strings.FieldsFunc(s, func(r rune) bool {
		return r == ' ' || r == ',' || r == '\t' || r == '\n'
	})
}

// installFollowerCerts writes leader-issued certificates (distributed by the
// panel) to the local cert dir for group-follower sites, so HAProxy serves them.
func (a *agent) installFollowerCerts(sites []models.Site) {
	for i := range sites {
		st := &sites[i]
		if !st.Follower() || strings.TrimSpace(st.CertPEM) == "" {
			continue
		}
		primary := st.Primary()
		if primary == "" {
			continue
		}
		path := filepath.Join(a.certDir, primary+".pem")
		if cur, err := os.ReadFile(path); err == nil && string(cur) == st.CertPEM {
			continue // unchanged
		}
		if err := os.MkdirAll(a.certDir, 0o755); err != nil {
			log.Printf("cert dir %s: %v", a.certDir, err)
			continue
		}
		if err := writeFileAtomic(path, []byte(st.CertPEM), 0o600); err != nil {
			log.Printf("install cert %s: %v", primary, err)
			continue
		}
		log.Printf("installed distributed cert for %s", primary)
	}
}

// pushCerts uploads leader-held certificates to the panel when they change, so
// the panel can distribute them to the group's other members (covers first issue
// and acme.sh cron renewals).
func (a *agent) pushCerts(ctx context.Context, sites []models.Site) {
	for i := range sites {
		st := &sites[i]
		if st.Follower() { // only leaders/single nodes hold an issued cert here
			continue
		}
		primary := st.Primary()
		if primary == "" {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(a.certDir, primary+".pem"))
		if err != nil {
			continue // not issued yet
		}
		pem := string(raw)
		if a.reported[primary] == pem {
			continue // already uploaded this exact cert
		}
		rctx, cancel := context.WithTimeout(ctx, 15*time.Second)
		_, err = a.cli.ReportCert(rctx, &pb.CertUpload{Domain: primary, Pem: pem})
		cancel()
		if err != nil {
			log.Printf("report cert %s: %v", primary, err)
			continue
		}
		a.reported[primary] = pem
	}
}

// writeFileAtomic writes data to path via a temp file + rename in the same dir.
func writeFileAtomic(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".cert-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return err
	}
	tmp.Close()
	if err := os.Chmod(tmpName, mode); err != nil {
		os.Remove(tmpName)
		return err
	}
	return os.Rename(tmpName, path)
}

// report sends HAProxy status + per-site cert expiries to the panel.
func (a *agent) report(ctx context.Context) {
	rctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	req := &pb.StatusRequest{HaproxyRunning: a.hp.Running()}

	// Validate the current on-disk config by reading sites back is not possible
	// here; instead validate that HAProxy accepts its running config file.
	if err := a.hp.ValidateFile(); err != nil {
		req.ConfigOk = false
		req.ConfigErr = err.Error()
	} else {
		req.ConfigOk = true
	}

	req.FirewallOk = a.fwErr == ""
	if a.fwErr != "" {
		req.FirewallErr = a.fwErr
	} else {
		req.FirewallErr = a.fwNote
	}

	for i := range a.lastSites {
		primary := a.lastSites[i].Primary()
		info := acme.CertInfo(a.certDir, primary)
		cs := &pb.CertStatus{Domain: primary, Exists: info.Exists, DaysLeft: int32(info.DaysLeft)}
		if info.Exists && info.NotAfter != "" {
			if t, err := time.Parse(time.RFC3339, info.NotAfter); err == nil {
				cs.NotAfterUnix = t.Unix()
			}
		}
		req.Certs = append(req.Certs, cs)
	}

	if _, err := a.cli.ReportStatus(rctx, req); err != nil {
		log.Printf("report: %v", err)
	}

	// Re-upload leader certs that acme.sh's cron may have renewed, so followers
	// pick up the renewed cert on their next sync.
	a.pushCerts(ctx, a.lastSites)
}

func atoiDef(s string, def int) int {
	if n, err := strconv.Atoi(strings.TrimSpace(s)); err == nil && n > 0 {
		return n
	}
	return def
}
