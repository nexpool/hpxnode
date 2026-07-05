#!/usr/bin/env bash
# 在一台 HAProxy 服务器上安装节点代理 hpxnode，并接入 hpxnode 面板。
# 装 HAProxy 3.x + acme.sh + hpxnode 代理(systemd)。代理经 gRPC 从面板拉取本节点
# 的站点，本地生成 haproxy.cfg、签发/续期证书、reload，并上报状态。
#
# 用法(在面板「节点」页新建节点后会给出完整命令):
#   sudo bash install-node.sh --panel <面板地址:9090> --id <节点ID> --secret <密钥>
#
# 选项:
#   --panel <host:port>  面板 gRPC 地址(必填)
#   --id <n>             节点 ID(必填)
#   --secret <s>         节点密钥(必填)
#   --bin <path>         本地 hpxnode 二进制(否则从 Release 下载)
#   --branch <x.y>       HAProxy 分支(默认 3.2)
#   --version <tag>      下载的 Release 版本
set -euo pipefail

green='\033[0;32m'; yellow='\033[0;33m'; red='\033[0;31m'; plain='\033[0m'
say()  { echo -e "${green}==>${plain} $*"; }
warn() { echo -e "${yellow}警告:${plain} $*"; }
die()  { echo -e "${red}错误:${plain} $*" >&2; exit 1; }

[[ $EUID -eq 0 ]] || die "必须使用 root 运行:  sudo bash $0"

REPO="${HPXNODE_REPO:-nexpool/hpxnode}"
PANEL=""; NODE_ID=""; NODE_SECRET=""; LOCAL_BIN=""; HAPROXY_BRANCH="3.2"; VERSION=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --panel)  PANEL="$2"; shift 2 ;;
    --id)     NODE_ID="$2"; shift 2 ;;
    --secret) NODE_SECRET="$2"; shift 2 ;;
    --bin)    LOCAL_BIN="$2"; shift 2 ;;
    --branch) HAPROXY_BRANCH="$2"; shift 2 ;;
    --version) VERSION="$2"; shift 2 ;;
    -h|--help) grep '^#' "$0" | sed 's/^# \?//'; exit 0 ;;
    *) die "未知参数: $1" ;;
  esac
done
[[ -n "$PANEL" && -n "$NODE_ID" && -n "$NODE_SECRET" ]] || die "需要 --panel / --id / --secret"

INSTALL_DIR=/usr/local/hpxnode
CONFIG_DIR=/etc/hpxnode
CERT_DIR=/etc/haproxy/certs
BIN="$INSTALL_DIR/hpxnode"

case "$(uname -m)" in
  x86_64|amd64) ARCH="amd64" ;;
  aarch64|arm64) ARCH="arm64" ;;
  *) die "不支持的架构: $(uname -m)" ;;
esac

# 升级兜底：坏配置占位，避免升级 HAProxy 时其安装脚本拿坏配置启动失败。
if [[ -f /etc/haproxy/haproxy.cfg ]]; then
  cp /etc/haproxy/haproxy.cfg /etc/haproxy/haproxy.cfg.bak 2>/dev/null || true
  printf 'global\n    log /dev/log local0\ndefaults\n    mode http\n    timeout connect 5s\n    timeout client 50s\n    timeout server 50s\nfrontend _ph\n    bind 127.0.0.1:65535\n    default_backend _phb\nbackend _phb\n    http-request return status 200\n' > /etc/haproxy/haproxy.cfg
fi

say "[1/6] 安装 HAProxy ${HAPROXY_BRANCH}.x + acme.sh + 依赖"
if command -v apt-get >/dev/null 2>&1; then
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -y
  apt-get install -y curl socat openssl ca-certificates gnupg software-properties-common cron
  if grep -qi ubuntu /etc/os-release 2>/dev/null && command -v add-apt-repository >/dev/null 2>&1; then
    add-apt-repository -y "ppa:vbernat/haproxy-${HAPROXY_BRANCH}" && apt-get update -y || warn "PPA 添加失败，用自带版本"
  fi
  apt-get install -y --allow-downgrades haproxy
elif command -v dnf >/dev/null 2>&1; then
  dnf install -y haproxy socat curl openssl cronie
elif command -v yum >/dev/null 2>&1; then
  yum install -y epel-release || true; yum install -y haproxy socat curl openssl cronie
else
  die "未识别的包管理器"
fi
say "已安装: $(haproxy -v 2>/dev/null | head -1)"
systemctl enable --now cron 2>/dev/null || systemctl enable --now crond 2>/dev/null || true
systemctl disable --now caddy 2>/dev/null || true

if [[ ! -f "$HOME/.acme.sh/acme.sh" ]]; then curl -s https://get.acme.sh | sh; fi
"$HOME/.acme.sh/acme.sh" --set-default-ca --server letsencrypt >/dev/null 2>&1 || true

say "[2/6] 证书目录 + 兜底自签证书"
mkdir -p "$CERT_DIR"; chmod 700 "$CERT_DIR"
if [[ ! -f "$CERT_DIR/000-default.pem" ]]; then
  tk=$(mktemp); tc=$(mktemp)
  openssl req -x509 -newkey rsa:2048 -nodes -days 3650 -keyout "$tk" -out "$tc" -subj "/CN=default" >/dev/null 2>&1
  cat "$tc" "$tk" > "$CERT_DIR/000-default.pem"; chmod 600 "$CERT_DIR/000-default.pem"; rm -f "$tk" "$tc"
fi
systemctl enable haproxy >/dev/null 2>&1 || true
systemctl restart haproxy || true   # 代理接入后会写入真正的配置并重载

say "[3/6] 安装节点代理二进制 -> $BIN"
mkdir -p "$INSTALL_DIR"
if [[ -n "$LOCAL_BIN" ]]; then
  [[ -f "$LOCAL_BIN" ]] || die "找不到本地二进制: $LOCAL_BIN"
  install -m 0755 "$LOCAL_BIN" "${BIN}.new"
else
  if [[ -z "$VERSION" ]]; then
    VERSION=$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/') || true
    [[ -z "$VERSION" ]] && die "无法获取版本，请用 --version 或 --bin(make linux-build 生成)"
  fi
  say "下载 hpxnode ${VERSION} (${ARCH})"
  curl -fSL "https://github.com/${REPO}/releases/download/${VERSION}/hpxnode-linux-${ARCH}" -o "${BIN}.new" || { rm -f "${BIN}.new"; die "下载失败"; }
  chmod +x "${BIN}.new"
fi
mv -f "${BIN}.new" "$BIN"

say "[4/6] 写入代理配置 $CONFIG_DIR/hpxnode.env"
mkdir -p "$CONFIG_DIR"; umask 077
cat > "$CONFIG_DIR/hpxnode.env" <<EOF
PANEL_GRPC=$PANEL
NODE_ID=$NODE_ID
NODE_SECRET=$NODE_SECRET
HAPROXY_BIN=haproxy
HAPROXY_CFG=/etc/haproxy/haproxy.cfg
CERT_DIR=$CERT_DIR
RELOAD_CMD=systemctl reload haproxy
ACME_HTTP_PORT=8080
HEARTBEAT_SECONDS=10
STATUS_SECONDS=30
EOF

say "[5/6] systemd 服务 + 管理命令"
cat > /etc/systemd/system/hpxnode.service <<EOF
[Unit]
Description=hpxnode node agent (hpxnode)
After=network-online.target haproxy.service
Wants=network-online.target

[Service]
Type=simple
EnvironmentFile=$CONFIG_DIR/hpxnode.env
ExecStart=$BIN
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

cat > /usr/bin/hpxnode <<'CLI'
#!/usr/bin/env bash
set -euo pipefail
[[ $EUID -ne 0 ]] && echo "请用 root 运行" && exit 1
case "${1:-}" in
  start)   systemctl start hpxnode ;;
  stop)    systemctl stop hpxnode ;;
  restart) systemctl restart hpxnode ;;
  status)  systemctl status hpxnode --no-pager ;;
  log)     journalctl -u hpxnode -f ;;
  config)  ${EDITOR:-vi} /etc/hpxnode/hpxnode.env; systemctl restart hpxnode ;;
  uninstall)
    systemctl disable --now hpxnode 2>/dev/null || true
    rm -f /etc/systemd/system/hpxnode.service /usr/bin/hpxnode /usr/local/hpxnode/hpxnode
    systemctl daemon-reload; echo "已卸载节点代理(HAProxy/证书保留)" ;;
  *) echo "usage: hpxnode {start|stop|restart|status|log|config|uninstall}" ;;
esac
CLI
chmod +x /usr/bin/hpxnode

systemctl daemon-reload
systemctl enable hpxnode >/dev/null 2>&1 || true
systemctl restart hpxnode

say "[6/6] 放行 80 / 443"
if command -v ufw >/dev/null 2>&1; then ufw allow 80/tcp >/dev/null 2>&1 || true; ufw allow 443/tcp >/dev/null 2>&1 || true; fi
if command -v firewall-cmd >/dev/null 2>&1; then
  firewall-cmd --add-service=http --add-service=https --permanent >/dev/null 2>&1 || true
  firewall-cmd --reload >/dev/null 2>&1 || true
fi

echo
say "节点接入完成 ✅  已连接面板 $PANEL (node $NODE_ID)"
echo "  在面板「节点」页应能看到本节点上线。之后给它分配站点即可。"
echo "  管理命令: hpxnode {start|stop|restart|status|log|config|uninstall}"
