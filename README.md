# hpxnode

**hzproxy** 的节点代理。运行在每台 HAProxy 服务器上，通过 gRPC 连接
[hzproxy](https://github.com/nexpool/hproxy) 面板，拉取本节点的站点，
本地生成 `haproxy.cfg`、用 acme.sh 签发/续期 Let's Encrypt 证书、reload，并上报状态。

```
面板(control plane) ──gRPC(node-id + secret)──▶ hpxnode ──▶ 本地 HAProxy + acme.sh
```

## 工作流程

1. 心跳（默认 10s）上报版本/系统，并取回面板的 `config_revision`。
2. revision 变化时 `Sync` 拉取本节点全部站点 → 生成 `haproxy.cfg` → `haproxy -c` 校验 → 原子写入 → reload。
3. 为没有证书的站点用 acme.sh 走 HTTP-01 申请（HAProxy 把 `/.well-known/acme-challenge/` 转发到本地 8080）；续期交给 acme.sh 自带 cron。
4. 状态上报（默认 30s）：HAProxy 是否运行、配置是否有效、每站证书到期。

## 安装（推荐）

在面板「节点」页新建节点后会给出完整命令：

```bash
sudo bash <(curl -fsSL https://raw.githubusercontent.com/nexpool/hpxnode/main/scripts/install.sh) \
  --panel 面板IP:9099 --id <节点ID> --secret <密钥>
```

安装脚本会装 HAProxy 3.x（Ubuntu 走官方 PPA）+ acme.sh + 本代理（systemd 服务 `hpxnode`）。

## 构建

```bash
make build          # 当前平台
make linux          # 发布用: hpxnode-linux-amd64 / hpxnode-linux-arm64
make proto          # 改了 proto/node.proto 才需要(需 protoc)
```

## 直接运行

```bash
PANEL_GRPC=面板IP:9099 NODE_ID=1 NODE_SECRET=xxx ./hpxnode
# 或
./hpxnode --panel 面板IP:9099 --id 1 --secret xxx
```

## 配置（flag 或环境变量）

| 环境变量            | flag       | 默认                       | 说明                                                                                                                                |
| ------------------- | ---------- | -------------------------- | ----------------------------------------------------------------------------------------------------------------------------------- |
| `PANEL_GRPC`        | `--panel`  | —                          | 面板 gRPC 地址 host:port（必填）                                                                                                    |
| `NODE_ID`           | `--id`     | —                          | 节点 ID（必填）                                                                                                                     |
| `NODE_SECRET`       | `--secret` | —                          | 节点密钥（必填）                                                                                                                    |
| `HAPROXY_BIN`       |            | `haproxy`                  | HAProxy 二进制                                                                                                                      |
| `HAPROXY_CFG`       |            | `/etc/haproxy/haproxy.cfg` | 目标配置文件                                                                                                                        |
| `CERT_DIR`          |            | `/etc/haproxy/certs`       | 证书目录（按 SNI 加载）                                                                                                             |
| `RELOAD_CMD`        |            | `systemctl reload haproxy` | reload 命令                                                                                                                         |
| `ACME_HTTP_PORT`    |            | `8080`                     | acme.sh standalone 本地端口                                                                                                         |
| `HEARTBEAT_SECONDS` |            | `10`                       | 心跳间隔                                                                                                                            |
| `STATUS_SECONDS`    |            | `30`                       | 状态上报间隔                                                                                                                        |
| `FIREWALL_FORWARD`  |            | `1`                        | 防火墙规则是否也约束**转发**流量（Docker 发布端口经 DNAT 走 forward 链，input 链看不到）。`0` = 只管 input，Docker 端口不受规则约束 |

## 管理命令

安装后：

```bash
hpxnode {start|stop|restart|status|log|config|update|uninstall}
```

`hpxnode update` 会从 GitHub Release 拉取最新 `hpxnode-linux-<arch>`、原子替换二进制并重启服务。

## 目录

```
main.go              代理主循环
proto/ pb/           gRPC 协议 + 生成代码(与面板一致)
internal/haproxy/    生成/校验/reload haproxy.cfg
internal/acme/       acme.sh 封装 + 证书到期解析
internal/models/     Site / CertInfo
scripts/install.sh   一键安装
```

## gRPC 协议

心跳/同步/上报三个 RPC 的完整说明、`node.proto` 生成命令、服务端/客户端实现、鉴权与排错，
见面板仓库的 [docs/grpc.md](https://github.com/nexpool/hzproxy/blob/main/docs/grpc.md)。

`node.proto` 与面板那份**除 `go_package` 外必须字节一致**，改协议时两边同步改、各自 `make proto`。

> 注意：当前与面板的 gRPC 连接为明文（`insecure`）。跨公网部署建议走内网/VPN，
> 或后续为面板 gRPC 加 TLS。
