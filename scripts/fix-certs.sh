#!/usr/bin/env bash
# hpxnode 证书抢修 —— 对【本节点】证书目录里所有已过期/即将过期的证书强制重签。
#
#   sudo bash fix-certs.sh            # 处理已过期或 10 天内到期的证书
#   sudo bash fix-certs.sh --days 30  # 阈值改成 30 天
#   sudo bash fix-certs.sh --dry-run  # 只看要做什么，不动手
#
# 在【每一台】HAProxy 节点上各跑一次（HK-ALI、CN-ZZ）。
#
# 设计要点（依据 acme.sh 3.1.6 源码核对）:
#   * 续期窗口是按【签发时间】算的（签发后 30 天到期续期），不是「到期前 30 天」；
#   * 已过期的证书一定会被 --force 重签，不会因为窗口判定被跳过；
#   * acme.sh 的 haproxy deploy hook 是【原地截断重写】PEM，非原子 —— 并发 reload
#     可能读到空/半截文件。所以这里部署后先校验，校验通过才 reload。
set -uo pipefail

CERT_DIR="${CERT_DIR:-/etc/haproxy/certs}"
ACME_HTTP_PORT="${ACME_HTTP_PORT:-8080}"
RELOAD_CMD="${RELOAD_CMD:-systemctl reload haproxy}"
THRESHOLD=10; DRY=0; RENEWED=0
while [ $# -gt 0 ]; do
  case "$1" in
    --days) THRESHOLD="$2"; shift 2 ;;
    --dry-run) DRY=1; shift ;;
    *) echo "未知参数: $1"; exit 1 ;;
  esac
done

ACME_HOME=""
for c in /root/.acme.sh "$HOME/.acme.sh"; do [ -x "$c/acme.sh" ] && ACME_HOME="$c" && break; done
if [ -z "$ACME_HOME" ]; then echo "错误: 找不到 acme.sh"; exit 1; fi
ACME_SH="$ACME_HOME/acme.sh"
g='\033[0;32m'; y='\033[0;33m'; r='\033[0;31m'; b='\033[1m'; p='\033[0m'
say(){  printf "${g}==>${p} %s\n" "$*"; }
warn(){ printf "${y}警告:${p} %s\n" "$*"; }
bad(){  printf "${r}错误:${p} %s\n" "$*"; }

[ "$(id -u)" = "0" ] || { bad "请用 root 运行: sudo bash $0"; exit 1; }
[ -d "$CERT_DIR" ] || { bad "证书目录不存在: $CERT_DIR"; exit 1; }
command -v openssl >/dev/null || { bad "缺少 openssl"; exit 1; }

pem_expiry(){ openssl x509 -in "$1" -noout -enddate 2>/dev/null | sed "s/^notAfter=//"; }

# ---------- 第 1 步：扫描 ----------
NOW="$(date +%s)"
TARGETS=""
shopt -s nullglob
for pem in "$CERT_DIR"/*.pem; do
  DOM="$(basename "$pem" .pem)"
  case "$DOM" in 000-default) continue ;; esac
  openssl x509 -in "$pem" -noout >/dev/null 2>&1 || continue
  END="$(date -d "$(pem_expiry "$pem")" +%s 2>/dev/null || echo 0)"
  LEFT=$(( (END - NOW) / 86400 ))
  if [ "$END" -lt "$NOW" ]; then
    bad "$DOM 已过期 $(( (NOW - END) / 86400 )) 天 -> 需要重签"
    TARGETS="$TARGETS $DOM"
  elif [ "$LEFT" -le "$THRESHOLD" ]; then
    warn "$DOM 剩 ${LEFT} 天（<= ${THRESHOLD}）-> 需要续期"
    TARGETS="$TARGETS $DOM"
  else
    say "$DOM 剩 ${LEFT} 天，跳过"
  fi
done

if [ -z "$TARGETS" ]; then say "没有需要处理的证书。"; exit 0; fi
echo; say "将要处理:$TARGETS"
if [ "$DRY" = "1" ]; then say "--dry-run，到此为止。"; exit 0; fi

# ---------- 第 2 步：逐张抢修 ----------
FAILED=""; DONE=""
for DOM in $TARGETS; do
  echo "=================================================="
  say "处理 $DOM"
  PEM="$CERT_DIR/$DOM.pem"
  OLD_EXP="$(pem_expiry "$PEM")"
  SERVED_BEFORE="$(echo | timeout 8 openssl s_client -connect 127.0.0.1:443 -servername "$DOM" 2>/dev/null | openssl x509 -noout -enddate 2>/dev/null | sed "s/^notAfter=//")"

  # 情况 A：磁盘上已经是【有效】证书，但 HAProxy 还在发旧的 => 只是没 reload
  OLD_END="$(date -d "$OLD_EXP" +%s 2>/dev/null || echo 0)"
  if [ "$OLD_END" -gt "$NOW" ] && [ -n "$SERVED_BEFORE" ] && [ "$SERVED_BEFORE" != "$OLD_EXP" ]; then
    warn "  磁盘上已是有效证书（$OLD_EXP），但 HAProxy 在发旧证书（$SERVED_BEFORE）"
    say "  => 只差一次 reload，不重新签发"
    RENEWED=1
    DONE="$DONE $DOM(reload)"
    continue
  fi

  CONF="$ACME_HOME/$DOM/$DOM.conf"
  if [ ! -f "$CONF" ]; then
    bad "  $DOM: 没有 acme.sh 域名配置 $CONF，无法自动重签"
    warn "  手工签发示例:"
    warn "  $ACME_SH --issue -d $DOM --server letsencrypt --standalone --httpport $ACME_HTTP_PORT --force"
    FAILED="$FAILED $DOM"
    continue
  fi

  Domain="$(sed -n "s/^Le_Domain='\?\([^']*\)'\?$/\1/p" "$CONF" 2>/dev/null | head -1)"
  Alt="$(sed -n "s/^Le_Alt='\?\([^']*\)'\?$/\1/p" "$CONF" 2>/dev/null | head -1)"
  API="$(sed -n "s/^Le_API='\?\([^']*\)'\?$/\1/p" "$CONF" 2>/dev/null | head -1)"
  DARGS=""
  [ -n "$Domain" ] && DARGS="-d $Domain"
  if [ -n "$Alt" ]; then
    IFS=","; for a in $Alt; do [ -n "$a" ] && DARGS="$DARGS -d $a"; done; unset IFS
  fi
  [ -n "$DARGS" ] || DARGS="-d $DOM"
  SERVER="${API:-https://acme-v02.api.letsencrypt.org/directory}"
  say "  域名: $DARGS"
  say "  CA:   $SERVER"

  # deploy hook 靠这两个环境变量把「目标目录/reload 命令」持久化进域名配置，
  # 这样以后 acme.sh 自己的 cron 续期也知道该写哪、该 reload 什么。
  export DEPLOY_HAPROXY_PEM_PATH="$CERT_DIR"
  export DEPLOY_HAPROXY_RELOAD="$RELOAD_CMD"

  say "  [1/3] 强制签发（--force）..."
  timeout 300 "$ACME_SH" --issue $DARGS --server "$SERVER" --standalone --httpport "$ACME_HTTP_PORT" --force >/tmp/.acme_out 2>&1
  RC=$?
  tail -6 /tmp/.acme_out | sed "s/^/      /"
  if [ "$RC" != "0" ] && [ "$RC" != "2" ]; then
    bad "  $DOM: 签发失败 (退出码 $RC)"
    FAILED="$FAILED $DOM"
    continue
  fi

  say "  [2/3] 部署到 $CERT_DIR ..."
  if ! timeout 120 "$ACME_SH" --deploy -d "$DOM" --deploy-hook haproxy >/tmp/.acme_dep 2>&1; then
    tail -6 /tmp/.acme_dep | sed "s/^/      /"
    bad "  $DOM: 部署失败"
    FAILED="$FAILED $DOM"
    continue
  fi

  say "  [3/3] 校验部署结果（防止读到半截 PEM）..."
  NEW_EXP="$(pem_expiry "$PEM")"
  if ! openssl x509 -in "$PEM" -noout >/dev/null 2>&1; then
    bad "  $DOM: 部署后文件不是合法 PEM，跳过 reload（避免 HAProxy 加载失败）"
    FAILED="$FAILED $DOM"
    continue
  fi
  if [ "$NEW_EXP" = "$OLD_EXP" ]; then
    bad "  $DOM: 部署后到期时间没变（仍是 $NEW_EXP）—— 证书其实没换成新的"
    FAILED="$FAILED $DOM"
    continue
  fi
  say "  证书已更新: $OLD_EXP  ->  $NEW_EXP"
  # 原子化重写，消除「HAProxy 在 reload 时读到截断文件」的窗口
  if ! cat "$PEM" > "$PEM.tmp" || ! openssl x509 -in "$PEM.tmp" -noout >/dev/null 2>&1; then
    bad "  $DOM: 临时文件校验失败，保留原文件"
    rm -f "$PEM.tmp"
    FAILED="$FAILED $DOM"
    continue
  fi
  chmod 600 "$PEM.tmp" && mv -f "$PEM.tmp" "$PEM"
  say "  $DOM 完成"
  RENEWED=1
  DONE="$DONE $DOM"
done
rm -f /tmp/.acme_out /tmp/.acme_dep

# ---------- 第 3 步：统一 reload ----------
echo
if [ -n "$FAILED" ]; then
  warn "有证书处理失败，为安全起见【不 reload】HAProxy（现网继续用旧证书，不会中断）"
  warn "失败的:$FAILED"
elif [ "$RENEWED" = "1" ]; then
  say "reload HAProxy ..."
  if $RELOAD_CMD 2>&1 | sed "s/^/    /"; then
    say "reload 成功"
  else
    bad "reload 失败！证书已就位但 HAProxy 还在用旧的，请手工执行: $RELOAD_CMD"
  fi
fi

# ---------- 复核 ----------
echo
say "复核（磁盘 vs HAProxy 实际发出）:"
for pem in "$CERT_DIR"/*.pem; do
  DOM="$(basename "$pem" .pem)"
  case "$DOM" in 000-default) continue ;; esac
  openssl x509 -in "$pem" -noout >/dev/null 2>&1 || continue
  DE="$(pem_expiry "$pem")"
  SE="$(echo | timeout 8 openssl s_client -connect 127.0.0.1:443 -servername "$DOM" 2>/dev/null | openssl x509 -noout -enddate 2>/dev/null | sed "s/^notAfter=//")"
  MARK="  "
  [ -n "$SE" ] && [ "$SE" != "$DE" ] && MARK="${r}<= 不一致${p}"
  printf "  %-26s 磁盘=%s  %s\n" "$DOM" "$DE" "$MARK"
done

echo
if [ -n "$DONE" ]; then say "已处理:$DONE"; fi
if [ -n "$FAILED" ]; then bad "仍失败:$FAILED"; fi
echo
say "别忘了修自动续期（否则 90 天后又过期）:"
echo "  1) $ACME_SH --install-cronjob   然后 crontab -l 确认有它"
echo "  2) systemctl enable --now cron"
echo "  3) 跑 diag-cert.sh 确认 cron 的 --home 与证书所在目录一致"
