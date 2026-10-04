#!/usr/bin/env bash
# hpxnode 证书续期体检 —— 只读诊断，不改动任何东西。
# 在【每一台】HAProxy 节点上各跑一次:
#
#   sudo bash diag-cert.sh
#
# 逐张检查证书目录里的每个证书，回答三个问题:
#   1. 磁盘上的证书过期了吗？
#   2. HAProxy 实际发出去的是哪一张？（与磁盘不一致 = 没 reload）
#   3. acme.sh 的续期配置齐不齐？（cron / deploy hook / reload / 下次续期）
set -uo pipefail

CERT_DIR="${CERT_DIR:-/etc/haproxy/certs}"
ACME_HOME=""
for c in /root/.acme.sh "$HOME/.acme.sh"; do
  [ -x "$c/acme.sh" ] && ACME_HOME="$c" && break
done
ACME_SH=""
[ -n "$ACME_HOME" ] && ACME_SH="$ACME_HOME/acme.sh"

hdr(){ printf '\n===== %s =====\n' "$*"; }
ok(){   printf '  [正常] %s\n' "$*"; }
warn(){ printf '  [注意] %s\n' "$*"; }
bad(){  printf '  [异常] %s\n' "$*"; }
info(){ printf '  [信息] %s\n' "$*"; }

NOW="$(date +%s)"
expired_list=""
noconf_list=""
PROC_START=0

hdr "0. 环境"
info "主机名: $(hostname)"
info "当前时间: $(date '+%F %T %Z')"
info "证书目录: $CERT_DIR"
if [ -n "$ACME_SH" ]; then ok "acme.sh: $ACME_SH"; else bad "找不到 acme.sh（/root/.acme.sh 或 ~/.acme.sh）"; fi

if pgrep -x haproxy >/dev/null; then
  MAIN_PID="$(pgrep -x haproxy | head -1)"
  PROC_START="$(stat -c %Y /proc/$MAIN_PID 2>/dev/null || echo 0)"
  ok "HAProxy 在运行 (PID=$MAIN_PID, 启动于 $(date -d "@$PROC_START" '+%F %T' 2>/dev/null))"
  echo "    提示: 证书文件修改时间【晚于】这个启动时间 => 换了但没 reload。"
else
  bad "HAProxy 没在运行"
fi

hdr "1. 自动续期定时任务"
CRON_ALL="$( (crontab -l 2>/dev/null; cat /etc/cron.d/acme.sh 2>/dev/null; cat /var/spool/cron/crontabs/root 2>/dev/null; cat /var/spool/cron/root 2>/dev/null; systemctl list-timers --all 2>/dev/null) | grep -iE 'acme' )"
if [ -n "$CRON_ALL" ]; then
  ok "找到 acme.sh 定时任务:"
  printf '%s\n' "$CRON_ALL" | sed 's/^/    /'
else
  bad "没有任何 acme.sh 定时任务 —— 证书永远不会自动续期（最可能的根因）"
  info "修法: $ACME_SH --install-cronjob"
fi

# 【重要】cron 里 acme.sh 的 HOME 必须和签证书时用的那个一致，
# 否则 cron 去另一个空目录里找证书，永远「没有需要续期的证书」。
if [ -n "$CRON_ALL" ]; then
  printf '%s\n' "$CRON_ALL" | while IFS= read -r line; do
    [ -n "$line" ] || continue
    CSH="$(printf '%s\n' "$line" | sed -n 's/^[^ ]*[ ]*\([^ ]*acme\.sh\).*/\1/p')"
    CHOME="$(printf '%s\n' "$line" | sed -n 's/.*--home[ =]\"\([^\"]*\)\".*/\1/p')"
    [ -n "$CSH" ] || continue
    if [ -f "$CSH" ]; then
      ok "cron 用的 acme.sh 存在: $CSH"
    else
      bad "cron 指向的 acme.sh 不存在: $CSH  —— 续期命令会直接报 command not found"
    fi
    if [ -n "$CHOME" ]; then
      info "cron 用的 HOME: $CHOME"
      if [ "$CHOME" != "$ACME_HOME" ]; then
        bad "与本次检测到的 acme.sh 目录不一致（$ACME_HOME）！"
        info "  => cron 会在 $CHOME 里找证书，而证书在 $ACME_HOME —— 永远不会续期"
      else
        ok "cron 的 HOME 与证书所在目录一致"
      fi
      if [ -d "$CHOME" ]; then
        N="$(find "$CHOME" -maxdepth 1 -name '*.conf' 2>/dev/null | wc -l)"
        if [ "$N" = "0" ]; then
          bad "  $CHOME 下没有任何域名配置 —— cron 跑起来会认为「没有证书要续」"
        fi
      fi
    fi
  done
fi
if systemctl is-active --quiet cron 2>/dev/null || systemctl is-active --quiet crond 2>/dev/null; then
  ok "cron 服务在运行"
else
  bad "cron 服务没在运行 —— 有定时任务也不会执行"
  info "修法: systemctl enable --now cron"
fi

hdr "2. 证书目录逐张体检"
[ -d "$CERT_DIR" ] || { bad "证书目录不存在: $CERT_DIR"; exit 1; }
shopt -s nullglob
for pem in "$CERT_DIR"/*.pem; do
  DOM="$(basename "$pem" .pem)"
  echo
  echo "---- $DOM ----"
  if ! openssl x509 -in "$pem" -noout >/dev/null 2>&1; then warn "不是合法证书文件，跳过"; continue; fi

  NOTAFTER="$(openssl x509 -in "$pem" -noout -enddate 2>/dev/null | sed "s/^notAfter=//")"
  END="$(date -d "$NOTAFTER" +%s 2>/dev/null || echo 0)"
  MTIME="$(stat -c %Y "$pem")"
  ISSUER="$(openssl x509 -in "$pem" -noout -issuer 2>/dev/null | sed 's/^issuer=//')"
  LEFT_DAYS=$(( (END - NOW) / 86400 ))

  info "签发者: $ISSUER"
  info "到期时间: $(date -d "@$END" '+%F %T' 2>/dev/null)  (剩余 ${LEFT_DAYS} 天)"
  info "文件修改: $(date -d "@$MTIME" '+%F %T' 2>/dev/null)"

  if [ "$END" -lt "$NOW" ]; then
    bad "证书【已过期】$(( (NOW - END) / 86400 )) 天"
    expired_list="$expired_list $DOM"
  elif [ "$LEFT_DAYS" -lt 15 ]; then
    warn "即将过期，只剩 ${LEFT_DAYS} 天"
  else
    ok "证书有效，剩 ${LEFT_DAYS} 天"
  fi

  SERVED="$(echo | timeout 8 openssl s_client -connect 127.0.0.1:443 -servername "$DOM" 2>/dev/null | openssl x509 -noout -enddate 2>/dev/null | sed "s/^notAfter=//")"
  if [ -n "$SERVED" ]; then
    if [ "$SERVED" != "$NOTAFTER" ]; then
      bad "HAProxy 实际发出的是【另一张】证书（到期 $SERVED）→ 文件换了但没 reload"
    else
      ok "HAProxy 实际发出的与磁盘一致"
    fi
  else
    warn "无法通过 SNI=$DOM 取到证书（该域名可能不在此节点服务）"
  fi

  if [ -n "$ACME_HOME" ] && [ -d "$ACME_HOME/$DOM" ]; then
    CONF="$ACME_HOME/$DOM/$DOM.conf"
    if [ -f "$CONF" ]; then
      NextRenewTimeStr="$(sed -n "s/^Le_NextRenewTimeStr='\?\([^']*\)'\?$/\1/p" "$CONF" 2>/dev/null | head -1)"
      DeployHook="$(sed -n "s/^Le_DeployHook='\?\([^']*\)'\?$/\1/p" "$CONF" 2>/dev/null | head -1)"
      Deploy_haproxy_pem_path="$(sed -n "s/^Le_Deploy_haproxy_pem_path='\?\([^']*\)'\?$/\1/p" "$CONF" 2>/dev/null | head -1)"
      Deploy_haproxy_reload="$(sed -n "s/^Le_Deploy_haproxy_reload='\?\([^']*\)'\?$/\1/p" "$CONF" 2>/dev/null | head -1)"
      DeploySuccessTimeStr="$(sed -n "s/^Le_DeploySuccessTimeStr='\?\([^']*\)'\?$/\1/p" "$CONF" 2>/dev/null | head -1)"
      info "acme.sh 下次续期: ${NextRenewTimeStr:-（未设置）}"
      info "deploy hook: ${DeployHook:-（未设置 —— 续期后不会部署！）}"
      info "deploy 目标目录: ${Deploy_haproxy_pem_path:-（未持久化，cron 时回退到 /etc/haproxy）}"
      info "deploy reload: ${Deploy_haproxy_reload:-（未持久化 —— 续期后不会 reload）}"
      info "上次部署成功: ${DeploySuccessTimeStr:-（无记录）}"
      [ -z "$DeployHook" ] && warn "没有 deploy hook，续期成功也不会写进 HAProxy 目录"
    else
      bad "没有域名配置 $CONF —— acme.sh 不认识它，不会续期"
      noconf_list="$noconf_list $DOM"
    fi
  else
    bad "acme.sh 里没有 $DOM 这个证书 —— 它不在自动续期范围内！"
    noconf_list="$noconf_list $DOM"
  fi
done

hdr "3. acme.sh 已知证书（raw）"
if [ -n "$ACME_SH" ]; then "$ACME_SH" --list --raw 2>&1 | sed "s/^/  /"; else warn "acme.sh 不可用"; fi

hdr "4. 手动跑一次 --cron（cron 每天做的事，看真实报错）"
if [ -n "$ACME_SH" ]; then
  timeout 180 "$ACME_SH" --cron 2>&1 | tail -40 | sed "s/^/    /"
else
  warn "acme.sh 不可用，跳过"
fi

hdr "5. 汇总"
if [ -n "$expired_list" ]; then bad "已过期:$expired_list"; else ok "没有已过期的证书"; fi
if [ -n "$noconf_list" ]; then bad "不在 acme.sh 续期范围内:$noconf_list"; fi
echo
echo "把上面完整输出贴回来即可定位。"
