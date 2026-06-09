#!/usr/bin/env bash
# Phase 0 egress audit orchestration.
# 在 root network namespace 沙箱内（只有 lo、无外网卡=结构性密封）跑真 claude，
# 证明无占位 token 绕过 cc-mysub 到达官方，并枚举全量出网域名。
# 需 Linux + root（容器内）或 sudo（CI）。本机 macOS 请用 ci/egress/docker-run.sh 进容器。
set -uo pipefail

PROXY_HOST="ccapi.ci.local"
NS="egress-audit"
MOCKTEST="sk-ant-oat01-MOCKTEST"
PLACEHOLDER="cco_dev_placeholder"   # claude/curl 烤入的固定占位 token（非凭据）；cc-mysub 按 mTLS 证书换真 token
REPO="$(cd "$(dirname "$0")/../.." && pwd)"
ROOT="$REPO/ci/egress"
WORK="/tmp/egress-work"
STAGE="${1:---all}"

SUDO=""; [ "$(id -u)" -ne 0 ] && SUDO="sudo"
in_ns() { $SUDO ip netns exec "$NS" "$@"; }

log() { echo "[run.sh] $*"; }
fail() { echo "[run.sh] FAIL: $*" >&2; exit 1; }

teardown() {
  $SUDO pkill -INT -f "$WORK/bin/" 2>/dev/null || true
  sleep 1
  $SUDO ip netns del "$NS" 2>/dev/null || true
  $SUDO rm -rf "/etc/netns/$NS" 2>/dev/null || true
}
trap teardown EXIT

setup_netns() {
  mkdir -p "$WORK"
  $SUDO ip netns del "$NS" 2>/dev/null || true
  $SUDO ip netns add "$NS"
  in_ns ip link set lo up                      # 新 netns 的 lo 默认 DOWN
  $SUDO mkdir -p "/etc/netns/$NS"
  echo "nameserver 127.0.0.1" | $SUDO tee "/etc/netns/$NS/resolv.conf" >/dev/null
}

apply_firewall() {
  # netns 已无外网卡（结构性密封）；default-DROP 为显式防御 + 让自检有意义。
  in_ns iptables  -P OUTPUT DROP
  in_ns iptables  -A OUTPUT -o lo -j ACCEPT
  in_ns ip6tables -P OUTPUT DROP 2>/dev/null || true
  in_ns ip6tables -A OUTPUT -o lo -j ACCEPT 2>/dev/null || true
}

selfcheck_seal() {
  # 写死公网 IP 字面量（绝不用域名——会被 catch-all DNS 引到回环放行区致盲）。
  local t
  for t in 1.1.1.1/443 1.1.1.1/80 1.1.1.1/65000; do
    if in_ns timeout 3 bash -c "exec 3<>/dev/tcp/${t%/*}/${t#*/}" 2>/dev/null; then
      fail "selfcheck: reached public ${t} (seal leak)"
    fi
  done
  if in_ns timeout 3 bash -c 'exec 3<>/dev/tcp/2606:4700:4700::1111/443' 2>/dev/null; then
    fail "selfcheck: reached public IPv6 :443 (seal leak)"
  fi
  log "selfcheck: public egress sealed (v4 :443/:80/:65000, v6 :443)"
}

# start_dns / assert_dns: topology-agnostic DNS stage helpers (used by stage2).
# Uses the v3 dnsmasq.conf.tmpl (catch-all→127.0.0.2 + PROXY_HOST→127.0.0.1), which
# stage2 only inspects (api.anthropic.com→.2, AAAA NODATA); stage_split has its own.
start_dns() {
  sed "s/__PROXY_HOST__/$PROXY_HOST/" "$ROOT/dnsmasq.conf.tmpl" > "$WORK/dnsmasq.conf"
  in_ns dnsmasq --conf-file="$WORK/dnsmasq.conf" --pid-file="$WORK/dnsmasq.pid"
  sleep 1
}

assert_dns() {
  test "$(in_ns dig +short @127.0.0.1 "$PROXY_HOST" A)" = "127.0.0.1" || fail "PROXY_HOST A != 127.0.0.1"
  test "$(in_ns dig +short @127.0.0.1 api.anthropic.com A)" = "127.0.0.2" || fail "catch-all A != 127.0.0.2"
  in_ns dig @127.0.0.1 api.anthropic.com AAAA | grep -q 'ANSWER: 0' || fail "AAAA not NODATA"
  log "DNS ok (A mapping + AAAA NODATA)"
}

# prep_home seeds a minimal ~/.claude.json so `claude -p` skips onboarding/trust
# prompts in the sealed netns. Used by stage_split (Probe A).
prep_home() {
  cat > "$WORK/home/.claude.json" <<JSON
{"hasCompletedOnboarding":true,"projects":{"$WORK/home":{"hasTrustDialogAccepted":true}}}
JSON
}

# =============================================================================
#  v4 SPLIT-EGRESS COVERAGE GUARD  (stage_split)
# -----------------------------------------------------------------------------
#  This is the v4 split-egress coverage guard, two-hop B model: claude → splitter →
#  A(cc-mysub) → B(统一出口 @127.0.0.2, records every SNI it receives). DNS sends only the
#  in-scope hosts to B; everything else → 直连 sink @127.0.0.3. It proves four invariants:
#    (A) Anthropic 收口: real `claude`, launched via `cc-mysub helper`, reaches B
#        carrying the SWAPPED real setup-token — the fixed placeholder token never
#        leaves cc-mysub.
#    (C) 透传转发经 A: in-scope passthrough hosts (datadog telemetry, downloads.claude.ai)
#        are chained to cc-mysub (logged as passthrough) and tunneled to B — not direct,
#        not 403'd.
#    (SCOPE) B 只收 in-scope: no out-of-scope host appears at B (DNS sends them to the sink;
#        a leak would mean cc-mysub over-forwarded).
#    (B) 非 Anthropic 直连: non-allowlisted hosts are dialed DIRECT by the helper,
#        bypassing cc-mysub entirely (cc-mysub's allowlist would 403 them), landing on
#        the sink — never on B.
#
#  RUN: needs a privileged container (root netns + iptables), a real `claude`
#  install, and the audit CA in the container system trust store. Run locally via
#  `ci/egress/docker-run.sh --split` or in CI via .github/workflows/egress-audit.yml.
#  mTLS-adapted: enroll = device-init (client cert) + add-device --fingerprint;
#  helper uses --host/--client-cert/--client-key; cc-mysub listens :443.
#
#  v4 audit wrinkle: cc-mysub forwards the inner request to the REAL CONNECT host
#  (api.anthropic.com:443) over HTTPS via http.DefaultTransport, which verifies
#  the server cert against SYSTEM roots. In the sealed netns catch-all DNS maps
#  api.anthropic.com → 127.0.0.2 where the mock runs, so the mock must present an
#  api.anthropic.com leaf signed by an audit CA that is installed into the
#  container trust store (update-ca-certificates) — otherwise cc-mysub's dial to
#  "upstream" fails TLS verification and the swap chain never completes.
# =============================================================================

AUDIT_CA="$WORK/audit-ca"   # audit CA + api.anthropic.com / evil.example leaves (system-trusted)

apply_firewall_v4() {
  # = apply_firewall (default-DROP OUTPUT, lo ACCEPT) + a QUIC bypass guard:
  # LOG+DROP udp dport 443. The lo ACCEPT (added by apply_firewall) precedes this
  # DROP, so localhost UDP is unaffected (DNS to 127.0.0.1:53 is udp:53, not :443).
  # In the sealed netns there is no real egress; this rule is a regression guard so
  # a future leak via QUIC/HTTP3 to :443 trips the LOG counter we assert on below.
  apply_firewall
  in_ns iptables -A OUTPUT -p udp --dport 443 -j LOG --log-prefix "QUIC-DROP " || true
  in_ns iptables -A OUTPUT -p udp --dport 443 -j DROP || true
}

# gen_audit_pki: one audit CA + leaves for api.anthropic.com and evil.example.
# The CA is installed into the container trust store so cc-mysub's default
# transport (system roots) trusts the mock's api.anthropic.com cert.
gen_audit_pki() {
  mkdir -p "$AUDIT_CA"
  openssl req -x509 -newkey rsa:2048 -nodes -days 1 \
    -keyout "$AUDIT_CA/ca.key" -out "$AUDIT_CA/ca.crt" \
    -subj "/CN=egress-audit-CA" >/dev/null 2>&1 || fail "openssl audit CA"
  local h
  for h in api.anthropic.com evil.example; do
    openssl req -newkey rsa:2048 -nodes -keyout "$AUDIT_CA/$h.key" -out "$AUDIT_CA/$h.csr" \
      -subj "/CN=$h" >/dev/null 2>&1 || fail "openssl csr $h"
    openssl x509 -req -in "$AUDIT_CA/$h.csr" -CA "$AUDIT_CA/ca.crt" -CAkey "$AUDIT_CA/ca.key" \
      -CAcreateserial -days 1 -extfile <(printf "subjectAltName=DNS:%s" "$h") \
      -out "$AUDIT_CA/$h.crt" >/dev/null 2>&1 || fail "openssl leaf $h"
  done
  # public_host 外层 TLS 身份叶 → <cfg>/certs/<host>.{crt,key}（cc-mysub main.go 从此加载外层证书；
  # helper 外层走系统信任验真，故同一 audit CA 进系统信任后这张叶即被信任）。
  mkdir -p "$WORK/cfg/certs"
  openssl req -newkey rsa:2048 -nodes -keyout "$WORK/cfg/certs/$PROXY_HOST.key" \
    -out "$AUDIT_CA/$PROXY_HOST.csr" -subj "/CN=$PROXY_HOST" >/dev/null 2>&1 || fail "openssl csr $PROXY_HOST"
  openssl x509 -req -in "$AUDIT_CA/$PROXY_HOST.csr" -CA "$AUDIT_CA/ca.crt" -CAkey "$AUDIT_CA/ca.key" \
    -CAcreateserial -days 1 -extfile <(printf "subjectAltName=DNS:%s" "$PROXY_HOST") \
    -out "$WORK/cfg/certs/$PROXY_HOST.crt" >/dev/null 2>&1 || fail "openssl leaf $PROXY_HOST"
  # Install audit CA into the container system trust store so cc-mysub's
  # http.DefaultTransport (system roots) trusts the mock's api.anthropic.com cert.
  $SUDO cp "$AUDIT_CA/ca.crt" /usr/local/share/ca-certificates/egress-audit-ca.crt 2>/dev/null \
    && $SUDO update-ca-certificates >/dev/null 2>&1 \
    || fail "install audit CA into system trust store (need ca-certificates + update-ca-certificates)"
}

build_bins_v4() {
  mkdir -p "$WORK/bin" "$WORK/cfg" "$WORK/home"
  ( cd "$REPO" && go build -o "$WORK/bin/cc-mysub" ./cmd/cc-mysub \
                && go build -o "$WORK/bin/mock" ./ci/egress/mock \
                && go build -o "$WORK/bin/collector" ./ci/egress/collector ) || fail "go build"
  gen_audit_pki
  # mTLS config: 外层 TLS 身份 = <cfg>/certs/<public_host>.{crt,key}（gen_audit_pki 签、audit CA 进系统信任）;
  # 内层 MITM 现签根 = <cfg>/ca.{crt,key}（add-device 生成）。cc-mysub listen :443（helper 写死拨 host:443）。
  cat > "$WORK/cfg/config.json" <<JSON
{"listen":"127.0.0.1:443",
 "client":{"public_host":"$PROXY_HOST","subscription_type":"max"}}
JSON
  echo "{\"oauthToken\":\"$MOCKTEST\"}" > "$WORK/cfg/upstream.json"
}

# gen_ccmysub_ca_and_enroll: mTLS enroll（信道 token 已删，身份由客户端证书承载）。
#   1) seed add-device（占位指纹）触发首次 EnsureCA → 生成 <cfg>/ca.crt(0644)+ca.key(0600)
#      = cc-mysub 自有 CA（外层身份现签根 + 内层 MITM 现签根）；随后清空 devices.json。
#   2) device-init（设备侧，XDG_CONFIG_HOME 控制落点）→ 生成 device.{key,crt} + 打印 SHA-256 指纹。
#   3) add-device --fingerprint <真指纹> 登记本设备（server 启动前写好，无需热重载）。
# 设备证书路径导出为 DEV_CRT/DEV_KEY 供 Probe A/B 的 helper 使用。
gen_ccmysub_ca_and_enroll() {
  # 1) 占位 seed → 生成 cc-mysub CA（仿 ci/install/run.sh）
  "$WORK/bin/cc-mysub" add-device --config-dir "$WORK/cfg" --label seed \
    --fingerprint "$(printf '%064d' 0)" >/dev/null 2>&1 || fail "seed add-device (CA gen)"
  [ -f "$WORK/cfg/ca.crt" ] || fail "add-device did not generate ca.crt"
  [ -f "$WORK/cfg/ca.key" ] || fail "add-device did not generate ca.key"
  echo '[]' > "$WORK/cfg/devices.json"   # 清掉 seed，只留下面登记的真设备

  # 2) device-init（XDG_CONFIG_HOME=$WORK/devhome → device.{key,crt} 落 $WORK/devhome/cc-mysub/）
  mkdir -p "$WORK/devhome"
  local fp
  fp="$(XDG_CONFIG_HOME="$WORK/devhome" "$WORK/bin/cc-mysub" device-init --label ci 2>&1 \
        | grep -oE '[0-9a-f]{64}' | head -1)"
  [ -n "$fp" ] || fail "device-init: no fingerprint captured"
  DEV_CRT="$WORK/devhome/cc-mysub/device.crt"
  DEV_KEY="$WORK/devhome/cc-mysub/device.key"
  { [ -f "$DEV_CRT" ] && [ -f "$DEV_KEY" ]; } || fail "device-init did not write device cert/key"

  # 3) 登记本设备指纹（逐设备显式授权 = add-device 唯一授予路径）
  "$WORK/bin/cc-mysub" add-device --config-dir "$WORK/cfg" --label ci \
    --fingerprint "$fp" >/dev/null 2>&1 || fail "add-device approve (register fingerprint)"
  log "enrolled device 'ci' via mTLS: cc-mysub CA generated, fingerprint ${fp:0:12}… registered"
}

start_dns_split() {
  # 两跳 B 模型的 DNS（v4）:只有 in-scope host → 127.0.0.2 (B=统一出口); 其余一切 → 127.0.0.3
  # (直连 sink)。这是「B 只收 A 的转发」可证的前提——范围外 host 在 DNS 上就到不了 B,
  # 故 B 即便被直连污染也不可能。in-scope = MITM 类 api.anthropic.com + 透传类 datadog/downloads
  # (须与 internal/hosts 一致)。PROXY_HOST → 127.0.0.1 (cc-mysub)。dnsmasq 的具体 address=/host/
  # 覆盖 catch-all address=/#/。
  cat > "$WORK/dnsmasq-split.conf" <<EOF
no-resolv
no-hosts
bind-interfaces
listen-address=127.0.0.1
address=/#/127.0.0.3
address=/api.anthropic.com/127.0.0.2
address=/http-intake.logs.us5.datadoghq.com/127.0.0.2
address=/downloads.claude.ai/127.0.0.2
address=/$PROXY_HOST/127.0.0.1
EOF
  in_ns dnsmasq --conf-file="$WORK/dnsmasq-split.conf" --pid-file="$WORK/dnsmasq.pid"
  sleep 1
}

start_services_split() {
  # B = 统一出口 @127.0.0.2:443:mock(TLS)。GetCertificate 回调枚举每个到达连接的 SNI
  # (= B 收到哪些 host);SNI=api.anthropic.com 时呈现 audit-CA 签的 api 叶(cc-mysub MITM
  # 换 token 后的转发须见系统信任叶才走得通),其余 SNI(datadog/downloads 透传)现签自签叶。
  in_ns bash -c "MOCK_ADDR=127.0.0.2:443 MOCK_TLS_CERT='$AUDIT_CA/api.anthropic.com.crt' MOCK_TLS_KEY='$AUDIT_CA/api.anthropic.com.key' exec '$WORK/bin/mock' > '$WORK/mock.out' 2>'$WORK/mock.err'" &
  # 直连 sink @127.0.0.3:443(= catch-all 落点)— collector 读 ClientHello SNI 记录范围外
  # 直连的 host(不终结 TLS;握手会失败但 SNI 已记)。范围外流量到这里、绝不到 B。
  in_ns bash -c "COLLECTOR_ADDR=127.0.0.3:443 exec '$WORK/bin/collector' > '$WORK/sink.out' 2>'$WORK/sink.err'" &
  # cc-mysub forward-proxy @127.0.0.1:443 (mTLS: 外层 certs/<host>, 内层 own CA, 按指纹认证设备)
  in_ns bash -c "exec '$WORK/bin/cc-mysub' --config-dir '$WORK/cfg' > '$WORK/cc.out' 2>'$WORK/cc.err'" &
  sleep 2
  in_ns timeout 3 bash -c 'exec 3<>/dev/tcp/127.0.0.1/443' 2>/dev/null || fail "cc-mysub not on :443"
  log "services up (cc-mysub:443 mock:127.0.0.2:443/TLS sink:127.0.0.3:443 dns:53)"
}

stage_split() {
  # ---- v4 split-egress coverage guard, mTLS-adapted (see banner above). ----
  setup_netns
  apply_firewall_v4
  selfcheck_seal   # 主动验证密封（netns 无外网卡；连任一公网 IP 必失败，连通=seal leak→fail）
  build_bins_v4
  gen_ccmysub_ca_and_enroll
  start_dns_split
  start_services_split

  local CC_CA="$WORK/cfg/ca.crt"   # cc-mysub 内层 MITM CA（add-device 生成；claude 经 NODE_EXTRA_CA_CERTS 信任）

  # Probe A — Anthropic 收口: real claude via helper. claude trusts cc-mysub's CA
  # (NODE_EXTRA_CA_CERTS) for the MITM'd api.anthropic.com leaf; the helper presents
  # the device client cert over outer mTLS and routes api.anthropic.com to cc-mysub;
  # cc-mysub identifies the device by cert fingerprint, swaps PLACEHOLDER→MOCKTEST,
  # and forwards to the (mock) real host.
  prep_home
  log "Probe A: running claude -p via cc-mysub helper (timeout 120) ..."
  in_ns env HOME="$WORK/home" \
    NODE_EXTRA_CA_CERTS="$CC_CA" \
    CLAUDE_CODE_OAUTH_TOKEN="$PLACEHOLDER" \
    CLAUDE_CODE_OAUTH_SCOPES="user:inference" \
    CLAUDE_CODE_SUBSCRIPTION_TYPE="max" \
    DISABLE_AUTOUPDATER=1 \
    timeout 120 "$WORK/bin/cc-mysub" helper \
      --host "$PROXY_HOST" --client-cert "$DEV_CRT" --client-key "$DEV_KEY" \
      -- claude -p "reply with the single word OK" > "$WORK/claude.out" 2>&1
  local claude_rc=$?
  echo "[run.sh] Probe A claude rc=$claude_rc"
  echo "----- claude.out -----"; head -40 "$WORK/claude.out" 2>/dev/null; echo "----------------------"

  # Probe B — 非 Anthropic 直连: curl via helper to evil.example. The helper dials
  # evil.example DIRECT (not allowlisted), so the connection lands on the sink
  # @127.0.0.3. If the helper wrongly chained it to cc-mysub, cc-mysub's allowlist
  # would 403 it and the sink would stay empty.
  log "Probe B: curl via cc-mysub helper to evil.example (direct-dial proof) ..."
  in_ns "$WORK/bin/cc-mysub" helper \
    --host "$PROXY_HOST" --client-cert "$DEV_CRT" --client-key "$DEV_KEY" \
    -- curl -s --cacert "$AUDIT_CA/ca.crt" --max-time 10 https://evil.example/probe \
    > "$WORK/curlB.out" 2>&1 || true
  sleep 1

  # Probe C — 透传转发: curl via helper to the in-scope passthrough hosts. These ARE in
  # the splitter allow (hosts.All()) → chained to cc-mysub → cc-mysub classifies them
  # passthrough → blind-tunnels to the real host → DNS maps it to B@127.0.0.2. curl -k
  # accepts B's self-signed leaf for the host; we only need B to record the SNI and
  # cc-mysub to log the passthrough. If cc-mysub wrongly 403'd them, B would never see
  # them; if the splitter wrongly direct-dialed them, cc-mysub would never log them.
  for ph in http-intake.logs.us5.datadoghq.com downloads.claude.ai; do
    log "Probe C: curl via cc-mysub helper to $ph (passthrough forward) ..."
    in_ns "$WORK/bin/cc-mysub" helper \
      --host "$PROXY_HOST" --client-cert "$DEV_CRT" --client-key "$DEV_KEY" \
      -- curl -sk --max-time 10 "https://$ph/probe" > "$WORK/curlC_$ph.out" 2>&1 || true
  done
  sleep 1

  # Drain recorders (SIGINT flushes mock auths + B SNI inventory + sink inventory to stdout).
  $SUDO pkill -INT -f "$WORK/bin/mock" 2>/dev/null || true
  $SUDO pkill -INT -f "$WORK/bin/collector" 2>/dev/null || true
  sleep 1
  echo "===== B (统一出口) OUTPUT: auths + SNI inventory ====="; cat "$WORK/mock.out" 2>/dev/null
  echo "===== 直连 SINK INVENTORY (catch-all 落点) ====="; cat "$WORK/sink.out" 2>/dev/null
  echo "===== cc-mysub passthrough 日志 (cc.err 摘录) ====="; grep -F "passthrough" "$WORK/cc.err" 2>/dev/null || echo "(无 passthrough 日志)"

  # ---- Assertions ----
  # (A) Anthropic 收口: B recorded the swapped REAL token (api.anthropic.com MITM via cc-mysub).
  grep -q "Bearer $MOCKTEST" "$WORK/mock.out" 2>/dev/null \
    || fail "ASSERT-A: B never saw Bearer $MOCKTEST (token-swap/route broken)"
  # 无占位泄漏: the fixed placeholder token must never reach B.
  if grep -q "$PLACEHOLDER" "$WORK/mock.out" 2>/dev/null; then
    fail "ASSERT-A: placeholder token leaked to B (swap bypassed)"
  fi
  log "ASSERT-A ok: B saw swapped MOCKTEST, no placeholder leak"

  # (C) 透传转发经 A: each passthrough host must (1) be logged by cc-mysub as a passthrough
  # tunnel — proves the splitter chained it to cc-mysub (not direct-dialed) — AND (2) appear
  # in B's SNI inventory — proves it reached the unified egress (cc-mysub didn't 403 it).
  for ph in http-intake.logs.us5.datadoghq.com downloads.claude.ai; do
    grep -F "passthrough" "$WORK/cc.err" 2>/dev/null | grep -qF "$ph" \
      || fail "ASSERT-C: cc-mysub never logged passthrough for $ph (splitter direct-dialed it? not chained)"
    grep -qF "$ph" "$WORK/mock.out" 2>/dev/null \
      || fail "ASSERT-C: B SNI inventory missing $ph (cc-mysub 403'd it? not forwarded to egress)"
  done
  log "ASSERT-C ok: datadog + downloads passthrough-forwarded via cc-mysub and reached B"

  # (SCOPE) B 只收 in-scope: no out-of-scope host may appear at B. evil.example was probed
  # (Probe B) and must land on the direct sink, never on B — DNS sends catch-all to .3, so a
  # leak here would mean cc-mysub forwarded something it shouldn't.
  if grep -q "evil.example" "$WORK/mock.out" 2>/dev/null; then
    fail "ASSERT-SCOPE: out-of-scope evil.example reached B (over-forwarding leak)"
  fi
  log "ASSERT-SCOPE ok: B inventory free of out-of-scope hosts (evil.example absent)"

  # (B) 非 Anthropic 直连: the sink recorded the evil.example connection (bypassed A, not at B).
  grep -q "evil.example" "$WORK/sink.out" 2>/dev/null \
    || fail "ASSERT-B: sink empty — helper did not direct-dial evil.example (routed via cc-mysub?)"
  log "ASSERT-B ok: helper direct-dialed evil.example (sink recorded it, never reached B)"

  # claude rc (non-fatal log; ASSERT-A above is the real proof inference reached upstream).
  log "Probe A claude rc=$claude_rc (non-fatal; ASSERT-A proves inference reached upstream)"

  # QUIC guard: log the udp:443 LOG/DROP counter. Zero is expected in the sealed
  # netns (no real egress); a nonzero count would mean claude attempted QUIC/:443.
  echo "===== QUIC GUARD (udp dpt:443 LOG/DROP counter) ====="
  in_ns iptables -L OUTPUT -v -n 2>/dev/null | grep -E 'udp dpt:443' || echo "(no udp:443 rule matched in listing)"
}

# Topology-agnostic stages: seal self-check and DNS mapping. Independent of the
# proxy egress model (v3 origin/fwdproxy or v4 split), so kept.
stage1() { setup_netns; apply_firewall; selfcheck_seal; }
stage2() { setup_netns; apply_firewall; start_dns; assert_dns; }

# RETIRED v3 stages (origin/fwdproxy + upstream_base_url model — deleted in v4):
#   stage3 (curl_token_swap), stage4 (run_claude via ANTHROPIC_BASE_URL),
#   stage_diag (TLS-MITM base_url-bypass diag), stage_proxytest (HTTPS_PROXY coverage
#   via fwdproxy). They wrote a `tls`+`upstream_base_url` config that v4 cc-mysub
#   ignores, and v4 cc-mysub needs ca.crt/ca.key + public_host to even start — so
#   none could launch v4 cc-mysub. Their replacement is stage_split. The build_bins/
#   start_services/run_claude/dump_and_assert/start_services_diag/gen_ca_and_leaf
#   helpers were v3-only and are deleted. ci/egress/fwdproxy (v3 mock splitter, now
#   superseded by the real `cc-mysub helper`) is deleted too. ci/egress/diag is kept
#   (TLS-MITM diagnostic + diag/mint_test.go). stage_proxytest also called an
#   undefined `gen_certs` (dead). Live: stage1/stage2 + stage_split.

case "$STAGE" in
  --stage1) stage1 ;;
  --stage2) stage2 ;;
  --split|--all) stage_split ;;   # --all now = v4 split-egress coverage guard
  *) echo "usage: $0 [--stage1|--stage2|--split|--all]"; exit 2 ;;
esac
log "stage '$STAGE' done."
