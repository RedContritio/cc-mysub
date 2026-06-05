#!/usr/bin/env bash
# Phase 0 egress audit orchestration.
# 在 root network namespace 沙箱内（只有 lo、无外网卡=结构性密封）跑真 claude，
# 证明无占位 token 绕过 cc-mysub 到达官方，并枚举全量出网域名。
# 需 Linux + root（容器内）或 sudo（CI）。本机 macOS 请用 ci/egress/docker-run.sh 进容器。
set -uo pipefail

PROXY_HOST="ccapi.ci.local"
NS="egress-audit"
MOCKTEST="sk-ant-oat01-MOCKTEST"
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
#  This is the v4 split-egress coverage guard. It proves the two v4 invariants:
#    (A) Anthropic 收口: real `claude`, launched via `cc-mysub helper`, reaches
#        upstream carrying the SWAPPED real setup-token — the per-device
#        placeholder never leaves cc-mysub.
#    (B) 非 Anthropic 直连: non-allowlisted hosts are dialed DIRECT by the helper,
#        bypassing cc-mysub entirely (cc-mysub's allowlist would 403 them).
#
#  CI-VALIDATED, NOT RUN LOCALLY: this stage needs a privileged container (root
#  netns + iptables), a real `claude` install, and an audit CA installed into the
#  container system trust store. It is exercised only by .github/workflows/
#  egress-audit.yml. It was authored without a local docker run; expect CI
#  iteration on the v4-topology assumptions called out inline below.
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
  # v4 config: NO tls, NO upstream_base_url. cc-mysub presents public_host identity
  # (minted from its own CA, generated by add-device) and dials the real CONNECT host.
  cat > "$WORK/cfg/config.json" <<JSON
{"listen":"127.0.0.1:8788",
 "client":{"public_host":"$PROXY_HOST","frps_ip":"127.0.0.1","proxy_port":8788,"subscription_type":"max"}}
JSON
  echo "{\"oauthToken\":\"$MOCKTEST\"}" > "$WORK/cfg/upstream.json"
}

# gen_ccmysub_ca_via_enroll: run `cc-mysub add-device`, which on first run generates
# <cfg>/ca.crt (0644) + <cfg>/ca.key (0600) — cc-mysub's OWN CA, used both as the
# outer-TLS identity root and the inner-MITM signing root — and issues a per-device
# token. Capture that token (TOK) for the helper/claude env.
gen_ccmysub_ca_via_enroll() {
  TOK="$("$WORK/bin/cc-mysub" add-device --config-dir "$WORK/cfg" --label ci --out "$WORK/myclaude-ci" \
        2>/dev/null | grep -oE 'cco_dev_[0-9a-f]{48}' | head -1)"
  rm -f "$WORK/myclaude-ci"
  [ -n "${TOK:-}" ] || fail "failed to capture TOK from add-device"
  [ -f "$WORK/cfg/ca.crt" ] || fail "add-device did not generate ca.crt"
  [ -f "$WORK/cfg/ca.key" ] || fail "add-device did not generate ca.key"
  sleep 2   # 等 cc-mysub mtime 热重载 devices.json
  log "enrolled device 'ci', cc-mysub CA generated, TOK captured (len=${#TOK})"
}

start_dns_split() {
  # catch-all → 127.0.0.2 (api.anthropic.com lands here = mock); evil.example →
  # 127.0.0.3 (third-party sink); PROXY_HOST → 127.0.0.1 (cc-mysub). dnsmasq's more
  # specific address=/host/ entries override the catch-all address=/#/.
  cat > "$WORK/dnsmasq-split.conf" <<EOF
no-resolv
no-hosts
bind-interfaces
listen-address=127.0.0.1
address=/#/127.0.0.2
address=/evil.example/127.0.0.3
address=/$PROXY_HOST/127.0.0.1
EOF
  in_ns dnsmasq --conf-file="$WORK/dnsmasq-split.conf" --pid-file="$WORK/dnsmasq.pid"
  sleep 1
}

start_services_split() {
  # mock @127.0.0.2:443 presenting the api.anthropic.com leaf (TLS, system-trusted CA)
  in_ns bash -c "MOCK_ADDR=127.0.0.2:443 MOCK_TLS_CERT='$AUDIT_CA/api.anthropic.com.crt' MOCK_TLS_KEY='$AUDIT_CA/api.anthropic.com.key' exec '$WORK/bin/mock' > '$WORK/mock.out' 2>'$WORK/mock.err'" &
  # third-party sink @127.0.0.3:443 — collector reads the ClientHello SNI and records
  # it (it does not terminate TLS; the curl handshake will fail but the SNI is logged).
  in_ns bash -c "COLLECTOR_ADDR=127.0.0.3:443 exec '$WORK/bin/collector' > '$WORK/sink.out' 2>'$WORK/sink.err'" &
  # cc-mysub forward-proxy @127.0.0.1:8788 (v4: own CA in cfg, public_host identity)
  in_ns bash -c "exec '$WORK/bin/cc-mysub' --config-dir '$WORK/cfg' > '$WORK/cc.out' 2>'$WORK/cc.err'" &
  sleep 2
  in_ns timeout 3 bash -c 'exec 3<>/dev/tcp/127.0.0.1/8788' 2>/dev/null || fail "cc-mysub not on :8788"
  log "services up (cc-mysub:8788 mock:127.0.0.2:443/TLS sink:127.0.0.3:443 dns:53)"
}

stage_split() {
  # ---- v4 split-egress coverage guard (see banner above). CI-validated only. ----
  setup_netns
  apply_firewall_v4
  build_bins_v4
  gen_ccmysub_ca_via_enroll
  start_dns_split
  start_services_split

  local CC_CA="$WORK/cfg/ca.crt"   # cc-mysub's own CA (generated by add-device)

  # Probe A — Anthropic 收口: real claude via helper. claude trusts cc-mysub's CA
  # (NODE_EXTRA_CA_CERTS) for the MITM'd api.anthropic.com leaf; the helper routes
  # api.anthropic.com to cc-mysub over outer TLS; cc-mysub swaps TOK→MOCKTEST and
  # forwards to the (mock) real host.
  prep_home
  log "Probe A: running claude -p via cc-mysub helper (timeout 120) ..."
  in_ns env HOME="$WORK/home" \
    NODE_EXTRA_CA_CERTS="$CC_CA" \
    CLAUDE_CODE_OAUTH_TOKEN="$TOK" \
    CLAUDE_CODE_OAUTH_SCOPES="user:inference" \
    CLAUDE_CODE_SUBSCRIPTION_TYPE="max" \
    DISABLE_AUTOUPDATER=1 \
    timeout 120 "$WORK/bin/cc-mysub" helper \
      --upstream 127.0.0.1:8788 --server-name "$PROXY_HOST" --ca "$CC_CA" \
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
    --upstream 127.0.0.1:8788 --server-name "$PROXY_HOST" --ca "$CC_CA" \
    -- curl -s --cacert "$AUDIT_CA/ca.crt" --max-time 10 https://evil.example/probe \
    > "$WORK/curlB.out" 2>&1 || true
  sleep 1

  # Drain recorders (SIGINT flushes mock auths + sink inventory to stdout).
  $SUDO pkill -INT -f "$WORK/bin/mock" 2>/dev/null || true
  $SUDO pkill -INT -f "$WORK/bin/collector" 2>/dev/null || true
  sleep 1
  echo "===== MOCK AUTHS (经 cc-mysub 换 token 后) ====="; cat "$WORK/mock.out" 2>/dev/null
  echo "===== THIRD-PARTY SINK INVENTORY (direct-dial 落点) ====="; cat "$WORK/sink.out" 2>/dev/null

  # ---- Assertions ----
  # (A) Anthropic 收口: mock recorded the swapped REAL token.
  grep -q "Bearer $MOCKTEST" "$WORK/mock.out" 2>/dev/null \
    || fail "ASSERT-A: mock never saw Bearer $MOCKTEST (token-swap/route broken)"
  # 无占位泄漏: the per-device placeholder TOK must never reach the mock.
  if grep -q "$TOK" "$WORK/mock.out" 2>/dev/null; then
    fail "ASSERT-A: placeholder TOK leaked to mock (swap bypassed)"
  fi
  log "ASSERT-A ok: mock saw swapped MOCKTEST, no placeholder TOK leak"

  # (B) 非 Anthropic 直连: the sink recorded the evil.example connection.
  grep -q "evil.example" "$WORK/sink.out" 2>/dev/null \
    || fail "ASSERT-B: sink empty — helper did not direct-dial evil.example (routed via cc-mysub?)"
  log "ASSERT-B ok: helper direct-dialed evil.example (sink recorded it)"

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
