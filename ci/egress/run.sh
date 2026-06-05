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

build_bins() {
  mkdir -p "$WORK/bin" "$WORK/cfg" "$WORK/certs" "$WORK/home"
  ( cd "$REPO" && go build -o "$WORK/bin/cc-mysub" ./cmd/cc-mysub \
                && go build -o "$WORK/bin/mock" ./ci/egress/mock \
                && go build -o "$WORK/bin/collector" ./ci/egress/collector \
                && go build -o "$WORK/bin/diag" ./ci/egress/diag ) || fail "go build"
  openssl req -x509 -newkey rsa:2048 -nodes -days 1 \
    -keyout "$WORK/certs/key.pem" -out "$WORK/certs/cert.pem" \
    -subj "/CN=$PROXY_HOST" -addext "subjectAltName=DNS:$PROXY_HOST" >/dev/null 2>&1 || fail "openssl"
  cat > "$WORK/cfg/config.json" <<JSON
{"listen":"127.0.0.1:443","tls":{"cert":"$WORK/certs/cert.pem","key":"$WORK/certs/key.pem"},
 "upstream_base_url":"http://127.0.0.1:9443",
 "client":{"public_host":"$PROXY_HOST","frps_ip":"127.0.0.1","subscription_type":"max"}}
JSON
  echo "{\"oauthToken\":\"$MOCKTEST\"}" > "$WORK/cfg/upstream.json"
  echo '[]' > "$WORK/cfg/devices.json"   # cc-mysub 启动即需此文件；enroll 追加后热重载
}

start_dns() {
  sed "s/__PROXY_HOST__/$PROXY_HOST/" "$ROOT/dnsmasq.conf.tmpl" > "$WORK/dnsmasq.conf"
  in_ns dnsmasq --conf-file="$WORK/dnsmasq.conf" --pid-file="$WORK/dnsmasq.pid"
  sleep 1
}

start_services() {
  in_ns bash -c "exec '$WORK/bin/mock'  > '$WORK/mock.out'  2>'$WORK/mock.err'" &
  in_ns bash -c "exec '$WORK/bin/collector' > '$WORK/coll.out' 2>'$WORK/coll.err'" &
  in_ns bash -c "exec '$WORK/bin/cc-mysub' --config-dir '$WORK/cfg' > '$WORK/cc.out' 2>'$WORK/cc.err'" &
  sleep 2
  in_ns timeout 3 bash -c 'exec 3<>/dev/tcp/127.0.0.1/443' 2>/dev/null || fail "cc-mysub not on :443"
  log "services up (cc-mysub:443 mock:9443 collector:127.0.0.2:443 dns:53)"
}

enroll() {
  TOK="$("$WORK/bin/cc-mysub" add-device --config-dir "$WORK/cfg" --label ci --out "$WORK/myclaude-ci" \
        2>/dev/null | grep -oE 'cco_dev_[0-9a-f]{48}' | head -1)"
  rm -f "$WORK/myclaude-ci"
  [ -n "${TOK:-}" ] || fail "failed to capture TOK from add-device"
  sleep 2   # 等 cc-mysub mtime 热重载 devices.json
  log "enrolled device 'ci', TOK captured (len=${#TOK})"
}

assert_dns() {
  test "$(in_ns dig +short @127.0.0.1 "$PROXY_HOST" A)" = "127.0.0.1" || fail "PROXY_HOST A != 127.0.0.1"
  test "$(in_ns dig +short @127.0.0.1 api.anthropic.com A)" = "127.0.0.2" || fail "catch-all A != 127.0.0.2"
  in_ns dig @127.0.0.1 api.anthropic.com AAAA | grep -q 'ANSWER: 0' || fail "AAAA not NODATA"
  log "DNS ok (A mapping + AAAA NODATA)"
}

curl_token_swap() {
  local out
  out="$(in_ns curl -s --max-time 10 --cacert "$WORK/certs/cert.pem" \
        -H "Authorization: Bearer $TOK" \
        -d '{"max_tokens":1024,"messages":[{"role":"user","content":"probe"}]}' \
        "https://$PROXY_HOST/v1/messages")" || true
  echo "$out" | grep -q '"text":"ok"' || fail "curl: no mock response (token-swap chain broken)"
  log "curl: token-swap chain reached mock"
}

prep_home() {
  cat > "$WORK/home/.claude.json" <<JSON
{"hasCompletedOnboarding":true,"projects":{"$WORK/home":{"hasTrustDialogAccepted":true}}}
JSON
}

run_claude() {
  prep_home
  log "running claude -p (timeout 120) ..."
  in_ns env HOME="$WORK/home" \
    ANTHROPIC_BASE_URL="https://$PROXY_HOST" \
    CLAUDE_CODE_OAUTH_TOKEN="$TOK" \
    CLAUDE_CODE_OAUTH_SCOPES="user:inference" \
    CLAUDE_CODE_SUBSCRIPTION_TYPE="max" \
    NODE_EXTRA_CA_CERTS="${CA_FOR_CLAUDE:-$WORK/certs/cert.pem}" \
    DISABLE_AUTOUPDATER=1 \
    timeout 120 claude -p "reply with the single word OK" > "$WORK/claude.out" 2>&1
  echo "[run.sh] claude rc=$?"
  echo "----- claude.out -----"; cat "$WORK/claude.out" 2>/dev/null | head -40; echo "----------------------"
}

dump_and_assert() {
  $SUDO pkill -INT -f "$WORK/bin/mock" 2>/dev/null || true
  $SUDO pkill -INT -f "$WORK/bin/collector" 2>/dev/null || true
  sleep 1
  echo "===== MOCK AUTHS ====="; cat "$WORK/mock.out" 2>/dev/null
  echo "===== EGRESS INVENTORY ====="; cat "$WORK/coll.out" 2>/dev/null
  # 断言 1：mock 只见 MOCKTEST、绝不含 TOK
  grep -q "Bearer $MOCKTEST" "$WORK/mock.out" 2>/dev/null || fail "ASSERT1: mock never saw MOCKTEST (token-swap/route broken)"
  if grep -q "$TOK" "$WORK/mock.out" 2>/dev/null; then fail "ASSERT1: placeholder TOK leaked to mock"; fi
  log "ASSERT1 ok: mock saw only MOCKTEST, no placeholder TOK"
  claude --version 2>/dev/null || true
}

# --- Phase 1 调查: TLS-MITM 刻画绕过 base_url 的直连 ---
WORK_CA="$WORK/ca"
gen_ca_and_leaf() {
  mkdir -p "$WORK_CA"
  openssl req -x509 -newkey rsa:2048 -nodes -days 1 -keyout "$WORK_CA/ca.key" -out "$WORK_CA/ca.crt" -subj "/CN=egress-ci-CA" >/dev/null 2>&1
  openssl req -newkey rsa:2048 -nodes -keyout "$WORK_CA/leaf.key" -out "$WORK_CA/leaf.csr" -subj "/CN=$PROXY_HOST" >/dev/null 2>&1
  openssl x509 -req -in "$WORK_CA/leaf.csr" -CA "$WORK_CA/ca.crt" -CAkey "$WORK_CA/ca.key" -CAcreateserial -days 1 \
    -extfile <(printf "subjectAltName=DNS:%s" "$PROXY_HOST") -out "$WORK_CA/leaf.crt" >/dev/null 2>&1
  cat > "$WORK/cfg/config.json" <<JSON
{"listen":"127.0.0.1:443","tls":{"cert":"$WORK_CA/leaf.crt","key":"$WORK_CA/leaf.key"},
 "upstream_base_url":"http://127.0.0.1:9443",
 "client":{"public_host":"$PROXY_HOST","frps_ip":"127.0.0.1","subscription_type":"max"}}
JSON
  echo "{\"oauthToken\":\"$MOCKTEST\"}" > "$WORK/cfg/upstream.json"
  echo '[]' > "$WORK/cfg/devices.json"
}
start_services_diag() {
  in_ns bash -c "exec '$WORK/bin/mock' > '$WORK/mock.out' 2>'$WORK/mock.err'" &
  in_ns bash -c "CA_CERT='$WORK_CA/ca.crt' CA_KEY='$WORK_CA/ca.key' exec '$WORK/bin/diag' > '$WORK/diag.out' 2>'$WORK/diag.err'" &
  in_ns bash -c "exec '$WORK/bin/cc-mysub' --config-dir '$WORK/cfg' > '$WORK/cc.out' 2>'$WORK/cc.err'" &
  sleep 2
  in_ns timeout 3 bash -c 'exec 3<>/dev/tcp/127.0.0.1/443' 2>/dev/null || fail "cc-mysub not on :443"
  log "services up (diag mode: mock + TLS-MITM diag + cc-mysub)"
}
stage_diag() {
  setup_netns; apply_firewall; build_bins; gen_ca_and_leaf; start_dns; start_services_diag; enroll
  CA_FOR_CLAUDE="$WORK_CA/ca.crt" run_claude
  $SUDO pkill -INT -f "$WORK/bin/diag" 2>/dev/null || true
  $SUDO pkill -INT -f "$WORK/bin/mock" 2>/dev/null || true
  sleep 1
  echo "===== MOCK AUTHS (经 cc-mysub 换 token 后) ====="; cat "$WORK/mock.out" 2>/dev/null
  echo "===== DIAG: 绕过 base_url 的直连 (TLS-MITM, 含 path + Authorization) ====="; cat "$WORK/diag.out" 2>/dev/null
}

stage1() { setup_netns; apply_firewall; selfcheck_seal; }
stage2() { setup_netns; apply_firewall; start_dns; assert_dns; }
stage3() { setup_netns; apply_firewall; build_bins; start_dns; start_services; enroll; curl_token_swap; }
stage4() { setup_netns; apply_firewall; build_bins; start_dns; start_services; enroll; selfcheck_seal; run_claude; dump_and_assert; }

case "$STAGE" in
  --stage1) stage1 ;;
  --stage2) stage2 ;;
  --stage3) stage3 ;;
  --stage4|--all) stage4 ;;
  --diag) stage_diag ;;
  *) echo "usage: $0 [--stage1|--stage2|--stage3|--stage4|--all|--diag]"; exit 2 ;;
esac
log "stage '$STAGE' done."
