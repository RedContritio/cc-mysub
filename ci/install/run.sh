#!/usr/bin/env bash
# install.sh 自助入网端到端验证（真 mTLS 轮询 + 全链换 token）。
#
# 在 privileged Linux 容器内复用 ci/egress 手法跑通设备自助入网全流程：
#   1. 建真 cc-mysub 二进制 → 灌 release mock 目录(+SHA256SUMS)。
#   2. 一个 e2e CA（LE 替身）签 public_host 外层叶 + api.anthropic.com mock 上游叶，
#      入容器系统信任（仿 ci/egress gen_audit_pki）。
#   3. seed add-device 触发 EnsureCA 生成 cc-mysub 内层 MITM CA → gen-config 产部署 JSON。
#   4. mock 上游(api.anthropic.com:443) + cc-mysub(:443) + 本地 http 服务(release+deploy.json) 起真服务。
#   5. /etc/hosts 把 public_host→127.0.0.1、api.anthropic.com→127.0.0.2(mock)。
#   6. 后台跑 install.sh（不设 CC_MYSUB_SKIP_POLL → 真轮询），抓指纹 → operator add-device 批准 →
#      install 轮询自动通过、装好 myclaude。
#   7. 断言: install rc=0 且显示「已批准」；myclaude 就位；helper+curl /v1/messages 经全链到 mock,
#      mock 收到换发的真 token sk-ant-oat01-E2ETEST（非占位 cco_dev_placeholder）。
#
# 需 Linux + root（容器内）。本机 macOS 请用 ci/install/docker-run.sh 进容器跑。
set -uo pipefail

REPO="$(cd "$(dirname "$0")/../.." && pwd)"
WORK=/tmp/install-e2e
PUBLIC_HOST="ccapi.e2e.local"
UPSTREAM_HOST="api.anthropic.com"
MOCK_IP="127.0.0.2"
REAL_TOKEN="sk-ant-oat01-E2ETEST"
PLACEHOLDER="cco_dev_placeholder"   # myclaude wrapper 烤入的固定占位 token
RELTAG="v0.0.0-e2e"
RELREPO="redcontritio/cc-mysub"
HTTP_PORT=8099

log() { echo "[install-e2e] $*"; }
fail() { echo "[install-e2e] FAIL: $*" >&2; exit 1; }

MOCK_PID="" CC_PID="" HTTP_PID="" INSTALL_PID=""
teardown() {
  for p in "$INSTALL_PID" "$HTTP_PID" "$CC_PID" "$MOCK_PID"; do
    [ -n "$p" ] && kill "$p" 2>/dev/null || true
  done
}
trap teardown EXIT

# install.sh 用的平台串（容器在 arm64 主机上 → linux-arm64；CI amd64 → linux-amd64）。
case "$(uname -s)/$(uname -m)" in
  Linux/x86_64)  PLAT=linux-amd64 ;;  Linux/aarch64) PLAT=linux-arm64 ;;
  Darwin/x86_64) PLAT=darwin-amd64 ;; Darwin/arm64)  PLAT=darwin-arm64 ;;
  *) fail "unsupported platform $(uname -s)/$(uname -m)" ;;
esac
log "platform = $PLAT"

rm -rf "$WORK"
REL="$WORK/rel/$RELREPO/releases/download/$RELTAG"
CA="$WORK/e2e-ca"
mkdir -p "$WORK/bin" "$WORK/cfg/certs" "$WORK/home" "$REL" "$CA"

# ---- 1) 建真二进制 + 灌 release mock + SHA256SUMS ----
( cd "$REPO" && go build -o "$WORK/bin/cc-mysub" ./cmd/cc-mysub \
              && go build -o "$WORK/bin/mock" ./ci/egress/mock ) || fail "go build"
cp "$WORK/bin/cc-mysub" "$REL/cc-mysub-$PLAT"
( cd "$REL" && sha256sum "cc-mysub-$PLAT" > SHA256SUMS ) || fail "sha256sum"

# ---- 2) e2e CA（LE 替身）：签外层 public_host 叶 + mock 上游 api.anthropic.com 叶，入系统信任 ----
# 单 CA 双叶（仿 ci/egress gen_audit_pki）：
#   - public_host 叶 = cc-mysub 外层 TLS 身份（splitter 用系统信任验真，故 CA 须在 trust store）。
#   - api.anthropic.com 叶 = mock 上游身份（cc-mysub http.DefaultTransport 用系统信任验真）。
openssl req -x509 -newkey rsa:2048 -nodes -days 2 \
  -keyout "$CA/ca.key" -out "$CA/ca.crt" -subj "/CN=cc-mysub-e2e-CA" >/dev/null 2>&1 || fail "openssl CA"
gen_leaf() {  # gen_leaf <host> <out-basename>
  local h="$1" base="$2"
  openssl req -newkey rsa:2048 -nodes -keyout "$base.key" -out "$base.csr" \
    -subj "/CN=$h" >/dev/null 2>&1 || fail "openssl csr $h"
  openssl x509 -req -in "$base.csr" -CA "$CA/ca.crt" -CAkey "$CA/ca.key" -CAcreateserial -days 2 \
    -extfile <(printf "subjectAltName=DNS:%s" "$h") -out "$base.crt" >/dev/null 2>&1 || fail "openssl leaf $h"
}
gen_leaf "$PUBLIC_HOST" "$WORK/cfg/certs/$PUBLIC_HOST"
chmod 600 "$WORK/cfg/certs/$PUBLIC_HOST.key" # cc-mysub 启动校验外层私钥权限(P1-3),openssl 默认 644 会被拒
gen_leaf "$UPSTREAM_HOST" "$CA/$UPSTREAM_HOST"
cp "$CA/ca.crt" /usr/local/share/ca-certificates/cc-mysub-e2e-ca.crt \
  && update-ca-certificates >/dev/null 2>&1 \
  || fail "install e2e CA into system trust store (need ca-certificates + update-ca-certificates)"

# ---- 3) server 配置 + seed add-device 生成 cc-mysub 内层 MITM CA → gen-config 产部署 JSON ----
cat > "$WORK/cfg/config.json" <<JSON
{"listen":"127.0.0.1:443","client":{"public_host":"$PUBLIC_HOST","subscription_type":"max","release_repo":"$RELREPO"}}
JSON
echo "{\"oauthToken\":\"$REAL_TOKEN\"}" > "$WORK/cfg/upstream.json"
chmod 600 "$WORK/cfg/upstream.json" # cc-mysub 启动校验凭据文件权限(P1-3),group/other-readable 被拒
echo '[]' > "$WORK/cfg/devices.json"

# seed add-device：首次跑触发 EnsureCA 生成 ca.crt/ca.key（gen-config 内联其入部署配置）。
# 用全零占位指纹登记一台 throwaway 设备拿到 CA 副作用，随后把 devices.json 重置为空，
# 使「空设备 → 轮询拒 → operator 批准 → 轮询通过」的断言叙事干净。
"$WORK/bin/cc-mysub" add-device --config-dir "$WORK/cfg" --label seed \
  --fingerprint "$(printf '%064d' 0)" >/dev/null 2>&1 || fail "seed add-device (CA gen)"
[ -f "$WORK/cfg/ca.crt" ] || fail "seed add-device did not generate ca.crt"
[ -f "$WORK/cfg/ca.key" ] || fail "seed add-device did not generate ca.key"
echo '[]' > "$WORK/cfg/devices.json"

# gen-config（用 --config-dir 指向 e2e cfg）→ deploy.json 落 web 根。
"$WORK/bin/cc-mysub" gen-config --config-dir "$WORK/cfg" --release "$RELTAG" \
  > "$WORK/rel/deploy.json" || fail "gen-config"
grep -q "$PUBLIC_HOST" "$WORK/rel/deploy.json" || fail "deploy.json missing public_host"
grep -q "BEGIN CERTIFICATE" "$WORK/rel/deploy.json" || fail "deploy.json missing inlined CA"

# ---- 4) /etc/hosts: public_host→127.0.0.1(cc-mysub), api.anthropic.com→127.0.0.2(mock) ----
grep -q " $PUBLIC_HOST$" /etc/hosts 2>/dev/null || echo "127.0.0.1 $PUBLIC_HOST" >> /etc/hosts
grep -q " $UPSTREAM_HOST$" /etc/hosts 2>/dev/null || echo "$MOCK_IP $UPSTREAM_HOST" >> /etc/hosts

# ---- 5) 起真服务: mock 上游 / cc-mysub / release+deploy.json http 服务 ----
MOCK_ADDR="$MOCK_IP:443" MOCK_TLS_CERT="$CA/$UPSTREAM_HOST.crt" MOCK_TLS_KEY="$CA/$UPSTREAM_HOST.key" \
  "$WORK/bin/mock" > "$WORK/mock.out" 2>"$WORK/mock.err" &
MOCK_PID=$!
"$WORK/bin/cc-mysub" --config-dir "$WORK/cfg" > "$WORK/cc.out" 2>&1 &
CC_PID=$!
python3 -m http.server "$HTTP_PORT" --bind 127.0.0.1 --directory "$WORK/rel" \
  > "$WORK/http.out" 2>&1 &
HTTP_PID=$!

sleep 2
timeout 3 bash -c "exec 3<>/dev/tcp/127.0.0.1/443" 2>/dev/null || fail "cc-mysub not on 127.0.0.1:443"
timeout 3 bash -c "exec 3<>/dev/tcp/$MOCK_IP/443" 2>/dev/null || fail "mock not on $MOCK_IP:443"
curl -fsS "http://127.0.0.1:$HTTP_PORT/deploy.json" >/dev/null || fail "http server not serving deploy.json"
log "services up (cc-mysub:443 mock:$MOCK_IP:443/TLS http:$HTTP_PORT)"

# ---- 6) 后台跑 install.sh（真轮询）；抓指纹 → operator add-device 批准 ----
BASE_URL="http://127.0.0.1:$HTTP_PORT"
HOME="$WORK/home" CC_MYSUB_RELEASE_BASE_URL="$BASE_URL" \
  bash "$REPO/install.sh" "$BASE_URL/deploy.json" e2ebox > "$WORK/install.log" 2>&1 &
INSTALL_PID=$!
log "install.sh 后台启动 (pid=$INSTALL_PID)，等待设备指纹 ..."

FP=""
for _ in $(seq 1 60); do
  FP="$(grep -oE '[0-9a-f]{64}' "$WORK/install.log" 2>/dev/null | head -1)"
  [ -n "$FP" ] && break
  kill -0 "$INSTALL_PID" 2>/dev/null || break
  sleep 1
done
if [ -z "$FP" ]; then echo "----- install.log -----"; cat "$WORK/install.log"; fail "no fingerprint from install.sh"; fi
log "device fingerprint = $FP"

# operator 批准：把指纹登记进 devices.json（cc-mysub 1s 内热重载）。
"$WORK/bin/cc-mysub" add-device --config-dir "$WORK/cfg" --label e2ebox \
  --fingerprint "$FP" >/dev/null 2>&1 || fail "add-device approve"
log "operator 已 add-device 批准 e2ebox；等待 install.sh 轮询通过 ..."

# ---- 7) 等 install.sh 收尾（轮询通过 = rc 0）----
RC=1
for _ in $(seq 1 40); do
  if ! kill -0 "$INSTALL_PID" 2>/dev/null; then wait "$INSTALL_PID"; RC=$?; break; fi
  sleep 1
done
echo "----- install.log -----"; cat "$WORK/install.log"; echo "-----------------------"
kill -0 "$INSTALL_PID" 2>/dev/null && fail "install.sh did not finish after approval (轮询卡住)"
[ "$RC" -eq 0 ] || fail "install.sh exit code $RC (期望 0)"
grep -q "已批准" "$WORK/install.log" || fail "install.sh 未显示 '已批准'（轮询未通过）"
log "ASSERT-轮询通过 ✓: install.sh 自助入网完成 (rc=0, 显示 '已批准')"

MYCLAUDE="$WORK/home/.local/bin/myclaude"
[ -x "$MYCLAUDE" ] || fail "myclaude 未就位 ($MYCLAUDE)"
log "ASSERT-myclaude 就位 ✓: $MYCLAUDE"

# ---- 8) 跑全链(helper+curl /v1/messages)→ mock；断言换发真 token ----
# 与 myclaude wrapper 同构：helper 出示本设备客户端证书做外层 mTLS、注入 HTTPS_PROXY 指向本地分流器，
# curl 带占位 token 经分流器→cc-mysub→内层 MITM→真上游(mock)。cc-mysub 按 mTLS 设备身份换发真 token。
D="$WORK/home/.config/cc-mysub"
"$WORK/bin/cc-mysub" helper --host "$PUBLIC_HOST" \
  --client-cert "$D/device.crt" --client-key "$D/device.key" \
  -- curl -s --max-time 15 --cacert "$D/ca.crt" \
     -H "Authorization: Bearer $PLACEHOLDER" \
     -H "content-type: application/json" \
     -H "anthropic-version: 2023-06-01" \
     -d '{"model":"claude-opus-4-8","max_tokens":1,"messages":[{"role":"user","content":"hi"}]}' \
     "https://$UPSTREAM_HOST/v1/messages" > "$WORK/curl.out" 2>"$WORK/curl.err"
echo "----- curl.out -----"; cat "$WORK/curl.out"; echo; echo "--------------------"

# drain mock（SIGINT 让 mock 把收到的 Authorization 刷到 stdout）。
[ -n "$MOCK_PID" ] && kill -INT "$MOCK_PID" 2>/dev/null || true
sleep 1
echo "===== MOCK AUTHS (经 cc-mysub 换 token 后) ====="; cat "$WORK/mock.out"

grep -q "Bearer $REAL_TOKEN" "$WORK/mock.out" \
  || fail "ASSERT: mock 未收到换发真 token Bearer $REAL_TOKEN（换 token/路由断裂）"
if grep -q "$PLACEHOLDER" "$WORK/mock.out"; then
  fail "ASSERT: 占位 token $PLACEHOLDER 泄漏到 mock（换 token 被绕过）"
fi
log "ASSERT-换 token ✓: mock 收到换发真 token Bearer $REAL_TOKEN，无占位泄漏"

log "e2e PASS ✓ — install.sh 自助入网 + 真 mTLS 轮询 + add-device 批准 + 全链换 token 全过"
