#!/usr/bin/env bash
# cc-mysub 设备自助入网安装器。
#   curl -fsSL <raw-url> | sh -s -- <configURL> [label]
# 无参时交互式提示 configURL + label。幂等可重跑。
set -euo pipefail

CONFIG_URL="${1:-}"; LABEL="${2:-}"
if [ -z "$CONFIG_URL" ]; then printf '部署配置 URL: ' >&2; read -r CONFIG_URL </dev/tty; fi
[ -n "$CONFIG_URL" ] || { echo "cc-mysub: 需要配置 URL" >&2; exit 1; }
if [ -z "$LABEL" ]; then
  printf '设备 label [%s]: ' "$(hostname)" >&2; read -r LABEL </dev/tty || true
  [ -n "$LABEL" ] || LABEL="$(hostname)"
fi

CFG="${HOME}/.config/cc-mysub"; BINDIR="${HOME}/.local/bin"; BIN="${BINDIR}/cc-mysub"; WRAP="${BINDIR}/myclaude"
mkdir -p "$CFG" "$BINDIR"

jget() {  # jget <key> < json(stdin)
  if command -v jq >/dev/null 2>&1; then jq -r ".$1 // empty"
  elif command -v python3 >/dev/null 2>&1; then python3 -c 'import sys,json;print(json.load(sys.stdin).get(sys.argv[1],""))' "$1"
  else echo "cc-mysub: 需要 jq 或 python3 解析配置" >&2; return 1; fi
}

echo "[cc-mysub] 拉取配置 ..." >&2
CONF="$(curl -fsSL "$CONFIG_URL")" || { echo "cc-mysub: 配置拉取失败 $CONFIG_URL" >&2; exit 1; }
PUBLIC_HOST="$(printf '%s' "$CONF" | jget public_host)"
SUB_TYPE="$(printf '%s' "$CONF" | jget subscription_type)"
RELEASE_REPO="$(printf '%s' "$CONF" | jget release_repo)"
RELEASE_TAG="$(printf '%s' "$CONF" | jget release_tag)"
CA_PEM="$(printf '%s' "$CONF" | jget ca_cert_pem)"
[ -n "$PUBLIC_HOST" ] && [ -n "$RELEASE_TAG" ] && [ -n "$CA_PEM" ] || { echo "cc-mysub: 配置缺 public_host/release_tag/ca_cert_pem" >&2; exit 1; }
[ -n "$RELEASE_REPO" ] || RELEASE_REPO="redcontritio/cc-mysub"
[ -n "$SUB_TYPE" ] || SUB_TYPE="max"

case "$(uname -s)/$(uname -m)" in
  Linux/x86_64)  PLAT=linux-amd64 ;;  Linux/aarch64) PLAT=linux-arm64 ;;
  Darwin/x86_64) PLAT=darwin-amd64 ;; Darwin/arm64)  PLAT=darwin-arm64 ;;
  *) echo "cc-mysub: 不支持平台 $(uname -s)/$(uname -m)" >&2; exit 1 ;;
esac
BASE="${CC_MYSUB_RELEASE_BASE_URL:-https://github.com}/${RELEASE_REPO}/releases/download/${RELEASE_TAG}"

sha256_of() { if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | awk '{print $1}'; else shasum -a 256 "$1" | awk '{print $1}'; fi; }

if [ ! -x "$BIN" ]; then
  echo "[cc-mysub] 下载二进制 $PLAT (sha256 校验) ..." >&2
  SUMS="$(curl -fsSL "$BASE/SHA256SUMS")" || { echo "cc-mysub: SHA256SUMS 拉取失败 (release $RELEASE_TAG?)" >&2; exit 1; }
  WANT="$(printf '%s\n' "$SUMS" | awk -v f="cc-mysub-$PLAT" '{n=$2; sub(/^\*/,"",n); if (n==f) print $1}' | head -1)"
  printf '%s' "$WANT" | grep -qE '^[0-9a-f]{64}$' || { echo "cc-mysub: SHA256SUMS 无 cc-mysub-$PLAT 条目" >&2; exit 1; }
  tmp="$(mktemp "${BIN}.XXXXXX")"
  curl -fsSL "$BASE/cc-mysub-$PLAT" -o "$tmp" || { rm -f "$tmp"; echo "cc-mysub: 二进制下载失败" >&2; exit 1; }
  got="$(sha256_of "$tmp")"
  [ "$got" = "$WANT" ] || { rm -f "$tmp"; echo "cc-mysub: sha256 校验失败 (供应链): got=$got want=$WANT" >&2; exit 1; }
  chmod 0755 "$tmp"; mv "$tmp" "$BIN"
fi

printf '%s\n' "$CA_PEM" > "$CFG/ca.crt"
echo "[cc-mysub] 二进制 + CA 就位。" >&2

# ⑤ device-init (幂等; 私钥不离机)
INIT_OUT="$(XDG_CONFIG_HOME="${HOME}/.config" "$BIN" device-init -label "$LABEL")"
FP="$(printf '%s' "$INIT_OUT" | grep -oE '[0-9a-f]{64}' | head -1)"
[ -n "$FP" ] || { echo "cc-mysub: device-init 未产出指纹" >&2; exit 1; }

echo >&2
echo "[cc-mysub] 本设备指纹:" >&2
echo "    $FP" >&2
echo "[cc-mysub] 请在代理主机登记: cc-mysub add-device --fingerprint $FP --label $LABEL" >&2

# ⑥ 轮询现有 mTLS 端点等批准 (零新增公网面)
probe_ok() {  # 用设备证书试 mTLS 握手 + CONNECT; 通过(已登记)=0
  local out
  out=$( { printf 'CONNECT api.anthropic.com:443 HTTP/1.1\r\nHost: x\r\n\r\n'; sleep 2; } | \
    openssl s_client -quiet -connect "$PUBLIC_HOST:443" -servername "$PUBLIC_HOST" \
      -cert "$CFG/device.crt" -key "$CFG/device.key" 2>&1 )
  printf '%s' "$out" | grep -qiE 'HTTP/1\.[01] 200'
}
if [ -z "${CC_MYSUB_SKIP_POLL:-}" ]; then
  echo "[cc-mysub] 等待批准中 (登记后自动继续; Ctrl-C 可中断, 稍后重跑本命令) ..." >&2
  DEADLINE=$(( $(date +%s) + 600 ))
  until probe_ok; do
    [ "$(date +%s)" -lt "$DEADLINE" ] || { echo "cc-mysub: 等待超时, 登记后重跑本命令即可。" >&2; exit 0; }
    sleep 4
  done
  echo "[cc-mysub] 已批准。" >&2
fi

# ⑦ 写 myclaude daily wrapper
cat > "$WRAP" <<WRAP
#!/usr/bin/env bash
D="\$HOME/.config/cc-mysub"
exec env \\
  NODE_EXTRA_CA_CERTS="\$D/ca.crt" \\
  CLAUDE_CODE_OAUTH_TOKEN="cco_dev_placeholder" \\
  CLAUDE_CODE_OAUTH_SCOPES="user:inference" \\
  CLAUDE_CODE_SUBSCRIPTION_TYPE="${SUB_TYPE}" \\
  "${BIN}" helper --host "${PUBLIC_HOST}" \\
    --client-cert "\$D/device.crt" --client-key "\$D/device.key" \\
    -- claude "\$@"
WRAP
chmod +x "$WRAP"

case ":$PATH:" in *":$BINDIR:"*) ;; *)
  echo 'export PATH="$HOME/.local/bin:$PATH"' >> "${HOME}/.bashrc"
  echo "[cc-mysub] 已加 ~/.local/bin 到 ~/.bashrc(重开终端或 source 生效)。" >&2 ;;
esac
echo "[cc-mysub] 完成 ✓  用法: myclaude  /  myclaude -p \"…\"" >&2
