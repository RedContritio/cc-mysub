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

# 测试钩子: 写完 CA 即退出, 使 Task 3 用例不依赖 device-init/轮询(Task 4 在此后追加入网逻辑)。
[ -n "${CC_MYSUB_SKIP_ENROLL:-}" ] && exit 0
