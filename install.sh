#!/usr/bin/env bash
# cc-mysub 设备自助入网安装器。
#   curl -fsSL <raw-url> | bash -s -- <configURL> [label]   （本脚本用 bash 特性,勿用 | sh）
# 无参时交互式提示 configURL + label。幂等可重跑。
set -euo pipefail

CONFIG_URL="${1:-}"; LABEL="${2:-}"
if [ -z "$CONFIG_URL" ]; then printf '部署配置 URL: ' >&2; read -r CONFIG_URL </dev/tty || true; fi
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
# subscription_type 必填、不静默默认最高档:gen-config 已对空档位 fail-fast,合法 deploy.json 恒带此字段;
# 缺失只来自手编配置,据 SECURITY.md「按实际档位填写」与无静默默认纪律,fail-closed 报错而非默认 max。
[ -n "$SUB_TYPE" ] || { echo "cc-mysub: 配置缺 subscription_type(应由 gen-config 写入;按实际档位填写,勿手填 max)" >&2; exit 1; }
[ -n "$RELEASE_REPO" ] || RELEASE_REPO="redcontritio/cc-mysub"

case "$(uname -s)/$(uname -m)" in
  Linux/x86_64)  PLAT=linux-amd64 ;;  Linux/aarch64) PLAT=linux-arm64 ;;
  Darwin/x86_64) PLAT=darwin-amd64 ;; Darwin/arm64)  PLAT=darwin-arm64 ;;
  *) echo "cc-mysub: 不支持平台 $(uname -s)/$(uname -m)" >&2; exit 1 ;;
esac
BASE="${CC_MYSUB_RELEASE_BASE_URL:-https://github.com}/${RELEASE_REPO}/releases/download/${RELEASE_TAG}"

sha256_of() { if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | awk '{print $1}'; else shasum -a 256 "$1" | awk '{print $1}'; fi; }

# 供应链锚:无条件取 SHA256SUMS 求出钉定版本(release_tag)的 sha;重跑路径也据此核对,不因
# 「本地已有二进制」就跳过版本核对(否则 operator bump release_tag 后存量设备重跑得到旧二进制 + 成功提示)。
SUMS="$(curl -fsSL "$BASE/SHA256SUMS")" || { echo "cc-mysub: SHA256SUMS 拉取失败 (release $RELEASE_TAG?)" >&2; exit 1; }
WANT="$(printf '%s\n' "$SUMS" | awk -v f="cc-mysub-$PLAT" '{n=$2; sub(/^\*/,"",n); if (n==f) print $1}' | head -1)"
printf '%s' "$WANT" | grep -qE '^[0-9a-f]{64}$' || { echo "cc-mysub: SHA256SUMS 无 cc-mysub-$PLAT 条目 (release $RELEASE_TAG?)" >&2; exit 1; }

if [ -x "$BIN" ] && [ "$(sha256_of "$BIN")" = "$WANT" ]; then
  echo "[cc-mysub] 已装二进制即配置钉定版本 ($RELEASE_TAG), 跳过下载。" >&2
else
  [ ! -x "$BIN" ] || echo "[cc-mysub] 已装二进制与配置钉定 $RELEASE_TAG 不一致, 重新下载替换 ..." >&2
  echo "[cc-mysub] 下载二进制 $PLAT (sha256 校验) ..." >&2
  # 临时文件在中断(INT/TERM)或 errexit(如 sha256_of 失败)时不残留:未校验字节绝不留在 PATH 目录。
  # 仅在下载块内挂 trap,mv 落位后即撤,故后续轮询的 Ctrl-C 仍按默认终止、不被改写。
  trap 'rm -f "${tmp:-}"' EXIT
  trap 'rm -f "${tmp:-}"; exit 130' INT
  trap 'rm -f "${tmp:-}"; exit 143' TERM
  tmp="$(mktemp "${BIN}.XXXXXX")"
  curl -fsSL "$BASE/cc-mysub-$PLAT" -o "$tmp" || { echo "cc-mysub: 二进制下载失败" >&2; exit 1; }
  got="$(sha256_of "$tmp")"
  [ "$got" = "$WANT" ] || { echo "cc-mysub: sha256 校验失败 (供应链): got=$got want=$WANT" >&2; exit 1; }
  chmod 0755 "$tmp"; mv "$tmp" "$BIN"; tmp=""
  trap - EXIT INT TERM
fi

# CA 公证书 TOFU(SECURITY.md:108):首次拉配置时信任;已存在则与新值比对,内容不同即拒,绝不
# 静默轮换 NODE_EXTRA_CA_CERTS 信任锚(防配置托管点事后被换内容后,任一次重跑安装静默换 CA →
# 持该 CA 私钥的中间人可解密设备到 api.anthropic.com 的内层流量)。比对用命令替换归一化尾随换行。
if [ -f "$CFG/ca.crt" ]; then
  if [ "$(<"$CFG/ca.crt")" != "$(printf '%s' "$CA_PEM")" ]; then
    echo "cc-mysub: 既有 $CFG/ca.crt 与配置下发的 CA 不一致 —— 拒绝静默轮换信任锚(TOFU)。" >&2
    echo "  若确属有意轮换 CA:先带外核对新 CA 指纹无误,再删除 $CFG/ca.crt 重跑;否则核查配置 URL 是否被篡改。" >&2
    exit 1
  fi
  # 内容一致:幂等,沿用既有 ca.crt,不重写。
else
  printf '%s\n' "$CA_PEM" > "$CFG/ca.crt"; chmod 0644 "$CFG/ca.crt"  # §5 step4: 0644，不随 umask
fi
echo "[cc-mysub] 二进制 + CA 就位。" >&2

# ⑤ device-init (幂等; 私钥不离机)
INIT_OUT="$(XDG_CONFIG_HOME="${HOME}/.config" "$BIN" device-init -label "$LABEL")"
# 容失败提取(|| true):pipefail 下 grep 无匹配会让整条管道 rc=1,纯赋值即继承该 rc → errexit
# 会在下一行 guard 前直接终止脚本。加 || true 让指纹缺失走显式 guard 报错,而非无声中断。
FP="$(printf '%s' "$INIT_OUT" | grep -oE '[0-9a-f]{64}' | head -1 || true)"
[ -n "$FP" ] || { echo "cc-mysub: device-init 未产出指纹" >&2; exit 1; }

echo >&2
echo "[cc-mysub] 本设备指纹:" >&2
echo "    $FP" >&2
echo "[cc-mysub] 请在代理主机登记: cc-mysub add-device --fingerprint $FP --label $LABEL" >&2

# ⑥ 轮询现有 mTLS 端点等批准 (零新增公网面)
# 探针三态 (§6): approved = CONNECT 200(已登记) / unapproved = mTLS 拒未登记证书(继续等) /
#   unreachable = 连不上/DNS/超时(非批准问题 → 快退)。区分二者才不会把不可达白等到超时。
PROBE_OUT="" PROBE_STATE=""
probe() {  # 设 PROBE_STATE=approved|unapproved|unreachable; PROBE_OUT=探针原始输出(供错误摘要)
  # 看门狗(id 28):openssl s_client 无 -connect_timeout,stock macOS 也无 coreutils timeout。
  # 后台跑探针 + (sleep N && kill),令被 DROP/黑洞的 host 在 N 秒内被判 unreachable,而非吊死在
  # OS TCP/TLS 读超时(可达分钟级),保住注释自述的「unreachable 快退」契约。看门狗输出导向 /dev/null,
  # 故 kill 其后短暂存活的 sleep 子进程也不会占住命令替换捕获管道。N 可经 CC_MYSUB_PROBE_TIMEOUT 调。
  # 服务端验真(id 29):-verify_return_error 用系统信任验真 public_host 的服务端(LE)证书,与 helper
  # 运行时口径一致;验不过即中止握手 → 归入 unreachable(并由 probe_err_summary 提示证书问题),杜绝
  # 「任意能答 CONNECT 200 的 TLS 端点(DNS 污染/误配开放代理)被当成已批准」这一未经认证的批准信号。
  PROBE_OUT="$(
    set +e
    { printf 'CONNECT api.anthropic.com:443 HTTP/1.1\r\nHost: x\r\n\r\n'; sleep 2; } | \
      openssl s_client -quiet -verify_return_error \
        -connect "$PUBLIC_HOST:${CC_MYSUB_PROBE_PORT:-443}" -servername "$PUBLIC_HOST" \
        -cert "$CFG/device.crt" -key "$CFG/device.key" 2>&1 &
    op=$!
    ( sleep "${CC_MYSUB_PROBE_TIMEOUT:-8}"; kill "$op" 2>/dev/null ) >/dev/null 2>&1 &
    wd=$!
    wait "$op"
    kill "$wd" 2>/dev/null
  )" || true
  if printf '%s' "$PROBE_OUT" | grep -qiE 'HTTP/1\.[01] 200'; then
    PROBE_STATE=approved
  elif printf '%s' "$PROBE_OUT" | grep -qiE 'certificate required|bad certificate|alert .*certificate'; then
    PROBE_STATE=unapproved   # 服务端 alert 42/CertificateRequired = 未登记，继续等
  else
    PROBE_STATE=unreachable  # connect:errno/refused/DNS/no route/空输出/超时/服务端证书验不过
  fi
}
probe_err_summary() {  # 从最近探针输出摘一行可读错误; 取不到回退占位
  local s
  s=$(printf '%s' "$PROBE_OUT" | grep -ioE 'certificate verify failed|verify error[^,]*|unable to get local issuer certificate|self.signed certificate[^,]*|unknown ca|connection refused|connect:errno=[0-9]+|name or service not known|nodename nor servname[^,]*|no route to host|operation timed out|timed out|gethostbyname[^ ]*' | head -1)
  [ -n "$s" ] || s='无响应/超时'
  printf '%s' "$s"
}
if [ -z "${CC_MYSUB_SKIP_POLL:-}" ]; then
  echo "[cc-mysub] 等待批准中 (登记后自动继续; Ctrl-C 可中断, 稍后重跑本命令) ..." >&2
  DEADLINE=$(( $(date +%s) + 600 ))
  miss=0   # 连续 unreachable 计数: 容忍瞬断, 连续 3 次才判定不可达(避免一次抖动就退)
  while :; do
    probe
    case "$PROBE_STATE" in
      approved) break ;;
      unapproved) miss=0 ;;
      unreachable)
        miss=$((miss + 1))
        if [ "$miss" -ge 3 ]; then
          echo "cc-mysub: 无法连接 $PUBLIC_HOST:443（$(probe_err_summary)）——检查 host/DNS/frps" >&2
          exit 1
        fi ;;
    esac
    [ "$(date +%s)" -lt "$DEADLINE" ] || { echo "cc-mysub: 等待超时, 登记后重跑本命令即可。" >&2; exit 1; }
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

# 确保 ~/.local/bin 进 PATH。macOS 默认 zsh 不读 ~/.bashrc，故同时写 bash 与 zsh 的 rc(幂等)。
ensure_path_in() {  # ensure_path_in <rcfile>: 幂等追加 PATH 导出 + 提示 source
  local rc="$1" line='export PATH="$HOME/.local/bin:$PATH"'
  if [ -f "$rc" ] && grep -qF "$line" "$rc" 2>/dev/null; then return 0; fi
  printf '%s\n' "$line" >> "$rc"
  echo "[cc-mysub] 已加 ~/.local/bin 到 $rc(source $rc 或重开终端生效)。" >&2
}
case ":$PATH:" in
  *":$BINDIR:"*) ;;  # 已在 PATH，无需改 rc
  *)
    ensure_path_in "${HOME}/.bashrc"
    # zsh rc: 优先已存在的 ~/.zshrc，否则 ~/.zprofile；都无则按 $SHELL=zsh 建 ~/.zshrc
    if [ -f "${HOME}/.zshrc" ]; then ZRC="${HOME}/.zshrc"
    elif [ -f "${HOME}/.zprofile" ]; then ZRC="${HOME}/.zprofile"
    elif [ "${SHELL##*/}" = zsh ]; then ZRC="${HOME}/.zshrc"
    else ZRC=""; fi
    if [ -n "$ZRC" ]; then ensure_path_in "$ZRC"; fi ;;
esac
echo "[cc-mysub] 完成 ✓  用法: myclaude  /  myclaude -p \"…\"" >&2
