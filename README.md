# CC MySub

一个 Go 单二进制本地代理，让**任意设备**上的真·Claude Code 通过 `ANTHROPIC_BASE_URL` 指向你的本机，复用本机持有的**单份订阅** setup-token，完整保留订阅功能（包括 auto 权限模式）。订阅凭据集中本机、永不下发；每台设备只持有一个可独立吊销的 per-device token。

它**不是** Web 终端——每台设备跑的是真正的 Claude Code CLI，本机只做纯传输代理。架构细节见 [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md)，安全与合规见 [`SECURITY.md`](SECURITY.md)。

## ⚠️ 安全前提

客户端是真 CC（不可改），无法在应用层做防重放签名 → 安全必须来自**信道加密**。

**裸明文 http（零加密层）传 per-device token 不安全。** 请用下表任一加密信道暴露本机端口。代理代码对入口层无感，监听本地端口即可。

## 入口层加密矩阵

| 方案 | 客户端 `ANTHROPIC_BASE_URL` | 加密层 | 备注 |
|---|---|---|---|
| Tailscale / WireGuard（首推）| `http://<ts-ip>:8788` | 网络层 WireGuard | 零证书 / 零域名，穿透 NAT |
| 代理自签 TLS | `https://<host>:8788` | 代理 `config.tls` | 无域名；客户端设 `NODE_EXTRA_CA_CERTS` 指向自签 CA |
| 真域名 + Let's Encrypt | `https://<your-domain>` | frp `https2http` / 代理 TLS | 客户端零配置（见 `deploy/frpc.example.toml`）|

## 客户端配置

在每台设备上设置以下三个环境变量（`base_url` 取上表对应行）：

```bash
export ANTHROPIC_BASE_URL=<上表 base_url>
export CLAUDE_CODE_OAUTH_TOKEN=<你给该设备签发的 per-device token>
export CLAUDE_CODE_OAUTH_SCOPES=user:inference
```

必须用 `CLAUDE_CODE_OAUTH_TOKEN` + `CLAUDE_CODE_OAUTH_SCOPES=user:inference`，远程 CC 才会保持订阅模式而非降级为 API 计费。用 `ANTHROPIC_AUTH_TOKEN` 会被判为非订阅凭据，丢失订阅行为。

## 本机配置（`~/.config/cc-mysub/`）

| 文件 | 内容 | 权限 |
|---|---|---|
| `config.json` | `{"listen":"127.0.0.1:8788"}`（可选 `"tls":{"cert":...,"key":...}`）| — |
| `upstream.json` | `{"oauthToken":"sk-ant-oat01-..."}`，你的真 setup-token | chmod 600 |
| `devices.json` | `[{"label":"laptop","token_sha256":"<sha256 of per-device token>","rate_limit":120}]` | — |

代理只存 per-device token 的 sha256，从不存明文。文件改动通过 mtime polling 热重载，无需重启。

### 生成一个 per-device token 与其 hash

```bash
TOKEN=$(openssl rand -hex 24); echo "give to device: $TOKEN"
printf '%s' "$TOKEN" | shasum -a 256
```

把 `$TOKEN` 交给设备（填入该设备的 `CLAUDE_CODE_OAUTH_TOKEN`），把 `shasum` 输出的十六进制填入 `devices.json` 的 `token_sha256`。

**吊销**：删掉 `devices.json` 里对应那一行即可，热重载后该设备立即失效，其他设备无感。

## 运行

```bash
go build -o /usr/local/bin/cc-mysub ./cmd/cc-mysub
cc-mysub                       # 默认读 ~/.config/cc-mysub/
cc-mysub --config-dir /path    # 自定义配置目录
```

后台常驻见 [`deploy/com.user.cc-mysub.plist`](deploy/com.user.cc-mysub.plist)（launchd），远程暴露见 [`deploy/frpc.example.toml`](deploy/frpc.example.toml)。

## 报告漏洞

请开一个私有 security advisory（GitHub 仓库 → Security → Report a vulnerability），不要在公开 issue 中披露。详见 [`SECURITY.md`](SECURITY.md)。
