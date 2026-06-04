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

在每台设备上设置以下四个环境变量（`base_url` 取上表对应行）：

```bash
export ANTHROPIC_BASE_URL=<上表 base_url>
export CLAUDE_CODE_OAUTH_TOKEN=<你给该设备签发的 per-device token>
export CLAUDE_CODE_OAUTH_SCOPES=user:inference
export CLAUDE_CODE_SUBSCRIPTION_TYPE=<你的订阅档: pro / max / team / enterprise>
```

这里涉及两个相互正交的判定，输入各自不同：

- **订阅认证模式**由 `CLAUDE_CODE_OAUTH_TOKEN` + `CLAUDE_CODE_OAUTH_SCOPES=user:inference` 决定：CC 据此走订阅 OAuth、带 `oauth-2025-04-20` beta，而非按 api-key 计费。
- **订阅档位 / tier 功能**由 `CLAUDE_CODE_SUBSCRIPTION_TYPE` 决定：缺它则 UI 显示 "Claude API"、auto 权限模式下的命令 classifier 不工作（卡在逐个命令确认）、1M 变体不可用；设为你的真实档位即可恢复 Max 标签、auto mode classifier 与 1M 变体可选。它是客户端本地的档位声明 env（CC 直读、不验真），与上面的认证模式相互独立。

注意 `CLAUDE_CODE_SUBSCRIPTION_TYPE` 只是客户端本地的自我声明，CC 不对其做真伪校验；上游真 Anthropic 是否接受这套，取决于本机代理后面挂的真 setup-token 的实际权限——它本就是给订阅用户使用的 env，但不代表凭它就能凭空获得相应权益。

仍须用 `CLAUDE_CODE_OAUTH_TOKEN`：用 `ANTHROPIC_AUTH_TOKEN` 会被判为非订阅凭据，丢失订阅行为。

> 实践中你**不必手动设置**这些 env——用 [`cc-mysub add-device`](#签发一台设备cc-mysub-add-device) 在签发设备时生成的 `myclaude` wrapper 会自动设好它们（含 `base_url`、token、scope、订阅档），你在设备上直接运行 `myclaude` 即可。上面的语义说明用于理解每个 env 的作用。

### 订阅档位与 1M

1M 上下文是 Opus 4.8 的**可选变体**，不是默认。`CLAUDE_CODE_SUBSCRIPTION_TYPE=max` 解锁的只是"1M 变体可被选择"，默认仍是 200k。需在 CC 里用 `/model` 选 "Opus 4.8 (1M context)" 才切到 1M，切换后 `/status` 才会显示 1M。

### 已知限制

`/usage` 可能显示 "API"。它要连写死的域名 `platform.claude.com` 去拉订阅用量，恶劣网络（如 WSL）连不上时会 fallback 成 API 显示。这只是 `platform.claude.com` 的连通性问题，与 `CLAUDE_CODE_SUBSCRIPTION_TYPE` 无关，也不影响推理本身与订阅计费归属。

## 本机配置（`~/.config/cc-mysub/`）

| 文件 | 内容 | 权限 |
|---|---|---|
| `config.json` | `{"listen":"127.0.0.1:8788"}`（可选 `"tls":{...}`、`"client":{...}`，见下）| — |
| `upstream.json` | `{"oauthToken":"sk-ant-oat01-..."}`，你的真 setup-token | chmod 600 |
| `devices.json` | `[{"label":"laptop","token_sha256":"<sha256 of per-device token>","rate_limit":120}]`，由 `add-device` 维护 | — |

代理只存 per-device token 的 sha256，从不存明文。文件改动通过 mtime polling 热重载，无需重启。

### 签发一台设备：`cc-mysub add-device`

把面向客户端的部署常量一次性写进 `config.json` 的 `client` 段（对一套部署固定不变，只有设备 label 与 token 每台不同）：

```json
{
  "listen": "127.0.0.1:8788",
  "client": {
    "public_host": "ccapi.example.com",
    "frps_ip": "203.0.113.10",
    "subscription_type": "max"
  }
}
```

之后每台设备只需一条命令——它签发 per-device token、把 sha256 写入 `devices.json`，并生成一份**已填好**的 `myclaude` wrapper：

```bash
cc-mysub add-device --label laptop
# → 打印交给该设备的明文 token（仅此一次）
# → 写入 devices.json（只存 sha256）
# → 生成 ./myclaude-laptop（已填入 host / frps_ip / token / 订阅档）
```

把生成的 `myclaude-laptop` 拷到该设备的 PATH（如 `~/.local/bin/myclaude`），之后在该设备上用 `myclaude` 代替 `claude` 即可——wrapper 内部设置好上面那四个 env、把代理域名直连 frps IP（绕本地 DNS 分流）、跳过 onboarding 预检，再把所有参数透传给真 `claude`。

任一部署常量都可用 flag 覆盖：`cc-mysub add-device --label work --sub pro`（亦支持 `--host` / `--frps-ip` / `--rate-limit` / `--out` / `--config-dir`）。生成的 wrapper **不会**替你预设 classifier 小模型（`ANTHROPIC_SMALL_FAST_MODEL`）；需要时取消 wrapper 里那行注释、自行填入即可。

代理热重载会自动加载新设备，无需重启。

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
