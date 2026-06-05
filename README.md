# CC MySub

一个 Go 单二进制，让**任意设备**上的真·Claude Code 通过**egress 收口**复用本机持有的单份订阅。
设备只设 `HTTPS_PROXY` 指向本地 `cc-mysub helper`（用户态、无系统改动）；helper **仅把 `api.anthropic.com`/`console.anthropic.com` 流量**经外层 TLS 转发到远程 cc-mysub forward-proxy，后者做内层 MITM token 换发；**其余一切**（WebFetch 目标、MCP、更新、第三方遥测、包管理器）helper 本地直连真主机，永不接触 cc-mysub。`base_url` 保持默认 `api.anthropic.com`，不改。

订阅凭据集中本机、永不下发；每台设备只持有一个可独立吊销的 per-device token。

它**不是** Web 终端——每台设备跑的是真正的 Claude Code CLI，本机只做纯传输代理。架构细节见 [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md)，安全与合规见 [`SECURITY.md`](SECURITY.md)。

## ⚠️ 安全前提

客户端是真 CC（不可改），无法在应用层做防重放签名。安全必须来自**信道加密**：cc-mysub 自有 CA 签发 `public_host` 身份证书，helper 用已下发 CA 公证书验证外层 TLS；设备经 `NODE_EXTRA_CA_CERTS` 信任 cc-mysub CA 做内层 MITM 验证。

frp 入口层必须用 **`type=tcp`** 透传——外层 TLS 由 cc-mysub 自己终结，frp 不可在边缘终结 TLS（`https`/`https2http` 在 v4 作废）。

## 入口层

远程暴露使用 frp **`type=tcp`** 透传（L4 直通，外层 TLS 完整到达 cc-mysub）。见 [`deploy/frpc.example.toml`](deploy/frpc.example.toml)。

## 客户端工作方式（v4 helper 形态）

`add-device` 生成的 `myclaude` wrapper 形如：

```bash
exec cc-mysub helper \
  --upstream <frps_ip:proxy_port> \
  --server-name <public_host> \
  --ca <path/to/ca.crt> \
  -- claude "$@"
```

wrapper 本身设置 `NODE_EXTRA_CA_CERTS`（信任 cc-mysub CA）、占位 `CLAUDE_CODE_OAUTH_TOKEN`、`CLAUDE_CODE_OAUTH_SCOPES=user:inference`、`CLAUDE_CODE_SUBSCRIPTION_TYPE`。`HTTPS_PROXY` 由 helper 在运行时注入（指向本地临时端口），**不在 wrapper 中硬编码**。

设备**无需设置 `ANTHROPIC_BASE_URL`**——`base_url` 保持默认 `api.anthropic.com`，helper 的分流逻辑负责把 Anthropic 流量路由到 cc-mysub。

这里涉及两个相互正交的判定，输入各自不同：

- **订阅认证模式**由 `CLAUDE_CODE_OAUTH_TOKEN` + `CLAUDE_CODE_OAUTH_SCOPES=user:inference` 决定：CC 据此走订阅 OAuth、带 `oauth-2025-04-20` beta，而非按 api-key 计费。
- **订阅档位 / tier 功能**由 `CLAUDE_CODE_SUBSCRIPTION_TYPE` 决定：缺它则 UI 显示 "Claude API"、auto 权限模式下的命令 classifier 不工作（卡在逐个命令确认）、1M 变体不可用；设为你的真实档位即可恢复 Max 标签、auto mode classifier 与 1M 变体可选。它是客户端本地的档位声明 env（CC 直读、不验真），与上面的认证模式相互独立。

注意 `CLAUDE_CODE_SUBSCRIPTION_TYPE` 只是客户端本地的自我声明，CC 不对其做真伪校验；上游真 Anthropic 是否接受这套，取决于本机代理后面挂的真 setup-token 的实际权限——它本就是给订阅用户使用的 env，但不代表凭它就能凭空获得相应权益。

仍须用 `CLAUDE_CODE_OAUTH_TOKEN`：用 `ANTHROPIC_AUTH_TOKEN` 会被判为非订阅凭据，丢失订阅行为。

### 订阅档位与 1M

1M 上下文是 Opus 4.8 的**可选变体**，不是默认。`CLAUDE_CODE_SUBSCRIPTION_TYPE=max` 解锁的只是"1M 变体可被选择"，默认仍是 200k。需在 CC 里用 `/model` 选 "Opus 4.8 (1M context)" 才切到 1M，切换后 `/status` 才会显示 1M。

### 已知限制

`/usage` 可能显示 "API"。它要连写死的域名 `platform.claude.com` 去拉订阅用量，恶劣网络（如 WSL）连不上时会 fallback 成 API 显示。这只是 `platform.claude.com` 的连通性问题，与 `CLAUDE_CODE_SUBSCRIPTION_TYPE` 无关，也不影响推理本身与订阅计费归属。

## 本机配置（`~/.config/cc-mysub/`）

| 文件 | 内容 | 权限 |
|---|---|---|
| `config.json` | `{"listen":"127.0.0.1:8788","client":{"public_host":"...","frps_ip":"...","proxy_port":8788,"subscription_type":"max"}}` | — |
| `upstream.json` | token 池：`{"oauthTokens":[{"id":"a","token":"sk-ant-oat01-..."}]}`（chmod 600；旧式 `{"oauthToken":"..."}` 单 token 仍可用）| chmod 600 |
| `devices.json` | `[{"label":"laptop","token_sha256":"...","upstream":"a","rate_limit":120}]`，由 `add-device` 维护；`upstream` 字段指向使用哪个池中 token | — |
| `ca.crt` | cc-mysub 自有 CA 公证书，由 `add-device` 首次生成，需拷到设备 | 0644 |
| `ca.key` | CA 私钥，由 `add-device` 首次生成，**永不入 git、永不离开本机** | 0600 |

代理只存 per-device token 的 sha256，从不存明文。文件改动通过 mtime polling 热重载，无需重启。

### 签发一台设备：`cc-mysub add-device`

把面向客户端的部署常量一次性写进 `config.json` 的 `client` 段（对一套部署固定不变，只有设备 label 与 token 每台不同）：

```json
{
  "listen": "127.0.0.1:8788",
  "client": {
    "public_host": "ccapi.example.com",
    "frps_ip": "203.0.113.10",
    "proxy_port": 8788,
    "subscription_type": "max"
  }
}
```

之后每台设备只需一条命令——它签发 per-device token、把 sha256 写入 `devices.json`、指定使用的池中 token id，并首次生成 `ca.crt`/`ca.key`（幂等：已存在则复用），最后生成一份**已填好**的 `myclaude` wrapper：

```bash
cc-mysub add-device --label laptop --upstream a
# → 打印交给该设备的明文 token（仅此一次）
# → 写入 devices.json（只存 sha256）
# → 首次生成 ca.crt / ca.key（已有则跳过）
# → 生成 ./myclaude-laptop（已填入 upstream / server-name / ca / token / 订阅档）
```

**设备部署三件事**：
1. 拷贝 `cc-mysub` 二进制（用于运行 `helper` 子命令）
2. 拷贝 `ca.crt`（公证书，路径见 add-device 输出）
3. 拷贝生成的 `myclaude-laptop` wrapper 到 PATH（如 `~/.local/bin/myclaude`）

之后在该设备上用 `myclaude` 代替 `claude` 即可。helper 直拨 `frps_ip:proxy_port` 的 cc-mysub forward-proxy，外层 TLS 验证其 `public_host` 身份；non-Anthropic 流量 helper 本地直连，不经 cc-mysub。

任一部署常量都可用 flag 覆盖：`cc-mysub add-device --label work --sub pro`（亦支持 `--host` / `--frps-ip` / `--proxy-port` / `--rate-limit` / `--out` / `--config-dir`）。生成的 wrapper **不会**替你预设 classifier 小模型（`ANTHROPIC_SMALL_FAST_MODEL`）；需要时取消 wrapper 里那行注释、自行填入即可。

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
