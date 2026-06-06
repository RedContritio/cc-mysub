# CC MySub

一个 Go 单二进制，让**任意设备**上的真·Claude Code 通过**egress 收口**复用本机持有的单份订阅。
设备只设 `HTTPS_PROXY` 指向本地 `cc-mysub helper`（用户态、无系统改动）；helper **仅把 `api.anthropic.com`/`console.anthropic.com` 流量**经外层双向 TLS（mTLS）转发到远程 cc-mysub forward-proxy，后者做内层 MITM token 换发；**其余一切**（WebFetch 目标、MCP、更新、第三方遥测、包管理器）helper 本地直连真主机，永不接触 cc-mysub。`base_url` 保持默认 `api.anthropic.com`，不改。

订阅凭据集中本机、永不下发；每台设备持有一份 per-device 客户端证书，**私钥在设备本地生成、永不离开设备**，按证书指纹独立吊销。

它**不是** Web 终端——每台设备跑的是真正的 Claude Code CLI，本机只做纯传输代理。架构细节见 [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md)，安全与合规见 [`SECURITY.md`](SECURITY.md)。

## ⚠️ 安全前提

客户端是真 CC（不可改），无法在应用层做防重放签名。安全来自**外层双向 TLS（mTLS）+ 证书指纹认证**：

- 外层服务端身份 = 真 LE 证书（`public_host`），设备走系统/公共信任验证——看着就是正常有效 HTTPS。
- 外层客户端身份 = per-device 自签客户端证书，设备本地 `device-init` 生成（**私钥永不离开设备**）；cc-mysub 在 TLS 握手时按其 **SHA-256(DER) 指纹白名单**认证（`devices.json`），无证书/未登记指纹→**握手即断、零应用字节**。
- 内层 MITM = cc-mysub 自有 CA 现签 `api.anthropic.com` 叶证书；设备经 `NODE_EXTRA_CA_CERTS` 信任该 CA。CA 仅用于内层，不参与外层。

frp 入口层用 **`type=https` SNI 透传**（不带 `https2http` 插件）——frps 读 ClientHello 的 SNI 路由、原样转发 TLS 流，**不终结**；外层 TLS+mTLS 由 cc-mysub 自己终结。设备经 `https://<public_host>` 访问，与同一 frps 上其它 https vhost 服务按 SNI 共用 443、无专属公网端口。

## 入口层

远程暴露使用 frp **`type=https` SNI 透传**（frps 按 SNI 路由、不终结 TLS，外层 TLS+mTLS 完整到达 cc-mysub）。见 [`deploy/frpc.example.toml`](deploy/frpc.example.toml)。

## 客户端工作方式（mTLS 形态）

`add-device` 生成的 `myclaude` wrapper 是**自举型 + 通用型**（无 per-device 秘密，全 fleet 可复用同一文件）：首次运行自动按 `uname` 下载对应平台的 `cc-mysub` 二进制（sha256 校验 fail-closed）、写出内联 CA 公证书、并跑一次 `cc-mysub device-init` 在设备本地生成密钥/证书并打印指纹。末行核心形如：

```bash
exec "$CC_MYSUB_BIN" helper \
  --host <public_host> \
  --client-cert ~/.config/cc-mysub/device.crt \
  --client-key  ~/.config/cc-mysub/device.key \
  -- claude "$@"
```

wrapper 本身设置 `NODE_EXTRA_CA_CERTS`（信任 cc-mysub CA 做内层 MITM 验证）、固定占位 `CLAUDE_CODE_OAUTH_TOKEN`、`CLAUDE_CODE_OAUTH_SCOPES=user:inference`、`CLAUDE_CODE_SUBSCRIPTION_TYPE`。`HTTPS_PROXY` 由 helper 在运行时注入（指向本地临时端口），**不在 wrapper 中硬编码**。占位 token 的值非凭据——身份由客户端证书承载，cc-mysub 忽略其值、按证书指纹识别设备并换发真 token。

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
| `config.json` | `{"listen":"127.0.0.1:8788","client":{"public_host":"...","subscription_type":"max"}}` | — |
| `upstream.json` | token 池：`{"oauthTokens":[{"id":"a","token":"sk-ant-oat01-..."}]}`（chmod 600；旧式 `{"oauthToken":"..."}` 单 token 仍可用）| chmod 600 |
| `devices.json` | `[{"label":"laptop","cert_sha256":"<64 lowercase hex>","upstream":"a","rate_limit":120}]`，由 `add-device` 维护；`cert_sha256` = 设备客户端证书指纹，`upstream` 指向使用哪个池中 token | — |
| `certs/<public_host>.{crt,key}` | 外层身份用的真 LE 证书+私钥；cc-mysub 自终结外层 TLS 时加载（续期热重载）| key 0600 |
| `ca.crt` | cc-mysub 自有 CA 公证书（仅内层 MITM 用），由 `add-device` 首次生成（幂等）；已内联进 wrapper，设备首次运行时自动写出 | 0644 |
| `ca.key` | 内层 MITM CA 私钥，由 `add-device` 首次生成，**永不入 git、永不离开本机** | 0600 |

代理只存 per-device 证书的指纹（公开值），从不持有设备私钥。文件改动通过 mtime polling 热重载，无需重启。

### 签发一台设备：`device-init`（设备）+ `add-device`（代理主机）

把面向客户端的部署常量一次性写进 `config.json` 的 `client` 段（对一套部署固定不变；通用 wrapper 无 per-device 秘密）：

```json
{
  "listen": "127.0.0.1:8788",
  "client": {
    "public_host": "ccapi.example.com",
    "subscription_type": "max"
  }
}
```

通用 wrapper 一次生成、全 fleet 复用：

```bash
cc-mysub add-device --label laptop --fingerprint <设备指纹> --release v1.0.0
# 入网是一次往返(私钥不离设备 + 逐设备认证的必然):
#  1) 把通用 wrapper 拷到设备 PATH, 首次运行 → 下载二进制 + 写 CA + device-init 打印本设备指纹后退出
#  2) 在代理主机: add-device --label <X> --fingerprint <上一步的指纹>  → 写 devices.json(cert_sha256)
#  3) 设备 re-run → mTLS 握手通过, 正常工作
# (本命令同时: 从 GitHub Releases 下载 SHA256SUMS 烤入 wrapper; 首次生成 ca.crt/ca.key)
```

### 设备接入（通用 wrapper + 一次登记往返）

把生成的通用 wrapper（如 `myclaude-laptop`，与任何设备同字节）拷到设备 PATH（如 `~/.local/bin/myclaude`）。首次运行自动按 `uname` 从 GitHub Releases 下载对应平台的 `cc-mysub` 二进制（sha256 校验 fail-closed）、写出内联 CA 到 `~/.config/cc-mysub/ca.crt`、跑 `device-init` 在本地生成 `device.key`(0600)/`device.crt` 并**打印本设备证书指纹**后退出，提示你去代理主机登记。登记（`add-device --fingerprint`）后 re-run 即正常。

- `--release <tag>` 必填，钉定二进制版本（无默认 latest，杜绝移动目标）。
- `--fingerprint <64hex>` 必填（或 `--client-cert <file>` 自动算指纹）= 设备 `device-init` 打印的指纹。
- 换证书：设备重跑 `device-init` 得新指纹 → `add-device --rotate --label <label> --fingerprint <newfp>` 原地换发（删旧指纹行=吊销旧证书、写新指纹、覆写 wrapper）。（`--rotate` 是布尔 flag，须与 `--label` 一起给。）
- 平台：`linux/darwin × amd64/arm64`（Windows 不支持，wrapper 是 bash）。
- 二进制托管点默认 `redcontritio/cc-mysub` 的 GitHub Releases，可经 config `client.release_repo` 或 `--release-repo` 覆盖。

之后在该设备上用 `myclaude` 代替 `claude` 即可。helper 拨 `<public_host>:443`（DNS 解析到 frps），外层 mTLS 出示本设备客户端证书 + 系统信任验真 LE；non-Anthropic 流量 helper 本地直连，不经 cc-mysub。

部署常量可用 flag 覆盖（`--host` / `--sub` / `--rate-limit` / `--upstream`(池 id) / `--release-repo` / `--out` / `--config-dir`）。生成的 wrapper **不会**替你预设 classifier 小模型（`ANTHROPIC_SMALL_FAST_MODEL`）；需要时取消 wrapper 里那行注释、自行填入即可。

代理热重载会自动加载新设备，无需重启。

**吊销**：删掉 `devices.json` 里对应那一行（该设备指纹）即可，热重载后该设备立即失效，其他设备无感。

## 运行

```bash
go build -o /usr/local/bin/cc-mysub ./cmd/cc-mysub
cc-mysub                       # 默认读 ~/.config/cc-mysub/
cc-mysub --config-dir /path    # 自定义配置目录
```

后台常驻见 [`deploy/com.user.cc-mysub.plist`](deploy/com.user.cc-mysub.plist)（launchd），远程暴露见 [`deploy/frpc.example.toml`](deploy/frpc.example.toml)。

## 报告漏洞

请开一个私有 security advisory（GitHub 仓库 → Security → Report a vulnerability），不要在公开 issue 中披露。详见 [`SECURITY.md`](SECURITY.md)。
