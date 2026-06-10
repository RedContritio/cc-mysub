# CC MySub 运维手册

[`README.md`](../README.md) 是普通用户的快速上手(搭服务端 + 接设备)。本文是部署者的完整参考:工作原理、配置项、设备生命周期、入口层选择与常驻。架构见 [`ARCHITECTURE.md`](ARCHITECTURE.md),安全模型与合规见 [`../SECURITY.md`](../SECURITY.md)。

## 工作原理(mTLS 形态)

客户端是真 Claude Code(不可改),无法在应用层做防重放签名。安全来自**外层双向 TLS(mTLS)+ 证书指纹认证**,三个相互独立的 TLS 角色:

- **外层服务端身份** = 真 LE 证书(`public_host`),设备走系统/公共信任验证——看着就是正常有效 HTTPS。
- **外层客户端身份** = per-device 自签客户端证书,设备本地 `device-init` 生成(**私钥永不离开设备**);cc-mysub 在 TLS 握手时按其 **SHA-256(DER) 指纹白名单**(`devices.json`)认证,无证书/未登记指纹 → **握手即断、零应用字节**。
- **内层 MITM** = cc-mysub 自有 CA 现签 `api.anthropic.com` 叶证书;设备经 `NODE_EXTRA_CA_CERTS` 信任该 CA。该 CA 仅用于内层,不参与外层。

设备按 **fail-closed 后缀通配(档位 C)** 分流:`api.anthropic.com`/`console.anthropic.com` 经外层 mTLS 转发到 cc-mysub(内层 MITM 换 token);其余自家域名(`*.anthropic.com`/`*.claude.ai`/`*.claude.com`/`*.claudeusercontent.com`/`*.ant.dev`)与第三方遥测/MCP(`http-intake.logs.us5.datadoghq.com`/`api.datadoghq.com`/`mcp.sentry.dev`/`claude*.fedstart.com`)经 mTLS 链到 cc-mysub 走**纯透传盲隧道**(不解密、不换 token,仅收口出口 IP);只有**非自家第三方**(WebFetch 目标、用户自配 MCP、`raw.githubusercontent.com`、包管理器)helper 本地直连真主机,永不接触 cc-mysub。`base_url` 保持默认 `api.anthropic.com`,不改。分流判据权威在 `internal/hosts.Classify`,与 cc-mysub 侧同源。

订阅凭据集中服务器、永不下发;每台设备持有一份 per-device 客户端证书,按指纹独立吊销。

### 设备端 `myclaude` wrapper

`install.sh` 在自助入网时把 `myclaude` 写到 `~/.local/bin/myclaude`——薄封装,只设环境并 `exec cc-mysub helper`。下载二进制(按 `uname`、`SHA256SUMS` 校验 fail-closed)、写出内层 CA、跑 `device-init` 在本地生成密钥/证书并打印指纹这些自举步骤由 `install.sh` 完成,不在 wrapper 运行时。wrapper 末行核心形如:

```bash
exec env \
  NODE_EXTRA_CA_CERTS=~/.config/cc-mysub/ca.crt \
  CLAUDE_CODE_OAUTH_TOKEN=cco_dev_placeholder \
  CLAUDE_CODE_OAUTH_SCOPES=user:inference \
  CLAUDE_CODE_SUBSCRIPTION_TYPE=<tier> \
  ~/.local/bin/cc-mysub helper --host <public_host> \
    --client-cert ~/.config/cc-mysub/device.crt \
    --client-key  ~/.config/cc-mysub/device.key \
    -- claude "$@"
```

- `NODE_EXTRA_CA_CERTS` 让 CC 信任 cc-mysub CA 做内层 MITM 验证。
- `CLAUDE_CODE_OAUTH_TOKEN` 是固定占位(`cco_dev_placeholder`),**值非凭据**——身份由客户端证书承载,cc-mysub 忽略其值、按证书指纹识别设备并换发真 token。
- `HTTPS_PROXY` 由 helper 在运行时注入(指向本地临时端口),**不在 wrapper 中硬编码**。
- 设备**无需设置 `ANTHROPIC_BASE_URL`**——`base_url` 保持默认,helper 的分流逻辑负责把 Anthropic 流量路由到 cc-mysub。

### 两个正交判定

env 里有两个相互独立、输入不同的判定:

- **订阅认证模式**由 `CLAUDE_CODE_OAUTH_TOKEN` + `CLAUDE_CODE_OAUTH_SCOPES=user:inference` 决定:CC 据此走订阅 OAuth、带 `oauth-2025-04-20` beta,而非按 api-key 计费。
- **订阅档位 / tier 功能**由 `CLAUDE_CODE_SUBSCRIPTION_TYPE` 决定:缺它则 UI 显示 "Claude API"、auto 权限模式下的命令 classifier 不工作(卡在逐个命令确认)、1M 变体不可用;设为真实档位即可恢复 Max 标签、auto mode classifier 与 1M 变体可选。它是客户端本地的档位声明 env(CC 直读、不验真)。

注意 `CLAUDE_CODE_SUBSCRIPTION_TYPE` 只是客户端本地自我声明,CC 不校验真伪;上游真 Anthropic 是否接受取决于代理后面挂的真 setup-token 的实际权限。仍须用 `CLAUDE_CODE_OAUTH_TOKEN`:用 `ANTHROPIC_AUTH_TOKEN` 会被判为非订阅凭据,丢失订阅行为。

### 订阅档位与 1M

1M 上下文是 Opus 4.8 的**可选变体**,不是默认。`CLAUDE_CODE_SUBSCRIPTION_TYPE=max` 解锁的只是"1M 变体可被选择",默认仍是 200k。需在 CC 里用 `/model` 选 "Opus 4.8 (1M context)" 才切到 1M,切换后 `/status` 才会显示 1M。

### 已知限制:`/usage` 限额条

`/usage` 的**订阅用量限额条**(5 小时 / 每周那些)显示不出来。真因是 **OAuth scope**:限额数据来自 `api.anthropic.com/api/oauth/usage`,该端点要求 `user:profile` scope,而 `claude setup-token` 生成的凭据只含 `user:inference user:sessions:claude_code user:mcp_servers`、**永不含 `user:profile`**(setup-token 无选 scope 的选项),故请求恒返回 403。这是 **setup-token 鉴权的架构性限制**,不是连通性或路由问题。

**只影响这一项显示**:订阅认证、推理、计费归属、Max 档、auto mode classifier、1M 全部正常(只需 `user:inference`);`/usage` 的 header 仍正确显示 "using your subscription",`Total cost: $0.0000` 对订阅也是对的(不按 token 计费)。要看到限额条须改用交互登录态 token(含 `user:profile`)+ 代理侧实现 OAuth 刷新,代价是放宽 scope + 扩 TCB,与本项目最小 scope / 最小 TCB 的安全姿态相悖,故不做。

## 配置文件参考(`~/.config/cc-mysub/`)

| 文件 | 内容 | 权限 |
|---|---|---|
| `config.json` | `{"listen":"...","client":{"public_host":"...","subscription_type":"max"}}`。`listen` 直连公网用 `0.0.0.0:443`;frp 入口用 `127.0.0.1:8788`(见下) | — |
| `upstream.json` | token 池:`{"oauthTokens":[{"id":"a","token":"sk-ant-oat01-..."}]}`(旧式 `{"oauthToken":"..."}` 单 token 仍可用) | chmod 600 |
| `devices.json` | `[{"label":"laptop","cert_sha256":"<64 lowercase hex>","upstream":"a","rate_limit":120}]`,由 `add-device` 维护;`cert_sha256` = 设备客户端证书指纹,`upstream` 指向用池中哪个 token | — |
| `certs/<public_host>.{crt,key}` | 外层身份用的真 LE 证书+私钥;cc-mysub 自终结外层 TLS 时加载(续期热重载) | key 0600 |
| `ca.crt` | cc-mysub 自有 CA 公证书(仅内层 MITM 用),由 `add-device` 首次生成(幂等);经 `gen-config` 内联进部署配置(`ca_cert_pem`)下发,`install.sh` 在设备侧写出 | 0644 |
| `ca.key` | 内层 MITM CA 私钥,由 `add-device` 首次生成,**永不入 git、永不离开本机** | 0600 |

代理只存 per-device 证书的指纹(公开值),从不持有设备私钥。文件改动通过 mtime polling 热重载,无需重启。

## 设备生命周期

入网分三步(私钥不离设备 + 逐设备认证的必然一次往返):

### ① operator 发布部署配置(`gen-config`,每个 release 一次)

```bash
cc-mysub gen-config --release v1.0.0 > deploy.json
```

读 `config.json` 的 `client` 段 + `ca.crt`,产出部署配置 JSON(`public_host` / `subscription_type` / `release_repo` / `release_tag` / `ca_cert_pem`,全是公开常量、无密钥)。

- `--release <tag>` 必填,钉定二进制版本(无默认 latest,杜绝移动目标)。
- `--release-repo <owner/repo>` 可覆盖二进制托管点(默认 config `client.release_repo`,再退到 `redcontritio/cc-mysub`)。
- `ca.crt` 须已存在(首次跑一次 `add-device` 即幂等生成 CA;见 README 搭服务端步骤 4)。

发布:把 `deploy.json` 放到一个 HTTPS URL(如 GitHub gist raw),带外(私信/IM)把该 URL 给设备。配置交付走 **TOFU**(trust-on-first-use):HTTPS 传输 + operator 带外给的可信 URL。设备据此写出并信任内层 CA——**配置源被篡改即可让设备信任伪造 CA**,此残余风险见 [`../SECURITY.md`](../SECURITY.md)。

### ② 设备自助安装(`install.sh`,设备用户跑)

```bash
curl -fsSL https://raw.githubusercontent.com/redcontritio/cc-mysub/main/install.sh | sh -s -- <配置URL> [label]
# 无参时交互式提示「配置 URL」+「label」(label 默认主机名)。幂等可重跑。
```

`install.sh` 拉取配置 → 按 `uname` 下载对应平台二进制(`SHA256SUMS` 校验 fail-closed)→ 写出内层 CA 到 `~/.config/cc-mysub/ca.crt` → 跑 `device-init` 在本地生成 `device.key`(0600)/`device.crt`(**私钥永不离开设备**)→ **打印本设备证书指纹**并提示去服务器登记 → 轮询现有 mTLS 端点等批准(登记后自动继续;Ctrl-C 可中断、稍后重跑)→ 写好 `~/.local/bin/myclaude` daily wrapper。

- 支持平台:`linux/darwin × amd64/arm64`(Windows 不支持,install.sh 是 bash)。
- 依赖:`curl` + (`jq` 或 `python3`) + `openssl` + `sha256sum`/`shasum`。

### ③ operator 批准(`add-device`,服务器)

```bash
cc-mysub add-device --fingerprint <设备打印的指纹> --label my-laptop
# 仅登记:把该指纹写进 devices.json(cert_sha256)。
```

- `--fingerprint <64hex>` 必填(或 `--client-cert <file>` 自动算指纹)= 设备 `device-init` 打印的指纹。
- 部署常量可用 flag 覆盖:`--host` / `--sub` / `--rate-limit` / `--upstream`(池 id) / `--config-dir`。`--release` 不在此命令——它属于 `gen-config`。
- 首次运行(任意设备)会幂等生成 `ca.crt`/`ca.key`。

设备 ② 的轮询见到批准后自动装好 `myclaude` 并提示完成;之后在该设备上用 `myclaude` 代替 `claude`。

### 换证书(轮换)

设备重跑 `install.sh`(或 `device-init`)得新指纹 → `add-device --rotate --label <label> --fingerprint <newfp>` 原地换发(删旧指纹行=吊销旧证书、写新指纹)。`--rotate` 是布尔 flag,须与 `--label` 一起给。

### 吊销

`cc-mysub remove-device --fingerprint <fp>`(或 `--label <name>`)——按指纹/标签删除并**原子写回** `devices.json`,热重载后该设备立即失效,其他设备无感。**全程走 cli、不要手动编辑 `devices.json`**:cli 路径(add/rotate/remove)统一 temp+rename 原子写,保证文件永远是合法完整 JSON;手动删行可能写坏 JSON,届时热重载会保留旧表(撤销不生效)。

### 其它

如需 classifier 小模型,自行在 `~/.local/bin/myclaude` 里加 `ANTHROPIC_SMALL_FAST_MODEL` 环境变量。

## 入口层:两种方式

helper 拨 `<public_host>:443`(DNS 解析到服务器),外层 mTLS 出示本设备客户端证书 + 系统信任验真 LE。后面是哪种入口对 helper 透明:

- **直接监听公网 443**(README 快速开始用这个):`config.json` 设 `"listen":"0.0.0.0:443"`,cc-mysub 直接终结外层 TLS+mTLS。监听 443 需 root 或 `setcap cap_net_bind_service`。最简单,无额外组件。
- **frp `type=https` SNI 透传**(与其它 https vhost 共用 443 时):`config.json` 设 `"listen":"127.0.0.1:8788"`,frps 读 ClientHello 的 SNI 路由、原样转发 TLS **不终结**,外层 TLS+mTLS 完整到达 cc-mysub 自终结。与同一 frps 上其它 https 服务按 SNI 共用 443、无专属公网端口。见 [`../deploy/frpc.example.toml`](../deploy/frpc.example.toml)。

## 运行与常驻

```bash
go build -o /usr/local/bin/cc-mysub ./cmd/cc-mysub
cc-mysub                       # 默认读 ~/.config/cc-mysub/
cc-mysub --config-dir /path    # 自定义配置目录
```

后台常驻见 [`../deploy/com.user.cc-mysub.plist`](../deploy/com.user.cc-mysub.plist)(launchd),远程暴露见 [`../deploy/frpc.example.toml`](../deploy/frpc.example.toml)。
