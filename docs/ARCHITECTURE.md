# CC MySub — 架构

CC MySub 是一个本地代理，让你在**任意设备**上运行原生 Claude Code，复用本机持有的**单份订阅凭据**，同时保留订阅的全部功能（包括 auto 权限模式）。订阅凭据集中本机、永不下发；每台设备只持有一个可独立吊销的客户端证书（私钥本地生成、不离设备）。

它**不是** Web 终端——每台设备跑的是真正的 Claude Code CLI，本机只做纯传输代理。

## 数据流

```
设备上的真·Claude Code   (经 `cc-mysub helper` 启动)
   │  CLAUDE_CODE_OAUTH_TOKEN=<占位 token>        # 非凭据；cc-mysub 换发真 token
   │  CLAUDE_CODE_OAUTH_SCOPES=user:inference
   │  CLAUDE_CODE_SUBSCRIPTION_TYPE=<tier，如 max>
   │  HTTPS_PROXY=<本地分流器>   (helper 注入；base_url 保持默认 api.anthropic.com)
   ▼
设备本地分流器(splitter)   出示本设备客户端证书
   │  外层 mTLS  →  frp type=https SNI 透传(不终结)
   ▼
cc-mysub (出口)
   │  按客户端证书指纹核身 → 换上真 setup-token → 内层 MITM 透传
   ▼
api.anthropic.com
```

CC MySub 进程本身只监听本地端口；如何把端口安全暴露到远程，完全委托给「入口层」（见下）。

## 为什么客户端用 CLAUDE_CODE_OAUTH_TOKEN

要让远程 CC 走**订阅认证**（而非降级为 API 计费），客户端必须用 `CLAUDE_CODE_OAUTH_TOKEN`（v4 下为**占位值**，由 cc-mysub 按设备换发真 token）+ `CLAUDE_CODE_OAUTH_SCOPES=user:inference`。认证模式判定**只看 OAuth scope**、与 base_url 无关——v4 保持 base_url 默认 `api.anthropic.com`，由设备本地分流器经 `HTTPS_PROXY` 拦截转发（即便自定义 base_url，CC 的 provider 判定仍视为 first-party，故订阅认证与自定义 base_url 也可共存）。用 `ANTHROPIC_AUTH_TOKEN` 则会被判为非订阅凭据，丢失订阅行为。

## 订阅认证 vs 订阅档位（两个正交判定）

客户端 CC 的「认证模式」与「订阅档位」是**两个正交判定**，输入不同，互不替代：

- **认证模式**（是否走订阅 OAuth、是否带 `oauth-2025-04-20` beta、是否用非 api-key 的 Bearer）：**只看 OAuth scope**，即上面的 `CLAUDE_CODE_OAUTH_SCOPES`（不设时默认含 `user:inference`）。这一层决定请求是否以订阅身份发出，与档位无关。
- **订阅档位**（pro / max / team / enterprise，对应 UI 上的「Claude Max」标签与 tier 功能）：**只来自客户端 env `CLAUDE_CODE_SUBSCRIPTION_TYPE`**。不设此 env 时档位为 `null`，于是 UI 显示「Claude API」、auto 权限模式下的 Bash classifier 不工作（卡在逐个命令确认）、1M 变体不可选、tier 相关 beta 不下发。把它设为你的真实档位（如 `CLAUDE_CODE_SUBSCRIPTION_TYPE=max`），即可恢复 Max 标签、auto 权限模式 classifier（每次工具调用前先发一个极小请求逐个放行）、1M 变体可选与 tier beta 下发。

早先把「经代理后掉成 API 模式、丢 auto mode」误判为**认证**问题，实为只缺**档位** env：认证那层（scope）一直成立、从未失败，缺的只是 `CLAUDE_CODE_SUBSCRIPTION_TYPE`。

**1M 是可选变体而非默认**：`CLAUDE_CODE_SUBSCRIPTION_TYPE=max` 解锁的是「1M 变体可被选择」，默认仍是 200k；需在 CC 里 `/model` 选「Opus 4.8 (1M context)」才切到 1M，切后 `/status` 才显示 1M。

**诚实标注**：`CLAUDE_CODE_SUBSCRIPTION_TYPE` 是客户端**本地 env 声明、CC 不验真**——在 `CLAUDE_CODE_OAUTH_TOKEN` 路径下，客户端 CC 直读此 env、不做真伪校验。因此客户端的 tier 自我认知 ≠ 服务端鉴权：上游真 Anthropic 是否接受这套，取决于代理后面挂的真 setup-token 的真实权限，二进制层面无法断言服务端如何处理占位的 `CLAUDE_CODE_SUBSCRIPTION_TYPE`。这不改变本方案「真 CC + 纯透传、逐字节不可区分」的合规定位，而 `CLAUDE_CODE_SUBSCRIPTION_TYPE` 本就是给订阅用户使用的 env；但绝不可由此声称「服务端必然接受」或「凭空获得 Max 权益」。

**代理对这些 env 全程无感**：`CLAUDE_CODE_OAUTH_SCOPES` 与 `CLAUDE_CODE_SUBSCRIPTION_TYPE` 都在客户端 CC 侧设置、由客户端 CC 自行消费，代理既不读取也不注入，只做透传——这正呼应下文「代理不实现任何认证逻辑」。

## 代理核心：头变换

请求经过代理时，HTTP 头分四类处理：

| 处理 | 头 |
|---|---|
| 替换 | `Authorization` → `Bearer <真 setup-token>` |
| 重设 | `Host` → `api.anthropic.com` |
| 清理 | `X-Api-Key`（删除，防占位 / 设备凭据旁路泄漏）|
| 透传 | 其余全部（`anthropic-version`/`anthropic-beta`/`x-stainless-*`/`user-agent`/body/query），逐字节 |

代理**不补任何头**——OAuth 模式下 CC 自带 `anthropic-beta: oauth-2025-04-20`，透传即可。所有 `/v1/*` 路径透传，无白名单。

## token 替换与安全模型

设备凭据（客户端证书 + 私钥）与真 setup-token 是**两套独立凭据，无密码学关系**：

- **设备客户端证书** = 门禁卡，device-init 本地生成、私钥不离设备，不携带真 token 任何字节。
- **真 setup-token** = 主钥匙，本机独立保管，永不下发。

代理按**外层 mTLS 客户端证书指纹**核身（不靠内层 token）：握手时取客户端证书 → SHA-256(DER) → 查 `devices.json` 的 `cert_sha256` → 命中得设备标签及对应 upstream id（未登记则握手失败，根本不转发）。设备内层只持**占位 token**；命中后出站把 `Authorization` 整头重写为真 token。

由此得到三个安全性质：

1. **真 token 永不出门**——整头替换而非追加，上游永远看不到设备侧的值。
2. **泄露隔离**——偷到一台设备的证书 + 私钥也摸不到主钥匙；`cc-mysub remove-device` 即吊销该设备，其他设备无感。
3. **防残留**——删入站 `X-Api-Key`，杜绝旁路泄漏。

## 认证与凭据管理（`~/.config/cc-mysub/`）

> 注：认证为**外层 mTLS 客户端证书**（设备本地生成私钥、按证书指纹逐设备认证；frp `type=https` SNI 透传、外层走真 LE）。本文档已按此当前形态描述；下文「入口层加密矩阵 / overlay 取舍」保留为**历史设计 rationale**，实际接入/部署以 README 与 `OPERATING.md` 为准。

- `config.json` — 监听设置 `{listen}`，可选 `client`（部署常量：`public_host` / `subscription_type` / `release_repo`，供签发设备时填通用 wrapper）。
- `upstream.json`（chmod 600）— `{oauthToken}` 或 `{oauthTokens:[{id,token}]}`，你的真 setup-token（池）。
- `devices.json` — `[{label, cert_sha256, upstream, rate_limit}]`，`cert_sha256` = 设备客户端证书指纹（公开值）；代理不持设备私钥。
- `certs/<public_host>.{crt,key}` — 外层身份真 LE 证书（续期热重载）；`ca.{crt,key}` — 仅内层 MITM 现签根。

设备入网用通用 `install.sh`（拉部署配置 → sha256 校验下二进制 → `device-init` **在设备本地**生成私钥 + 客户端证书并打印指纹 → 轮询现有 mTLS 端点等批准 → 写 daily `myclaude` wrapper）。operator 在代理主机用 `cc-mysub add-device --fingerprint <SHA-256> --label <设备名>` **批准**该设备（把证书指纹追加进 `devices.json`）。详见 README 与 `OPERATING.md`。

吊销 = `cc-mysub remove-device --fingerprint <fp>`（或 `--label`）；cli 按指纹/标签删条目并原子写回（temp+rename），文件改动通过 mtime polling 热重载，无需重启。全程走 cli、不手动编辑 `devices.json`。

## 入口层加密（部署矩阵 — 历史 rationale）

> **当前形态**：生产用 frp **`type=https` SNI 透传**（不终结 TLS）+ 外层 **mTLS**（设备客户端证书，按指纹认证）+ 真 LE 服务端身份。下表是早期评估过的入口层加密**选项**，保留作设计 rationale；实际接入/部署以 README 与 `OPERATING.md` 为准。

**安全前提**：客户端是真 CC（不可改），无法在应用层做防重放签名 → 安全必须来自**传输层加密 + 认证**。**裸明文（零加密层）不安全。** 早期评估过的加密信道选项（代理代码对入口层无感）：

| 方案 | 客户端 base_url | 加密层 | 适用 |
|---|---|---|---|
| Tailscale / WireGuard | `http://<ts-ip>:PORT` | 网络层 WireGuard | 零证书/零域名，穿透 NAT |
| 代理自签 TLS | `https://<host>:PORT` | 代理 `config.tls` | 无域名；客户端设 `NODE_EXTRA_CA_CERTS` |
| 真域名 + Let's Encrypt（**当前**）| `https://<域名>` | frp `type=https` 透传 + 外层 mTLS | 客户端零配置 |

## 防护、日志与基线告警

- **限速**：per-device（按证书设备）token bucket；`/api/`、`/mcp-registry` 前缀豁免（遥测/注册表逐字节透传）。
- **访问日志**：结构化（设备/路径/状态/用量），日志即诊断面。
- **基线偏离告警**：被动观测真实流量，**只告警不拦截**——入站缺 `oauth-2025-04-20`、`Authorization` 结构异常、凭据落在 `x-api-key`，或上游 401/403 时记一条 WARN。用于在 CC 升级改变认证行为时尽早显形，而不牺牲透传鲁棒性。

## 鲁棒性：为什么对 CC 升级免疫

代理**不实现任何认证逻辑**——懂订阅认证规则的是远程的真 CC。CC 升级改认证规则时，真 CC 自己产出新格式请求，代理透传即可，大多数情况零改动。唯一会破坏方案的是 CC 移除「OAuth token + 自定义 base_url 共存」能力，或后端引入 token-请求绑定（channel binding）——后者是一切中间代理式方案的理论天花板，目前无迹象。

**版本失配是良性的**：若某次 CC 升级导致后端拒绝，那等效于「一个本地版本落后的正常 CC 用户」——后端看到的就是真 CC 的版本化请求，反应是「请升级」，不带账号风险。

## 合规定位

CC MySub 在每台设备运行**真正的 Claude Code 二进制**，用 `claude setup-token` 生成的订阅凭据——这正是该命令的预期用途（给 CC 做无交互订阅认证）。中间的代理是**纯传输层**（性质同 frp / 路由器 / ISP），不做推理、不冒充 CC；上游收到的请求与设备直连逐字节不可区分。这与「第三方工具 / SDK 拿订阅 OAuth token 自己调 API」有本质区别。

**注意**：使用消费级 OAuth 凭据须遵守 Anthropic 的服务条款；多设备共享单份订阅应控制在合理个人使用范围内。详见 `SECURITY.md`。

## 已知限制

- 不承诺高可用——自用工具，外部 CC 短时不可用是可接受的。
- 真后端是否持续接受经代理的请求，取决于 Anthropic 后端策略；本项目不规避任何 client-identity 校验，仅做保真透传。

**overlay 网络（headscale / WireGuard / Nebula）已评估并放弃。** overlay 能替代 frp + 大半 DoS 防护且认证更强（私钥不离设备、L3 准入），但**因设备侧隐蔽性放弃**：overlay 引入躲不掉的 VPN 进程 + 虚拟网卡 tell，EDR/MDM 把 mesh VPN 当明确检测类别 flag，违背「不引人注目」约束；而本地分流器（A 方案）的 footprint 像「一台普通的被代理开发机」。隐蔽性是硬约束 → 锁定 A 方案。（注：当时作为 future option 的 **mTLS / 客户端证书**——私钥不离设备、强于 bearer token——现已落地为当前认证机制，见上文。）
