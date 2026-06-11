# Security

本文档面向使用者，说明 CC MySub 的威胁模型、凭据分层、合规定位与漏洞上报流程。架构背景见 [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md)。

## 1. 威胁模型

- **客户端是真 CC 二进制（不可改）。** 每台设备跑的是原生 Claude Code CLI，我们无法在其中加入应用层的防重放签名或 channel binding。因此请求的真实性无法在应用层证明。
- **安全必须来自传输层认证（外层 mTLS）。** 外层走**双向 TLS**:cc-mysub 出示 `public_host` 的**真 Let's Encrypt 证书**(设备经**系统信任**验真,不依赖下发 CA);设备出示 **device-init 本地生成的客户端证书**,cc-mysub 按其 **SHA-256(DER) 指纹**逐设备认证(无证书 / 指纹未登记 → **TLS 握手即失败、零应用字节**)。内层 MITM 另用 cc-mysub **自有 CA**(设备经 `NODE_EXTRA_CA_CERTS` 信任,仅用于 `api.anthropic.com` 内层叶)。frp 入口层用 **`type=https` SNI 透传**:frps 读 ClientHello 的 SNI 路由、**不终结** TLS,外层 TLS+mTLS 完整到达 cc-mysub——任何在边缘终结外层 TLS 的配置都会破坏 mTLS 认证。
- **裸明文不安全。** 若外层 mTLS 未建立(无客户端证书 / 指纹未登记 / 服务端身份验证失败),握手即断、cc-mysub 不写一个应用字节。**禁止在无外层 TLS 的路径上暴露 cc-mysub forward-proxy。**
- 代理进程本身只监听本地端口（默认 `127.0.0.1:8788`）；如何把端口安全暴露到远程，完全委托给入口层（frp `type=https` SNI 透传、不终结 TLS）。

## 信道层准入（外层 mTLS 客户端证书）

cc-mysub forward-proxy 经 frp 暴露在**公网**端口；frp 的 `auth.token` 只鉴权隧道注册、**不**鉴权客户端访问。准入由**外层双向 TLS**承载:cc-mysub 用 `tls.RequireAnyClientCert` 要求客户端证书,并在 `VerifyPeerCertificate` 里按 **SHA-256(DER) 指纹**查 `devices.json` 的 `cert_sha256`——**未登记即握手失败**(连接级掐断、零应用字节、不写 `200 Connection Established`、不签 leaf 证书、不返回任何 HTTP 响应)。CONNECT 头不再带任何信道 token / `Proxy-Authorization`,身份由证书承载。

**设备凭据 = 客户端证书 + 私钥（device-init 本地生成）。** 私钥在设备本地生成、**永不离开设备**;`add-device --fingerprint <SHA-256>` 把该证书指纹登记进 `devices.json`(逐设备显式授权)。相较旧的「复用 token 作信道凭据」,私钥不离设备、强于 bearer token。吊销 = `cc-mysub remove-device --fingerprint <fp>`(或 `--label`),mtime 热重载即时生效。

**握手失败先于 allowlist（消除 host oracle）。** 无证书 / 指纹未登记的客户端在 **TLS 握手阶段**即被拒,拿不到任何 HTTP 响应,故无从用响应差异探测 allowlist;`403 Forbidden` 只在「**已认证设备**请求非 allowlist host」时出现(纵深防御)。认证在传输层、早于任何 host 处理,这条 oracle 被结构性消除。

**应用层匿名透传不降级。** mTLS 只在传输层认证设备,不把设备身份注入内层请求;内层匿名照旧（无 app token → 透传不注入、**应用语义层**不可区分于直连）。真正的 Claude Code 有合法无 OAuth token 请求（registry/遥测），匿名透传从「全公网开放」收紧为「已认证可信设备」，不再是洞，故保留、不砍。

## 2. 设备凭据与真 setup-token 分离

设备凭据（客户端证书 + 私钥）与真 setup-token 是**两套独立凭据，无密码学关系**：

- **设备客户端证书 = 门禁卡。** device-init 在设备本地生成的自签证书 + 私钥，不携带真 token 的任何字节；私钥永不离开设备。
- **真 setup-token = 主钥匙。** 本机独立保管（`upstream.json`，chmod 600），永不下发。v4 支持**池**：`{"oauthTokens":[{"id":"a","token":"sk-ant-oat01-A"},{"id":"b","token":"sk-ant-oat01-B"}]}`，每台设备在 `devices.json` 中通过 `"upstream":"<id>"` 指定使用哪个 setup-token；旧式单 token `{"oauthToken":"..."}` 仍兼容。

cc-mysub 按**外层 mTLS 客户端证书的指纹**核身（不靠内层 token）：握手时取客户端证书 → SHA-256(DER) → 查 `devices.json` 的 `cert_sha256` → 命中得设备标签及对应 upstream id（**未登记则握手失败，根本不转发**）。设备内层只持一个**占位 token**（非凭据）；命中设备后，cc-mysub 把出站 `Authorization` **整头重写**为该设备对应的真 token，并删除入站 `X-Api-Key`。

由此得到三个安全性质：

1. **真 token 永不出门**——整头替换而非追加，上游永远看不到设备侧的值。
2. **泄露隔离**——偷到一台设备的证书 + 私钥也摸不到主钥匙，且影响不外溢到其他设备（删该指纹一行即吊销）。
3. **防残留**——删入站 `X-Api-Key`，杜绝凭据旁路泄漏。

**吊销**：`cc-mysub remove-device --fingerprint <fp>`（或 `--label <name>`）——cli 按指纹/标签删条目并原子写回，全程走 cli、不手动编辑 `devices.json`。文件改动通过 mtime polling 热重载，无需重启；被删设备立即失效（既有连接也被主动断开），其他设备无感。

## 3. 合规定位

CC MySub 属于 **B 类**方案：每台设备运行**真正的 Claude Code 二进制**，用 `claude setup-token` 生成的订阅凭据——这正是该命令的预期用途（给 CC 做无交互订阅认证）。中间的代理是**纯传输层**（性质同 frp / 路由器 / ISP），不做推理、不冒充 CC；上游收到请求的 **HTTP 应用语义层（头值 / body / query / cch）与设备直连保真一致**（`api.anthropic.com` 因 MITM 换 token，其外联 TLS/HTTP2 transport 指纹是 cc-mysub 的 Go 栈、非 undici，见下文「诚实降级」节）。这与「第三方工具 / SDK 拿订阅 OAuth token 自己调 API」（A 类）有本质区别。

为守住这个定位，实现遵守三条工程边界：

1. **不实现任何认证逻辑。** 懂订阅认证规则的是远程的真 CC；代理只透传，不构造、不补认证头。CC 升级改认证规则时，真 CC 自己产出新格式请求，代理透传即可。
2. **不冒充、不规避身份校验，做保真透传。** 代理逐字节透传 CC 的指纹头（`anthropic-version` / `anthropic-beta` / `x-stainless-*` / `user-agent` / body / query），不规避任何 client-identity 校验。版本失配是良性的——等效于「一个本地版本落后的正常 CC 用户」，后端反应是「请升级」，不带账号风险。
3. **不下发主钥匙、凭据集中本机。** 真 setup-token 永不离开本机；设备只持有可吊销的客户端证书（私钥本地生成、不离设备）。

**注意**：使用消费级 OAuth 凭据须遵守 Anthropic 的服务条款；多设备共享单份订阅应控制在合理个人使用范围内。

**2026 政策更新(如实告知)**: Anthropic 2026-02-19 服务条款更新**禁止「提取 OAuth token 供第三方工具使用」**; 2026-04-04 起第三方经订阅的用量**按 token 计费**(非订阅价)。对 cc-mysub 的边界:
- **可辩护立场**: cc-mysub 由订阅所有者本人运营、用自己的 setup-token、喂给设备上**真正的 Claude Code 二进制**(B 类纯透传), 属该 token 的预期用途(headless CC 订阅认证), 非「提取给第三方工具」。
- **残留风险(诚实)**: cc-mysub 确实把真 token 取出集中保管并服务端整头替换; 相比「不提取 token、跑官方 `claude --print` 子进程」的做法, 更暴露于上述禁令的字面解释。「多设备共享单份订阅」亦受「合理个人使用」约束。
- **定位**: 本工具仅供**订阅所有者本人**在**自有设备**上分发自己的订阅; 解释权与计费归属终归 Anthropic(承担风险)。请据你的实际情况与最新 ToS 自行判断合规性。

## 请求保真: cch / 用量归因

Claude Code 会对**请求 body** 算一个非加密 xxHash64(`x-anthropic-billing-header`/`cch`, 用于 billing/attribution 与缓存门控), **客户端算、服务端不重算不校验**。cc-mysub **逐字节透传 body 与该头不动** → cch 一致、prompt caching 不破、用量如实归到真 token 的账户。这坐实「不碰性能/用量指标」: cc-mysub 只改 `Authorization`(整头替换) + 删 `X-Api-Key`, 其余(cch / `x-stainless-*` / `anthropic-beta` / body / query)全部保真透传。

## v4 收口架构与加密边界

设备只设 `HTTPS_PROXY` 指向**本地** `cc-mysub helper`(用户态、无系统改动)。收口判据 = **fail-closed 后缀通配(档位 C,权威在 `internal/hosts.Classify`)**:自家域名一律收口、非自家第三方直连。helper 分流(三类):
- **MITM 换 token**:`api.anthropic.com`/`console.anthropic.com` 经**外层双向 TLS（mTLS）** 链到 cc-mysub(cc-mysub 出示 public_host 真 LE 证书、helper 经系统信任验真;helper 出示设备客户端证书、cc-mysub 按指纹认证) → cc-mysub 内层按 host 现签 MITM 终结、换 token;
- **纯透传盲隧道(收口出口 IP)**:其余自家域名(`*.anthropic.com`/`*.claude.ai`/`*.claude.com`/`*.claudeusercontent.com`/`*.ant.dev` 的控制面/状态/文档/MCP 网关/用户内容/staging)+ 第三方遥测/MCP(`http-intake.logs.us5.datadoghq.com`/`api.datadoghq.com`/`mcp.sentry.dev`/`claude*.fedstart.com`)经外层 TLS 链到 cc-mysub,cc-mysub **不解密、不换 token**,仅把出口 IP 收敛到统一出口(否则直连泄漏设备真实 IP)。均不带订阅 token,透传不泄露凭据;
- **本地直连**:非自家第三方(WebFetch 目标/用户自配 MCP/`raw.githubusercontent.com`/包管理器) helper 直连真主机, **永不接触 cc-mysub、不被 MITM**(cert-pinning 主机不破)。

**双层 TLS**: 外层 = 双向 mTLS(cc-mysub 真 LE 身份 + 设备客户端证书指纹认证;防 CONNECT 目标 host 在 helper↔cc-mysub 跳明文); 内层 = api.anthropic.com MITM(设备经 `NODE_EXTRA_CA_CERTS` 信任 cc-mysub 自有 CA)。

**helper 的密钥面 = 仅设备私钥**: helper 不终结内层 TLS、不持 setup-token、不持 CA 私钥。设备侧的 CA **公**证书供**内层 MITM** 验证(由 claude 经 `NODE_EXTRA_CA_CERTS` 信任、非 helper 使用);**外层服务端身份走系统信任**验真真 LE、**不依赖该 CA**。helper 唯一持有的密钥是设备私钥 `device.key`(以 `--client-key` 读取、做外层 mTLS 客户端认证)——它是该设备本地凭据,归入下文**边界 #1**。

**隐私改善(相对 v3 blanket 代理)**: 非自家第三方流量(WebFetch/用户自配 MCP/`raw.githubusercontent.com`/包管理器)留在设备本地, cc-mysub 不接触。自家域名与第三方遥测/MCP 虽经 cc-mysub 收口出口 IP, 但(除 `api.anthropic.com` 内层 MITM 外)走盲隧道**不解密**, cc-mysub 读不到其内容。

## CA 私钥管理

cc-mysub 自有 CA(`<config-dir>/ca.crt` + `ca.key`)由 `add-device` 首次生成并持久化(`ca.key` chmod **0600**、**不入 git**、幂等不重生——重生会废掉已信任设备)。设备经 `NODE_EXTRA_CA_CERTS` 信任 `ca.crt`(公证书)。**CA 私钥泄露 = 对信任它的设备的全 MITM 面**——务必 0600 + 仅留本机。

## 诚实降级: 不可区分性

每条请求的 **HTTP 应用语义层(头值 / body / query / cch)** 与「某台设备直连」保真一致(不碰遥测/性能/用量、匿名零注入、cch 透传)。但有**两项**直连不存在、无法消除的关联信号,如实并列披露:

- **源 IP 收敛**: 多设备汇聚到本机单一出口 IP,是直连不存在的关联信号。多 setup-token 池缓解「共用单一凭据」一维, **源 IP 收敛仍在**。
- **MITM host 的 transport 指纹**: `api.anthropic.com` / `console.anthropic.com` 走内层 MITM 换 token——cc-mysub 在出口**终结**设备上真 CC 的内层 TLS、再由 **Go 网络栈重新发起**对上游的 TLS/HTTP(ClientHello 的 JA3/JA4 是 Go `crypto/tls` 的、出站默认协商 HTTP/2 并经 h1→h2 重序列化),故这两个端点上观测到的 **transport 指纹是 cc-mysub(Go) 的、非真 CC(Node/undici) 的**;请求的应用语义层逐字节保真**不受影响**。这是「MITM 换 token」的**固有代价**——盲隧道无法换 token,故唯独需要真凭据的推理端点无法保留原生 transport 指纹;**纯透传 host**(datadog / downloads 等盲隧道)是端到端 TLS,transport 指纹仍是真 CC 的。

二者均**定位为承担风险, 非隐私增强**。

## 诚实边界：设备私钥暴露面 与 限流豁免

**边界 #1（设备私钥是设备本地凭据，按文件权限保护）。** 设备凭据是 `device-init` 在本地生成的私钥文件 `device.key`(chmod 0600);helper 以 `--client-key` 读取它做外层 mTLS,**不**放进任何 env、也**不**继承给 `claude` 子进程。故旧版「信道 token 经 env 继承给 claude 后代(MCP / npm / Bash 工具)可读」的向量在 mTLS 下**消失**:设备内层仍持的 `CLAUDE_CODE_OAUTH_TOKEN` 已是**占位串(非凭据)**,后代读到也无用。残留暴露 = `device.key` 是该设备本地文件,**同 uid 进程 / root / 备份**可读即可冒充该设备连 cc-mysub——这是「设备本地凭据对该设备用户可读」的固有事实,作为 **deliberate accepted exposure** 如实记录,由 0600 + 删指纹吊销收敛。

**边界 #2（限流豁免路径）。** mTLS 下**每个连接都已认证设备**(证书握手保证),故匿名内层请求(无 app token、但连接已认证)归入**其证书设备的限流桶**——旧版「匿名走透传且不受 per-device 限流」的 un-rate-limited relay 面**不再存在**。残留:**仅匿名(无入站凭据)的** `/api/`、`/mcp-registry` 前缀请求豁免限流(代码 `isExempt(path) && !HasInboundCredential(r)`,使遥测 / 注册表查询逐字节不动、不引入与直连可区分的行为);**带凭据的同路径请求一律走该证书设备的 per-device 桶**(P3-7,堵借豁免前缀绕过 per-device 限流),且 dot-segment 等非规范路径不豁免(`path.Clean` fail-closed)。被豁免的匿名请求本就被 Anthropic 401、拿不到订阅,仅耗 cc-mysub 资源,由 **`cc-mysub remove-device`**(吊销该证书指纹)收敛。这是被接受的残留风险,非零暴露。

## 订阅档位声明（subscriptionType）的诚实边界

客户端要在 UI 上显示 Max 标签、解锁 auto mode 的 Bash classifier、让 1M 变体可选、收到 tier beta，依赖客户端本地环境变量 `CLAUDE_CODE_SUBSCRIPTION_TYPE` 声明订阅档位（pro/max/team/enterprise）。需要诚实说明它的边界：

- **这是客户端本地 env 声明，CC 不验真。** 在占位 token（OAUTH_TOKEN 路径）下，真 CC 直接读取本机 `CLAUDE_CODE_SUBSCRIPTION_TYPE` 来决定 tier 自我认知，不对其真伪做任何校验。它只影响客户端自己的界面与门控，不是一道服务端授权。
- **客户端 tier 自我认知 ≠ 服务端鉴权。** 上游真 Anthropic 是否接受这套档位，取决于代理后面挂的**真 setup-token 的真实权限**，而非客户端声明的 `CLAUDE_CODE_SUBSCRIPTION_TYPE`。二进制层面无法断言服务端如何处理占位 subscriptionType——不要据此声称"服务端必然接受"。
- **它不改变 B 类定位。** 整链仍是真 CC + 纯透传、应用语义层与设备直连保真一致（MITM host 的 transport 指纹边界见「诚实降级」节）；`CLAUDE_CODE_SUBSCRIPTION_TYPE` 本就是给订阅用户使用的 env，由客户端自行声明其持有的档位。
- **不要据此"凭空获得"未持有的订阅权益。** 该 env 只让客户端按声明的档位呈现界面与功能门控；真正的订阅权益与计费归属，始终落在代理后那份真 setup-token 对应的账户上。请按你实际持有的档位填写。

## 4. 报告漏洞

请通过 GitHub 的**私有 security advisory** 上报：仓库页面 → **Security** 标签 → **Report a vulnerability**。

请勿在公开 issue、PR 或讨论区披露安全问题。报告中请尽量包含复现步骤、影响范围和受影响版本。我们会在私有 advisory 内跟进并协调修复与披露时间。

## 设备入网（install.sh）供应链不变量

设备入网由通用 `install.sh` 驱动:拉部署配置(`public_host` / `subscription_type` / `release_tag` / `ca_cert_pem`,**无密钥**)→ 下二进制并按 release 的 `SHA256SUMS` 校验 → `device-init` 本地生成私钥 + 客户端证书 → 轮询现有 mTLS 端点等 operator 批准 → 写 daily `myclaude` wrapper。

- **二进制完整性 fail-closed**：install.sh 从 release 拉 `SHA256SUMS`、按本平台条目校验下载的二进制,不匹配则绝不安装（`mktemp` 私有临时 + 同目录原子 `mv`,被 rename 的对象必已校验）。信任根 = GitHub 平台 + 发布该 release 的 operator(与 CI 在 GitHub 构建同属已纳入 TCB);此为**安装期传输信任**,非离线锚。reproducible build（pin-Go + `-trimpath`）是可选的独立审计 hedge。
- **设备凭据 = 本地私钥,不经分发**：`device-init` 在设备本地生成 `device.key`(私钥**永不离开设备**);入网**不分发任何密钥**——部署配置只含公开的 host / CA 公证书 / release。daily wrapper 写在 `~/.local/bin/myclaude`(设备 HOME 下、不在仓库 work tree),只含**占位 token** + 指向本地 `device.{crt,key}` 的路径,本身非凭据。`.gitignore` 的 `*.key` 兜底防 `--config-dir=.` 时 `device.key`/`ca.key` 误入 work tree(`config.json`/`upstream.json`/`devices.json`/`certs/` 亦在忽略列表)。
- **CA 公证书 TOFU**：部署配置内嵌 cc-mysub CA **公**证书(`ca_cert_pem`),首次拉配置时信任(TOFU);它只用于内层 MITM 验证、非密钥。
- **逐设备显式授权**:每台新设备的证书指纹须由 operator 经 `add-device --fingerprint` 批准才登记进 `devices.json`;install.sh **轮询现有 mTLS 端点**等批准(三态探针:approved / unapproved / unreachable),**零新增公网面**。
- **首次下载 trace 不经 cc-mysub MITM**：install.sh 在 helper 起本地分流器之前运行,且 GitHub release CDN 不在 helper allowlist;像普通开发机的 release 下载,deliberate accepted。
