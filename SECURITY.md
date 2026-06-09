# Security

本文档面向使用者，说明 CC MySub 的威胁模型、凭据分层、合规定位与漏洞上报流程。架构背景见 [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md)。

## 1. 威胁模型

- **客户端是真 CC 二进制（不可改）。** 每台设备跑的是原生 Claude Code CLI，我们无法在其中加入应用层的防重放签名或 channel binding。因此请求的真实性无法在应用层证明。
- **安全必须来自信道加密。** cc-mysub 自有 CA 签发 `public_host` 身份证书，`cc-mysub helper` 持 CA 公证书验证**外层 TLS**；设备经 `NODE_EXTRA_CA_CERTS` 信任 cc-mysub CA，用于内层 MITM 连接验证。frp 入口层必须用 **`type=tcp`** 透传（L4），外层 TLS 完整到达 cc-mysub——旧的 `https`/`https2http` 边缘终结 TLS 在 v4 作废，会破坏外层 TLS。
- **裸明文不安全。** 若外层 TLS 未建立（如 helper 的 CA 验证失败），helper 不转发。**禁止在无外层 TLS 的路径上暴露 cc-mysub forward-proxy。**
- 代理进程本身只监听本地端口（默认 `127.0.0.1:8788`）；如何把端口安全暴露到远程，完全委托给入口层（frp `type=tcp`）。

## 信道层准入（CONNECT token）

cc-mysub forward-proxy 经 frp 暴露在**公网**端口；frp 的 `auth.token` 只鉴权隧道注册、**不**鉴权客户端访问，外层 TLS 又是**单向**的（cc-mysub 只出示身份、不校验客户端凭据）。因此在信道层加一道**准入门**：设备分流器经外层 TLS 链到 cc-mysub 时，在上游 CONNECT 头里带 `Proxy-Authorization: Bearer <信道 token>`（外层 TLS 内、绝不上行到 Anthropic）；cc-mysub 读 CONNECT 头时校验，**不过则 407 并断**，绝不写 `200 Connection Established`、不签 leaf 证书、不 echo token（日志只记远端 addr + "channel auth failed"）。

**信道 token = 复用 per-device `DEVICE_TOKEN`（经 env）。** wrapper 已 `export CLAUDE_CODE_OAUTH_TOKEN="$DEVICE_TOKEN"`，helper 读该 env、自加 CONNECT 头（无 CLI flag）。cc-mysub 用同一份 `auth.Lookup` 校验。一个 token 两层、删 `devices.json` 一行即两层同时吊销。这是**有意**的统一（纵深损失 largely illusory）：恢复路径就是删行；future option 是 `HKDF(DEVICE_TOKEN,"channel")` 派生出独立信道 token。

**校验置于 allowlist 之前（消除 host oracle）。** tokenless 或坏 token 的客户端**一律 407**，不泄露 allowlist 成员；`403 Forbidden` 只在「**已鉴权设备**请求非 allowlist host」时出现（纵深防御）。若把 allowlist 放在信道校验之前，攻击者就能用 403-vs-407 的差异探测哪些 host 在白名单里——这条 oracle 被准入门顺序焊死消除。

**应用层匿名透传不降级。** 信道 token 只在 CONNECT 层做通过/拒绝，不把设备身份透传内层；内层匿名照旧（无 app token → 透传不注入、字节级不可区分于直连）。真正的 Claude Code 有合法无 OAuth token 请求（registry/遥测），匿名透传从「全公网开放」收紧为「已鉴权可信设备」，不再是洞，故保留、不砍。

## 2. per-device token 与真 setup-token 分离

per-device token 与真 setup-token 是**两个独立随机串，无密码学关系**：

- **per-device token = 门禁卡号。** 发给某台设备，不携带真 token 的任何字节。
- **真 setup-token = 主钥匙。** 本机独立保管（`upstream.json`，chmod 600），永不下发。v4 支持**池**：`{"oauthTokens":[{"id":"a","token":"sk-ant-oat01-A"},{"id":"b","token":"sk-ant-oat01-B"}]}`，每台设备在 `devices.json` 中通过 `"upstream":"<id>"` 指定使用哪个 setup-token；旧式单 token `{"oauthToken":"..."}` 仍兼容。

代理不「解密」per-device token，而是「查名单核身 + 整头替换」：取入站 `Authorization` 里的 token → sha256 → 查 `devices.json` → 命中得设备标签及对应 upstream id（**未命中直接 401，根本不转发**）→ 出站把 `Authorization` 整头重写为该设备对应的真 token，并删除入站 `X-Api-Key`。

由此得到三个安全性质：

1. **per-device token 永不出门**——整头替换而非追加，上游永远看不到它。
2. **泄露隔离**——偷到一张门禁卡也摸不到主钥匙，且影响不外溢到其他设备。
3. **防残留**——删入站 `X-Api-Key`，杜绝凭据旁路泄漏。

**吊销**：删 `devices.json` 里对应那一行即可。文件改动通过 mtime polling 热重载，无需重启；被删设备立即失效，其他设备无感。

## 3. 合规定位

CC MySub 属于 **B 类**方案：每台设备运行**真正的 Claude Code 二进制**，用 `claude setup-token` 生成的订阅凭据——这正是该命令的预期用途（给 CC 做无交互订阅认证）。中间的代理是**纯传输层**（性质同 frp / 路由器 / ISP），不做推理、不冒充 CC；上游收到的请求与设备直连逐字节不可区分。这与「第三方工具 / SDK 拿订阅 OAuth token 自己调 API」（A 类）有本质区别。

为守住这个定位，实现遵守三条工程边界：

1. **不实现任何认证逻辑。** 懂订阅认证规则的是远程的真 CC；代理只透传，不构造、不补认证头。CC 升级改认证规则时，真 CC 自己产出新格式请求，代理透传即可。
2. **不冒充、不规避身份校验，做保真透传。** 代理逐字节透传 CC 的指纹头（`anthropic-version` / `anthropic-beta` / `x-stainless-*` / `user-agent` / body / query），不规避任何 client-identity 校验。版本失配是良性的——等效于「一个本地版本落后的正常 CC 用户」，后端反应是「请升级」，不带账号风险。
3. **不下发主钥匙、凭据集中本机。** 真 setup-token 永不离开本机；设备只持有可吊销的 per-device token。

**注意**：使用消费级 OAuth 凭据须遵守 Anthropic 的服务条款；多设备共享单份订阅应控制在合理个人使用范围内。

**2026 政策更新(如实告知)**: Anthropic 2026-02-19 服务条款更新**禁止「提取 OAuth token 供第三方工具使用」**; 2026-04-04 起第三方经订阅的用量**按 token 计费**(非订阅价)。对 cc-mysub 的边界:
- **可辩护立场**: cc-mysub 由订阅所有者本人运营、用自己的 setup-token、喂给设备上**真正的 Claude Code 二进制**(B 类纯透传), 属该 token 的预期用途(headless CC 订阅认证), 非「提取给第三方工具」。
- **残留风险(诚实)**: cc-mysub 确实把真 token 取出集中保管并服务端整头替换; 相比「不提取 token、跑官方 `claude --print` 子进程」的做法, 更暴露于上述禁令的字面解释。「多设备共享单份订阅」亦受「合理个人使用」约束。
- **定位**: 本工具仅供**订阅所有者本人**在**自有设备**上分发自己的订阅; 解释权与计费归属终归 Anthropic(承担风险)。请据你的实际情况与最新 ToS 自行判断合规性。

## 请求保真: cch / 用量归因

Claude Code 会对**请求 body** 算一个非加密 xxHash64(`x-anthropic-billing-header`/`cch`, 用于 billing/attribution 与缓存门控), **客户端算、服务端不重算不校验**。cc-mysub **逐字节透传 body 与该头不动** → cch 一致、prompt caching 不破、用量如实归到真 token 的账户。这坐实「不碰性能/用量指标」: cc-mysub 只改 `Authorization`(整头替换) + 删 `X-Api-Key`, 其余(cch / `x-stainless-*` / `anthropic-beta` / body / query)全部保真透传。

## v4 收口架构与加密边界

设备只设 `HTTPS_PROXY` 指向**本地** `cc-mysub helper`(用户态、无系统改动)。helper 分流(三类):
- **`api.anthropic.com`/`console.anthropic.com`** 经**外层 TLS** 链到 cc-mysub(cc-mysub 出示 public_host 身份证书, helper 用已下发 CA 公证书验证) → cc-mysub 内层按 host 现签 MITM 终结、换 token;
- **遥测/更新**(`http-intake.logs.us5.datadoghq.com` / `downloads.claude.ai`)同样经外层 TLS 链到 cc-mysub,但 cc-mysub 做**纯透传盲隧道**——不解密、不换 token,仅把出口 IP 收敛到统一出口(否则从设备直连会泄漏设备真实 IP、破坏同出口等效)。二者不带订阅 token(datadog 用 DD-API-KEY、downloads 无认证),故透传不泄露凭据;
- **其余一切**(WebFetch 目标/MCP/`raw.githubusercontent.com`/包管理器) helper **本地直连**真主机, **永不接触 cc-mysub、不被 MITM**(cert-pinning 主机不破)。

**双层 TLS**: 外层 = cc-mysub 身份(防 CONNECT 目标 host 在 helper↔cc-mysub 跳明文); 内层 = api.anthropic.com MITM(设备经 `NODE_EXTRA_CA_CERTS` 信任 cc-mysub CA)。

**helper 无密钥面**: 不终结内层 TLS、不持 setup-token、不持 CA 私钥(只持 CA 公证书做外层身份验证)。

**隐私改善(相对 v3 blanket 代理)**: 与 Anthropic 无关的第三方流量(WebFetch/MCP/`raw.githubusercontent.com`/包管理器)留在设备本地, cc-mysub 不接触。遥测/更新虽经 cc-mysub 收口出口 IP, 但走盲隧道**不解密**, cc-mysub 同样读不到其内容。

## CA 私钥管理

cc-mysub 自有 CA(`<config-dir>/ca.crt` + `ca.key`)由 `add-device` 首次生成并持久化(`ca.key` chmod **0600**、**不入 git**、幂等不重生——重生会废掉已信任设备)。设备经 `NODE_EXTRA_CA_CERTS` 信任 `ca.crt`(公证书)。**CA 私钥泄露 = 对信任它的设备的全 MITM 面**——务必 0600 + 仅留本机。

## 诚实降级: 不可区分性

每条请求**字节级**与「某台设备直连」不可区分(不碰遥测/性能/用量、匿名零注入、cch 透传); 但**多设备汇聚到本机单一出口 IP** 是直连不存在的关联信号。多 setup-token 池缓解「共用单一凭据」一维, **源 IP 收敛仍在**——定位为承担风险, 非隐私增强。

## 诚实边界：信道 token 暴露面 与 匿名 relay blast radius

**边界 #1（env 不等于「strictly 紧于 argv」）。** 信道 token 经 env 传、**绝不经 CLI flag**——env 消除了 world-readable `argv`（`ps` / `/proc/<pid>/cmdline` 对**其他本地 uid** 可见）这一向量。但 helper 仍把 `CLAUDE_CODE_OAUTH_TOKEN` 继承给它启动的 `claude` 子进程（`cmd.Env = append(os.Environ(), …)`），故 **claude 的后代进程（MCP server / npm / Bash 工具）经继承 env 仍可读**该 token。这层暴露**不变**，且本就是 claude 订阅认证的既有事实——作为 **deliberate accepted exposure** 如实记录。不要据此宣称「env 严格紧于 argv」而不带此限定。

**边界 #2（匿名 relay blast radius）。** 信道准入通过后，内层**匿名**请求（无 app token）走透传且**不受 per-device 限流**（`RateLimitByDevice` 跳过匿名）。故一个泄露的 `DEVICE_TOKEN` 不止换得该设备的限流配额，还开出一条 **un-rate-limited 匿名 relay**：匿名请求被 Anthropic 401、**拿不到订阅**，但仍消耗 cc-mysub 资源、可作隐藏 IP relay。本版以一个**粗粒度全局匿名请求 cap**（`globalAnonPerMin`，与 device 无关、豁免遥测路径）兜底，并由**删 `devices.json` 一行**的吊销路径收敛。这是被接受的残留风险，非零暴露。

## 订阅档位声明（subscriptionType）的诚实边界

客户端要在 UI 上显示 Max 标签、解锁 auto mode 的 Bash classifier、让 1M 变体可选、收到 tier beta，依赖客户端本地环境变量 `CLAUDE_CODE_SUBSCRIPTION_TYPE` 声明订阅档位（pro/max/team/enterprise）。需要诚实说明它的边界：

- **这是客户端本地 env 声明，CC 不验真。** 在占位 token（OAUTH_TOKEN 路径）下，真 CC 直接读取本机 `CLAUDE_CODE_SUBSCRIPTION_TYPE` 来决定 tier 自我认知，不对其真伪做任何校验。它只影响客户端自己的界面与门控，不是一道服务端授权。
- **客户端 tier 自我认知 ≠ 服务端鉴权。** 上游真 Anthropic 是否接受这套档位，取决于代理后面挂的**真 setup-token 的真实权限**，而非客户端声明的 `CLAUDE_CODE_SUBSCRIPTION_TYPE`。二进制层面无法断言服务端如何处理占位 subscriptionType——不要据此声称"服务端必然接受"。
- **它不改变 B 类定位。** 整链仍是真 CC + 纯透传、与设备直连逐字节不可区分；`CLAUDE_CODE_SUBSCRIPTION_TYPE` 本就是给订阅用户使用的 env，由客户端自行声明其持有的档位。
- **不要据此"凭空获得"未持有的订阅权益。** 该 env 只让客户端按声明的档位呈现界面与功能门控；真正的订阅权益与计费归属，始终落在代理后那份真 setup-token 对应的账户上。请按你实际持有的档位填写。

## 4. 报告漏洞

请通过 GitHub 的**私有 security advisory** 上报：仓库页面 → **Security** 标签 → **Report a vulnerability**。

请勿在公开 issue、PR 或讨论区披露安全问题。报告中请尽量包含复现步骤、影响范围和受影响版本。我们会在私有 advisory 内跟进并协调修复与披露时间。

## 自举 wrapper 供应链不变量

- **二进制完整性 fail-closed**：wrapper 内嵌 per-platform sha256（离线锚），下载的二进制
  sha256 不匹配则绝不 exec，并发首次运行下亦持（mktemp 私有临时 + 同目录原子 rename，
  被 rename 的对象必已校验）。
- **信任离线锚在 wrapper**：运行时对二进制的校验不依赖对 GitHub 的传输信任；sha256 pin 在
  `add-device` 时由 operator 联网拉取并烤入，那一刻信任根 = GitHub 平台 + operator 账号
  （与 CI 在 GitHub 构建同属已纳入 TCB）。reproducible build（pin-Go + `-trimpath`）是可选
  的独立审计 hedge。
- **wrapper = 设备凭据**：内嵌明文 per-device token，分发渠道须鉴权（operator 责任，沿用
  「明文仅此一次」模型）。`.gitignore` 已覆盖 `myclaude-*`。
- **首次下载 trace 不经 cc-mysub MITM**：bootstrap 在 helper 起本地分流器之前运行，且 GitHub
  不在 helper allowlist；像普通开发机的 release 下载，deliberate accepted（远低于常驻 VPN，
  合 v4 隐蔽性约束）。curl/wget 默认 honor 设备 ambient HTTPS_PROXY——与安全无关：sha256
  离线锚使完整性独立于下载路径。
- **私有 repo / macOS Gatekeeper / reproducibility 操作化**：见 spec §10 非阻塞后续。
