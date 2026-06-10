# 订阅请求转发的等效性分析

抛开本仓库的具体实现,从第一性原理分析:怎样转发 Claude Code 的订阅请求、怎么搭建环境,使得**官方视角下,经技术中转的设备等效于「同一出口代理后面、一个订阅所有者正常登录的普通设备」**。

**适用范围**:自有订阅、个人自用、跑**官方 Claude Code 二进制**(不改客户端)。本文的「等效」基线 = 同出口普通登录设备,而非各设备直连——因为中转本就有一个统一出口。合规边界(ToS 等)见 [`../SECURITY.md`](../SECURITY.md),不在本文重复。

**验证基线**:Claude Code CLI `2.1.168`(2026-06-08 容器内 egress 审计 + 公网链路实测)、`2.1.169`(2026-06-09 §2 端点提取:二进制硬编码域名 + CONNECT 抓包)、模型 `claude-opus-4-8`。后续版本行为可能变,以实测为准。

---

## 1. CC 在线上到底产生什么

要做到「等效」,先得知道官方能观测到什么。关键事实:**跑的是官方 CC 二进制,绝大多数可观测面由 CC 自己产生、与中转无关**。逐层盘点。

### 网络层

- **TLS 指纹(JA3/JA4)、HTTP/2 指纹**:由 CC 的网络栈(Node.js / undici)决定,**不是中转能选择的**。跑真 CC → 指纹落在「真 CC」的分布内。注意它随 Node 版本变(本机 v24、审计容器 v20 即不同),所以"同出口普通登录设备"本身也不是单一指纹,而是一族真 CC 指纹;中转设备只要也跑真 CC,就在同一族内。**前提是中转不重构请求、内层 TLS 由真 CC 自己发起**(见 §3)。
- **出口 IP**:中转后 = 出口服务器的 IP。在「同出口」基线下,这正是预期——基线就是多设备共用这一个出口。

### 认证层

- **`Authorization: Bearer <token>`**:订阅 OAuth token。
- **OAuth scopes**:`claude setup-token` 产出的凭据含 `user:inference` / `user:sessions:claude_code` / `user:mcp_servers`,**不含 `user:profile`**(setup-token 没有选 scope 的入口)。
- **beta header `anthropic-beta: oauth-2025-04-20`**:订阅认证模式的标志,由 CC 在检测到 OAuth token 时自动带上。

这些头**由 CC 根据环境(`CLAUDE_CODE_OAUTH_TOKEN` 等)自行构造**。中转要处理的只有 token 的**值**(见 §3),头的**格式、scope 声明、beta 标志都是 CC 发的**,天然等效。

### client metadata

- **CC 版本头、`User-Agent`**:由 CC 二进制产生。跑真 `2.1.168` → metadata 就是真的,无需也不应伪造。

### 内容层

- **请求 body**:CC 构造(messages、model、tools 等)。
- **计费头 `cch`(`x-anthropic-billing-header`)**:客户端对 body 算的非加密 xxHash64。服务端不校验它,但它**锚定 body**——只要 body 不动,这个头自洽。

### 行为层

- **请求时序、并发**:由实际使用产生。一个人多设备通过同一出口登录使用,本就是「同出口普通登录」基线的一部分。

### 小结

跑官方 CC 二进制时,**网络指纹、client metadata、认证头格式与 scope、body、计费头几乎全部天然等效**。中转真正要处理的只有两件:**认证凭据的值**,和**统一出口**。

---

## 2. CC 访问哪些端点 / 转发哪些

CC 运行时会触及多个端点。收口判据 = **fail-closed 后缀通配(档位 C)**:凡 **Anthropic/Claude 自家域名**(`*.anthropic.com` / `*.claude.ai` / `*.claude.com` / `*.claudeusercontent.com` / 内部 `*.ant.dev`)一律经统一出口收口——不论用途吃不吃得准,「不漏」优先;只有 Anthropic 观测不到的**非自家第三方**流量(WebFetch 用户 URL、用户自配 MCP、github/npm)才本地直连。依据:自用工具下「流量经自己服务器」无隐私损失,**直连才暴露设备真实 IP**,故收口在隐私上恒优、唯一代价是带宽。判据从早先「精确清单、新增 host 显式登记」反转为后缀自适应——CC 新增的自家端点自动收口、无需人跟版(分类权威在 `internal/hosts.Classify`)。

| 端点 | 用途 | 处理 |
|---|---|---|
| `api.anthropic.com` / `console.anthropic.com` | 推理、OAuth token 使用、WebFetch 域名预检 | **转发·MITM**——经出口换发真 token(唯一需要真凭据的流量) |
| 其余自家域名:控制面/账户(`claude.ai`/`platform.claude.com`/`code.claude.com`)、文档/状态/支持、MCP 网关(`*.mcp.claude.com`)、用户内容(`*.claudeusercontent.com`)、内部/staging(`*.ant.dev`) | 登录态/控制面/Anthropic 托管 MCP/用户内容 | **转发·纯透传**——盲隧道收口出口 IP(不解密、不换 token);多数 setup-token 场景运行时不触发,fail-closed 一并收口无害 |
| 第三方收口(精确登记):`http-intake.logs.us5.datadoghq.com`、`api.datadoghq.com`/`mcp.sentry.dev`、`claude*.fedstart.com` | CC 自发遥测 / 硬编码第三方 MCP / FedRAMP 部署 | **转发·纯透传**——非自家、后缀匹配不到,精确登记;收口以对该第三方也隐藏设备 IP |
| WebFetch 用户 URL / 用户自配 MCP(`mcp.notion.so` 之类) / `raw.githubusercontent.com` / npm | 用户内容 / 工具执行 / 非 Anthropic 资源 | **直连**——非自家、Anthropic 观测不到;自配 MCP 要收口须加进 `hosts.PassthroughExact` |

**为什么遥测 / 更新必须经出口转发、而不能从设备直连**:它们虽不发往 `api.anthropic.com`,但 Anthropic 仍摄取——遥测进 Anthropic 的 Datadog 账户、更新由 Anthropic 的 CDN 提供。若从设备直连,它们从设备真实 IP 出网,IP ≠ 统一出口,于是「推理来自出口、遥测/更新来自设备」IP 不一致,直接破坏「同出口普通登录设备」等效。所以处理它们的轴是**收口出口 IP**,而非端点域名是否属 `anthropic.com`。

**实测端点与处理(Claude Code 2.1.170:二进制硬编码域名提取 + CONNECT 抓包;`ci/egress/hostscan` 漂移守卫持续跟版)**:

- 遥测 `http-intake.logs.us5.datadoghq.com/api/v2/logs`:Datadog 日志 intake,用 `DD-API-KEY` 头认证(Anthropic 内嵌的 Datadog key),**不携带用户 OAuth token**。
- 更新 `downloads.claude.ai/claude-code-releases/…`:公开 CDN,**无认证**。
- 第三方 MCP `api.datadoghq.com`/`mcp.sentry.dev`:CC 推荐配置里的 MCP server 端点(需用户显式配密钥才连);档位 C 一并收口。
- 本版**无独立 sentry / statsig 遥测**:特性开关走 `api.anthropic.com/api/claude_code/settings`、指标走 `/api/claude_code/metrics`(均在 `api.anthropic.com`,已随推理流量转发)。

二者都不带订阅 token,故**纯透传**即足够:经出口盲 CONNECT 隧道把出口 IP 收敛到统一出口,**不解密、不换 token、不扩解密面、不破坏 cert pinning**(claude 与真上游端到端做 TLS,cc-mysub 只搬 TCP 字节)。这正是「等效」要的——遥测/更新与推理同出口,且字节与普通设备一致。(禁用 `CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1` 是更激进的替代:TCB 更小但牺牲遥测/更新功能;本部署选保留功能、走转发。)

**真正直连的只有非自家第三方流量**:WebFetch 用户给的 URL、用户运行时自配 MCP、`raw.githubusercontent.com` / npm 等发往第三方主机——Anthropic 观测不到,不构成感知面;且普通登录设备这些同样直连。用户自配 MCP 默认直连(功能正常、暴露设备 IP),要收口须把该 host 加进 `hosts.PassthroughExact`(--allow 不行——只让设备 chain,cc-mysub 仍按 allowlist 403)。

> 控制面登录域名官方文档现用 `platform.claude.com`(早期为 `console.anthropic.com`);无论哪个都属交互登录端点,`setup-token` 预生成凭据的中转场景运行时不依赖它。

---

## 3. 中转如何处理使其等效

原则:**只搬运、不重构、不注入**。CC 发什么就转发什么,中转只在凭据与出口两处做最小必要处理。

- **认证(换发真 token)**:中转按设备身份,把请求里的占位/设备凭据换成真订阅 token,使 `Authorization` 与"登录设备直接持 token"逐字一致。scope 声明、beta header 不碰(CC 自己发的)。
  - 这之所以可行:Anthropic API 对请求**没有签名 / HMAC / token-binding / DPoP / 反篡改**——bearer token 是唯一凭据,独立于请求内容校验。所以替换 token 不破坏请求其余部分。
- **内容(body 逐字节透传)**:body 一个字节都不改,计费头 `cch` 随之自洽 → **用量如实计入你的真账户**(这正是「自用、如实计费」,不是规避计费)。
- **网络(统一出口 + 真指纹)**:所有中转设备经同一出口出网 = 满足「同出口」基线。中转对 Anthropic 的 TLS **由设备上的真 CC 发起**——中转做的 MITM 重加密只为读取目标 host、换 token,**不重建请求、不替 CC 说话**,所以到达官方的 TLS/HTTP2 指纹仍是真 CC 的。
- **零额外注入**:不添加任何 CC 自己不会发的头或痕迹;匿名请求(无凭据)保持匿名透传,不被动加上身份。任何额外注入都会让中转设备区别于"普通登录设备",所以一律不做。

### `/usage` 限额条为何看不到(认证 scope 的技术后果)

这是一个常被误认为"中转没做好"的点,实际是 **OAuth scope 的固有结果,与中转、与等效都无关**:

- `/usage` 的**用量限额条**(5 小时 / 每周那些)数据来自 `api.anthropic.com/api/oauth/usage`,该端点要求 OAuth **`user:profile`** scope。
- 而 `setup-token` 产出的凭据**永不含 `user:profile`**(见 §1 认证层),故该端点对这套凭据**恒返回 403**。
- 因此**直连、同出口普通登录、还是经中转,只要用的是 setup-token 凭据,限额条都一样看不到**——它不是中转引入的差异,正说明中转与"普通 setup-token 登录"等效。
- `/usage` 的其余信息正常:header 仍显示 "using your subscription"、`Total cost: $0.0000`(订阅不按 token 计费)——这些只需 `user:inference`。

---

## 4. 环境搭建(最小要件)

抽象出与具体实现无关的四个要件:

- **统一出口 / 转发点**:一个稳定的公网出口,所有中转设备的 Anthropic 流量经它出网,以满足「同出口」基线。出口同时是真 token 的持有处。
- **TLS 终结与重加密**:出口处终结来自设备的外层 TLS(用于认证设备身份),再对 `api.anthropic.com` 建立 TLS 转发。重加密仅为读取目标 host 与换发 token;**内层请求由设备上的真 CC 发起**,出口不重构它。
- **token 管理**:真订阅 token **只**集中在出口,按设备换发;**真 token 永不下发到设备**——设备只持一个非凭据的占位值。这样不可信设备拿不到真凭据,而官方收到的请求带的是真 token,与登录设备等效。
- **设备接入**:设备跑**官方 CC 二进制**,经一个本地分流器把发往 Anthropic 的流量导向出口——`api.anthropic.com` 经 MITM 换 token,遥测(`http-intake.logs.us5.datadoghq.com`)/ 更新(`downloads.claude.ai`)经纯透传盲隧道(不解密、不换 token,仅收口出口 IP);只有与 Anthropic 无关的流量(WebFetch 用户 URL / MCP / `raw.githubusercontent.com` / npm)本地直连。

---

**一句话**:跑官方 CC 二进制 + 只在「凭据值」和「统一出口」两处做最小处理 + 绝不重构请求或注入痕迹,官方侧收到的就是一组带真 token、真 CC 指纹、真 body 的请求,来自一个统一出口——与「一个订阅所有者在该出口后多设备正常登录」在数据层面等效。
