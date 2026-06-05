# Security

本文档面向使用者，说明 CC MySub 的威胁模型、凭据分层、合规定位与漏洞上报流程。架构背景见 [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md)。

## 1. 威胁模型

- **客户端是真 CC 二进制（不可改）。** 每台设备跑的是原生 Claude Code CLI，我们无法在其中加入应用层的防重放签名或 channel binding。因此请求的真实性无法在应用层证明。
- **安全必须来自信道加密。** cc-mysub 自有 CA 签发 `public_host` 身份证书，`cc-mysub helper` 持 CA 公证书验证**外层 TLS**；设备经 `NODE_EXTRA_CA_CERTS` 信任 cc-mysub CA，用于内层 MITM 连接验证。frp 入口层必须用 **`type=tcp`** 透传（L4），外层 TLS 完整到达 cc-mysub——旧的 `https`/`https2http` 边缘终结 TLS 在 v4 作废，会破坏外层 TLS。
- **裸明文不安全。** 若外层 TLS 未建立（如 helper 的 CA 验证失败），helper 不转发。**禁止在无外层 TLS 的路径上暴露 cc-mysub forward-proxy。**
- 代理进程本身只监听本地端口（默认 `127.0.0.1:8788`）；如何把端口安全暴露到远程，完全委托给入口层（frp `type=tcp`）。

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

设备只设 `HTTPS_PROXY` 指向**本地** `cc-mysub helper`(用户态、无系统改动)。helper 分流:
- **仅 `api.anthropic.com`/`console.anthropic.com`** 经**外层 TLS** 链到 cc-mysub(cc-mysub 出示 public_host 身份证书, helper 用已下发 CA 公证书验证) → cc-mysub 内层按 host 现签 MITM 终结、换 token;
- **其余一切**(WebFetch 目标/MCP/更新/第三方遥测/包管理器) helper **本地直连**真主机, **永不接触 cc-mysub、不被 MITM**(cert-pinning 主机不破)。

**双层 TLS**: 外层 = cc-mysub 身份(防 CONNECT 目标 host 在 helper↔cc-mysub 跳明文); 内层 = api.anthropic.com MITM(设备经 `NODE_EXTRA_CA_CERTS` 信任 cc-mysub CA)。

**helper 无密钥面**: 不终结内层 TLS、不持 setup-token、不持 CA 私钥(只持 CA 公证书做外层身份验证)。

**隐私改善(相对 v3 blanket 代理)**: 非 Anthropic 流量留在设备本地, cc-mysub 不再有能力接触它们。

## CA 私钥管理

cc-mysub 自有 CA(`<config-dir>/ca.crt` + `ca.key`)由 `add-device` 首次生成并持久化(`ca.key` chmod **0600**、**不入 git**、幂等不重生——重生会废掉已信任设备)。设备经 `NODE_EXTRA_CA_CERTS` 信任 `ca.crt`(公证书)。**CA 私钥泄露 = 对信任它的设备的全 MITM 面**——务必 0600 + 仅留本机。

## 诚实降级: 不可区分性

每条请求**字节级**与「某台设备直连」不可区分(不碰遥测/性能/用量、匿名零注入、cch 透传); 但**多设备汇聚到本机单一出口 IP** 是直连不存在的关联信号。多 setup-token 池缓解「共用单一凭据」一维, **源 IP 收敛仍在**——定位为承担风险, 非隐私增强。

## 订阅档位声明（subscriptionType）的诚实边界

客户端要在 UI 上显示 Max 标签、解锁 auto mode 的 Bash classifier、让 1M 变体可选、收到 tier beta，依赖客户端本地环境变量 `CLAUDE_CODE_SUBSCRIPTION_TYPE` 声明订阅档位（pro/max/team/enterprise）。需要诚实说明它的边界：

- **这是客户端本地 env 声明，CC 不验真。** 在占位 token（OAUTH_TOKEN 路径）下，真 CC 直接读取本机 `CLAUDE_CODE_SUBSCRIPTION_TYPE` 来决定 tier 自我认知，不对其真伪做任何校验。它只影响客户端自己的界面与门控，不是一道服务端授权。
- **客户端 tier 自我认知 ≠ 服务端鉴权。** 上游真 Anthropic 是否接受这套档位，取决于代理后面挂的**真 setup-token 的真实权限**，而非客户端声明的 `CLAUDE_CODE_SUBSCRIPTION_TYPE`。二进制层面无法断言服务端如何处理占位 subscriptionType——不要据此声称"服务端必然接受"。
- **它不改变 B 类定位。** 整链仍是真 CC + 纯透传、与设备直连逐字节不可区分；`CLAUDE_CODE_SUBSCRIPTION_TYPE` 本就是给订阅用户使用的 env，由客户端自行声明其持有的档位。
- **不要据此"凭空获得"未持有的订阅权益。** 该 env 只让客户端按声明的档位呈现界面与功能门控；真正的订阅权益与计费归属，始终落在代理后那份真 setup-token 对应的账户上。请按你实际持有的档位填写。

## 4. 报告漏洞

请通过 GitHub 的**私有 security advisory** 上报：仓库页面 → **Security** 标签 → **Report a vulnerability**。

请勿在公开 issue、PR 或讨论区披露安全问题。报告中请尽量包含复现步骤、影响范围和受影响版本。我们会在私有 advisory 内跟进并协调修复与披露时间。
