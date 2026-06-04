# Security

本文档面向使用者，说明 CC MySub 的威胁模型、凭据分层、合规定位与漏洞上报流程。架构背景见 [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md)。

## 1. 威胁模型

- **客户端是真 CC 二进制（不可改）。** 每台设备跑的是原生 Claude Code CLI，我们无法在其中加入应用层的防重放签名或 channel binding。因此请求的真实性无法在应用层证明。
- **安全必须来自信道加密。** 由于客户端不可改，唯一可靠的保护是把 per-device token 放进一条加密信道传输（Tailscale / WireGuard、TLS、或 frp `https2http`）。
- **裸明文 http 不安全。** 在零加密层的 http 上传 per-device token，等同于把门禁卡明文广播——任何能观测链路的人都能截获并重放。**禁止在明文 http 上暴露代理。** 请始终使用 README「入口层加密矩阵」中的任一加密信道。
- 代理进程本身只监听本地端口（默认 `127.0.0.1:8788`）；如何把端口安全暴露到远程，完全委托给入口层。

## 2. per-device token 与真 setup-token 分离

per-device token 与真 setup-token 是**两个独立随机串，无密码学关系**：

- **per-device token = 门禁卡号。** 发给某台设备，不携带真 token 的任何字节。
- **真 setup-token = 主钥匙。** 本机独立保管（`upstream.json`，chmod 600），永不下发。

代理不「解密」per-device token，而是「查名单核身 + 整头替换」：取入站 `Authorization` 里的 token → sha256 → 查 `devices.json` → 命中得设备标签（**未命中直接 401，根本不转发**）→ 出站把 `Authorization` 整头重写为真 token，并删除入站 `X-Api-Key`。

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

## 订阅档位声明（subscriptionType）的诚实边界

客户端要在 UI 上显示 Max 标签、解锁 auto mode 的 Bash classifier、让 1M 变体可选、收到 tier beta，依赖客户端本地环境变量 `CLAUDE_CODE_SUBSCRIPTION_TYPE` 声明订阅档位（pro/max/team/enterprise）。需要诚实说明它的边界：

- **这是客户端本地 env 声明，CC 不验真。** 在占位 token（OAUTH_TOKEN 路径）下，真 CC 直接读取本机 `CLAUDE_CODE_SUBSCRIPTION_TYPE` 来决定 tier 自我认知，不对其真伪做任何校验。它只影响客户端自己的界面与门控，不是一道服务端授权。
- **客户端 tier 自我认知 ≠ 服务端鉴权。** 上游真 Anthropic 是否接受这套档位，取决于代理后面挂的**真 setup-token 的真实权限**，而非客户端声明的 `CLAUDE_CODE_SUBSCRIPTION_TYPE`。二进制层面无法断言服务端如何处理占位 subscriptionType——不要据此声称"服务端必然接受"。
- **它不改变 B 类定位。** 整链仍是真 CC + 纯透传、与设备直连逐字节不可区分；`CLAUDE_CODE_SUBSCRIPTION_TYPE` 本就是给订阅用户使用的 env，由客户端自行声明其持有的档位。
- **不要据此"凭空获得"未持有的订阅权益。** 该 env 只让客户端按声明的档位呈现界面与功能门控；真正的订阅权益与计费归属，始终落在代理后那份真 setup-token 对应的账户上。请按你实际持有的档位填写。

## 4. 报告漏洞

请通过 GitHub 的**私有 security advisory** 上报：仓库页面 → **Security** 标签 → **Report a vulnerability**。

请勿在公开 issue、PR 或讨论区披露安全问题。报告中请尽量包含复现步骤、影响范围和受影响版本。我们会在私有 advisory 内跟进并协调修复与披露时间。
