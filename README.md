# CC MySub

让你**一份 Claude 订阅**被多台设备上的真·Claude Code 复用。每台设备跑的是真正的 Claude Code CLI(**不是** web 终端);订阅凭据只留在你的服务器、永不下发到设备。

原理:设备只把 `api.anthropic.com` 流量经 **mTLS** 转发到你的 cc-mysub 服务端换发真 token,其余一切(WebFetch、MCP、更新、包管理器…)本地直连。深入细节见 [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md)、安全与合规见 [`SECURITY.md`](SECURITY.md)、部署运维见 [`docs/OPERATING.md`](docs/OPERATING.md)。

## 快速开始

### 你需要先有

- 一台**公网服务器**(知道它的公网 IP)
- 一个 **Claude 订阅**(能跑 `claude setup-token` 拿到 token)

> 没有域名也行:下面用 `<IP>.sslip.io` 这类免费 DNS(自动解析到你的 IP)当主机名,即可签正常的 Let's Encrypt 证书。Let's Encrypt 不签纯 IP,所以需要这一层。

### 一、搭服务端(公网服务器上,做一次)

下面设公网 IP 为 `1.2.3.4`,于是主机名 `public_host = 1.2.3.4.sslip.io`(换成你自己的 IP)。

```bash
# 1) 装二进制
go build -o /usr/local/bin/cc-mysub ./cmd/cc-mysub   # 或从 Releases 下对应平台的二进制

# 2) 签 TLS 证书(acme.sh HTTP-01,需 80 端口临时可达)→ 放到 cc-mysub 约定路径
acme.sh --issue --standalone -d 1.2.3.4.sslip.io
mkdir -p ~/.config/cc-mysub/certs
acme.sh --install-cert -d 1.2.3.4.sslip.io \
  --cert-file ~/.config/cc-mysub/certs/1.2.3.4.sslip.io.crt \
  --key-file  ~/.config/cc-mysub/certs/1.2.3.4.sslip.io.key

# 3) 写两个配置文件到 ~/.config/cc-mysub/
#    config.json:
#      {"listen":"0.0.0.0:443","client":{"public_host":"1.2.3.4.sslip.io","subscription_type":"max"}}
#    upstream.json(chmod 600;token 来自 claude setup-token):
#      {"oauthTokens":[{"id":"a","token":"sk-ant-oat01-..."}]}

# 4) 生成内层 CA(首次一次性:用一个引导指纹触发生成)
cc-mysub device-init --label bootstrap                          # 打印一个指纹
cc-mysub add-device --label bootstrap --fingerprint <该指纹>    # 首次会生成 ca.crt / ca.key

# 5) 发布给设备用的配置(每个 release 一次)
cc-mysub gen-config --release v1.0.0 > deploy.json
#   把 deploy.json 放到一个 HTTPS URL(如 GitHub gist 的 raw 链接),带外(私信/IM)把该 URL 给设备

# 6) 启动(监听公网 443 需 root 或 setcap;后台常驻见 docs/OPERATING.md)
sudo cc-mysub
```

### 二、接入一台设备(每台要用的设备)

```bash
# 1) 设备上自助安装(用上面发布的配置 URL;label 默认主机名)
curl -fsSL https://raw.githubusercontent.com/redcontritio/cc-mysub/main/install.sh | sh -s -- <配置URL> [label]

# 2) 安装脚本会打印本设备指纹后停下等批准。在服务器上批准这台设备:
cc-mysub add-device --fingerprint <设备打印的指纹> --label my-laptop

# 3) 批准后设备端自动装好。之后这台设备用 myclaude 代替 claude:
myclaude            # 就是真 claude,但走你的订阅
```

依赖:设备需 `curl` + (`jq` 或 `python3`) + `openssl` + `sha256sum`/`shasum`;支持 linux/macOS × amd64/arm64(不支持 Windows,install.sh 是 bash)。

## 进阶 / 排查

- 多设备管理、吊销、换证书、env 语义与订阅档位、1M、`/usage` 限额条限制、与其它 https 服务共用 443(frp) → [`docs/OPERATING.md`](docs/OPERATING.md)
- 架构 → [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md);安全模型与合规 → [`SECURITY.md`](SECURITY.md)

## 报告漏洞

请开私有 security advisory(仓库 → Security → Report a vulnerability),勿在公开 issue 披露。详见 [`SECURITY.md`](SECURITY.md)。
