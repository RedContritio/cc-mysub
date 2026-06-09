// Package hosts 是 cc-mysub 转发主机的权威清单:单一事实源,供 cc-mysub forward-proxy
// （NewForwardProxy 的 MITM allow + 透传 allow）与设备 helper/splitter（默认链到 cc-mysub
// 的 host）共用,避免两端各写一份而漂移。精确匹配——不做后缀/通配放宽,使新增 host 必须显式登记。
//
// 两类必须互斥(一个 host 不能既换 token 又透传);NewForwardProxy 在装配时强制此契约。
package hosts

// MITMHosts 是需解密换 token 的 host（唯一携带订阅凭据的流量）。
//   - api.anthropic.com: 推理 + OAuth token 使用 + WebFetch 域名预检。
//   - console.anthropic.com: 沿袭原始 allowlist 的防御性保留。setup-token 中转场景运行时不
//     触发控制面登录,故此条休眠;保留它使「若出现则经出口换 token」而非从设备直连(纵深防御)。
var MITMHosts = []string{
	"api.anthropic.com",
	"console.anthropic.com",
}

// PassthroughHosts 是经出口纯透传（不解密、不换 token）的 host。实测自 Claude Code 2.1.169
// （strings 提取二进制硬编码域名 + CONNECT 抓包）：
//   - http-intake.logs.us5.datadoghq.com: 遥测日志 /api/v2/logs，DD-API-KEY 头认证、不带用户 token
//   - downloads.claude.ai: 自动更新二进制/插件下载（公开 CDN、无认证）
//
// 二者均不携带订阅 token，故纯透传即足够（无需 MITM 换 token），亦不扩解密面、不破坏 cert pinning
// （claude 校验的是真上游证书）。后续 CC 版本若改 DD site 或新增端点，须据实测更新此列表。
var PassthroughHosts = []string{
	"http-intake.logs.us5.datadoghq.com",
	"downloads.claude.ai",
}

// All 返回 MITMHosts ∪ PassthroughHosts 的并集（新切片，调用方可安全改动）。
// 供设备 splitter 的默认 allow（哪些 host 链到 cc-mysub）与 cc-mysub 的合并准入门共用。
func All() []string {
	out := make([]string, 0, len(MITMHosts)+len(PassthroughHosts))
	out = append(out, MITMHosts...)
	out = append(out, PassthroughHosts...)
	return out
}
