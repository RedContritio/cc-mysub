// Package hosts 是 cc-mysub 转发主机的权威分类:单一事实源,供 cc-mysub forward-proxy
// (决定 MITM 换 token vs 纯透传)与设备 helper/splitter（决定哪些 host 链到 cc-mysub）共用，
// 避免两侧 allowlist 漂移。精确匹配——不做后缀/通配放宽，使新增 host 必须显式登记。
package hosts

import "slices"

// Mode 是一个 CONNECT 目标 host 的处理类别。
type Mode int

const (
	// ModeDeny: 不在任何 allowlist。cc-mysub 侧 403（纵深防御），设备 splitter 侧本地直连。
	ModeDeny Mode = iota
	// ModeMITM: 解密 + 换发真订阅 token。仅 Anthropic 控制面/数据面——唯一需要真凭据的流量。
	ModeMITM
	// ModePassthrough: 盲隧道转发（经统一出口、不解密、不碰 token）。CC 的非必要 Anthropic
	// 产品流量（遥测/更新），若从设备直连会泄漏设备真实 IP、破坏「同出口普通登录设备」等效。
	ModePassthrough
)

// MITMHosts 是需解密换 token 的 host（唯一携带订阅凭据的流量）。
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

// Classify 返回 host 的处理类别（精确匹配；未登记 → ModeDeny）。
func Classify(host string) Mode {
	if slices.Contains(MITMHosts, host) {
		return ModeMITM
	}
	if slices.Contains(PassthroughHosts, host) {
		return ModePassthrough
	}
	return ModeDeny
}

// All 返回 MITMHosts ∪ PassthroughHosts 的并集（新切片，调用方可安全改动）。
// 供设备 splitter 的默认 allow（哪些 host 链到 cc-mysub）与 cc-mysub 的合并准入门共用。
func All() []string {
	out := make([]string, 0, len(MITMHosts)+len(PassthroughHosts))
	out = append(out, MITMHosts...)
	out = append(out, PassthroughHosts...)
	return out
}
