// Package hosts 是 cc-mysub 转发主机的权威分类:单一事实源,供 cc-mysub forward-proxy
// (按 Classify 决定 MITM/透传/403)与设备 helper/splitter(按 Classify!=Direct 决定是否链到
// cc-mysub)共用,避免两端各写一份而漂移。
//
// 分流姿态 = fail-closed(档位 C):Anthropic/Claude 自家域名按后缀通配一律收口(passthrough),
// 不再逐个精确登记——「不漏」优先于「可审计」。这反转了早先「精确匹配、新增 host 必须显式登记」
// 的原则:对自家域名,CC 将来新增的任何端点(newmetrics.anthropic.com 之类)自动被收口,无需人
// 跟版。第三方域名(用户配的 MCP、CC 自发遥测)无法靠自家后缀匹配,仍精确登记收口。
//
// 固有 gap(诚实标注):用户在 ~/.claude.json 运行时自配的第三方 MCP(mcp.notion.so 之类)不在二进制
// 硬编码、不匹配自家后缀 → splitter 直连(功能正常,但暴露设备 IP)。要收口它须把该 host 加进
// PassthroughExact 在服务端登记——不能靠 helper --allow:--allow 只让设备 chain 到 cc-mysub,而
// cc-mysub 仍按本包的 allowlist 裁决,非清单 host 一律 403(正是 stage_split Probe D 验证的不变量)。
package hosts

import (
	"slices"
	"strings"
)

// MITMHosts:精确,需解密换 token(唯一携带订阅凭据的流量)。
//   - api.anthropic.com: 推理 + OAuth token 使用 + WebFetch 域名预检。
//   - console.anthropic.com: 沿袭原始 allowlist 的防御性保留(setup-token 场景运行时不触发控制面
//     登录,此条休眠;保留使「若出现则经出口换 token」而非从设备直连)。
var MITMHosts = []string{
	"api.anthropic.com",
	"console.anthropic.com",
}

// FirstPartySuffixes:Anthropic/Claude 自家域名后缀。matchSuffix 同时匹配 apex(anthropic.com)
// 与子域(*.anthropic.com),fail-closed 自适应。
//   - anthropic.com / claude.ai / claude.com: 推理外的控制面/账户/文档/状态/web/MCP 网关
//     (*.mcp.claude.com)/更新(downloads.claude.ai),均可能带账号或设备关联 → 收口。
//   - claudeusercontent.com: Anthropic 托管的用户内容(自用工具,经自己服务器无隐私损失;直连才
//     暴露设备 IP)→ 收口。
//   - ant.dev: Anthropic 内部域(staging/beacon 等);生产几乎不连,fail-closed 一并收口无害。
//
// 第三方平台 fedstart.com 不在此(见 PassthroughExact)——后缀会误收整个平台。
var FirstPartySuffixes = []string{
	"anthropic.com",
	"claude.ai",
	"claude.com",
	"claudeusercontent.com",
	"ant.dev",
}

// PassthroughExact:精确收口的第三方 host(非自家域名、靠后缀匹配不到,但要 fail-closed 收口)。
//   - http-intake.logs.us5.datadoghq.com: CC 自发遥测(datadog 日志 intake,DD-API-KEY 非用户 token)。
//   - api.datadoghq.com / mcp.sentry.dev: 二进制硬编码的第三方 MCP(连用户自己的第三方账号;收口以
//     对该第三方也隐藏设备 IP——档位 C)。用户运行时自配的其它 MCP 不在此 → 直连,见包头 gap 说明。
//   - claude.fedstart.com / claude-staging.fedstart.com: Anthropic 的 FedRAMP/govcloud 部署
//     (域名属第三方平台 fedstart.com,故精确登记而非 .fedstart.com 后缀,避免收口整个平台)。
var PassthroughExact = []string{
	"http-intake.logs.us5.datadoghq.com",
	"api.datadoghq.com",
	"mcp.sentry.dev",
	"claude.fedstart.com",
	"claude-staging.fedstart.com",
}

// Class 是一个 CONNECT 目标 host 的分流类别。
type Class int

const (
	Direct      Class = iota // splitter 本地直连 / cc-mysub 403(纵深防御)
	MITM                     // 解密换 token
	Passthrough              // 盲隧道收口(不解密、不碰 token,仅收敛出口 IP)
)

// matchSuffix 报告 host 是否等于 suffix(apex)或为其子域(host 以 "."+suffix 结尾)。
// 要求 "." 边界,故 evil-anthropic.com 不匹配 anthropic.com。
func matchSuffix(host, suffix string) bool {
	return host == suffix || strings.HasSuffix(host, "."+suffix)
}

// Classify 按 precedence 给 host 定类:精确 MITM > passthrough(精确 ∪ 自家后缀) > Direct。
// 精确 MITM 永远先判,故 api.anthropic.com 走换 token、不被 .anthropic.com 后缀降级成盲隧道。
func Classify(host string) Class {
	if slices.Contains(MITMHosts, host) {
		return MITM
	}
	if slices.Contains(PassthroughExact, host) {
		return Passthrough
	}
	for _, s := range FirstPartySuffixes {
		if matchSuffix(host, s) {
			return Passthrough
		}
	}
	return Direct
}
