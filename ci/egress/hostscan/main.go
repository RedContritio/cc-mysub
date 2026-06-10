// Command hostscan 静态扫描 claude 可执行文件(Mach-O 原生打包 或 npm cli.js bundle 均可),
// 提取其中硬编码的、与「CC 自发遥测/控制面」相关的域名候选,供 egress-audit 的漂移守卫 diff 一份
// checked-in 的已审基线(ci/egress/known-hosts.txt)。Monitored 会先把自家域名(hosts.IsFirstParty——
// 经 FirstPartySuffixes 后缀自动收口、零维护)排除,只留需人决策的第三方候选;出现基线外的新第三方
// 域名 → CI 报错,逼人分类(新遥测厂商/新 datadog region=加进 hosts.PassthroughExact 收口 vs 第三方
// MCP/SDK 死码=记进基线直连)。
//
// 定位(诚实标注,见 docs/SUBSCRIPTION-FORWARDING.md):这是漂移「提醒」,不是穷尽「保证」。
//  1. 只盯命中遥测/控制面关键词(kwRe)的域名——不含已知关键词的全新遥测厂商域名(如 metrics-xyz.io)
//     会漏。这是「关键词子集」基线的固有盲区(全集穷尽因 minify 噪声不可维护,实测 1806 候选→灾难
//     信噪比,故取子集)。
//  2. 静态提取给的是「候选上界」,不是「运行时实际发出的请求」——候选里混着 MCP 配置端点
//     (如 api.datadoghq.com/mcp,需用户显式配 DD-API-KEY 才连)、staging 死域、SDK 常量。
//     「这是该收口的遥测 vs 本就该直连」需人读上下文裁决,扫描器不替人分类。
package main

import (
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"

	"github.com/redcontritio/cc-mysub/internal/hosts"
)

// httpsRe 抓带 scheme 的 endpoint(host 部分);bareRe 抓裸 host 字符串(如 datadog intake——
// 实测它在二进制里不带 https:// 前缀,纯 https 提取会漏,故必须并用裸域名提取)。
// bareRe 的 TLD 集合刻意不含 me/co/so/sh/gg 等「既是 TLD 又是常见代码标识符后缀」的,以避开
// minify 产物(com.anthropic.models.me / this.segments.so 之类)的海量误报。
var (
	httpsRe = regexp.MustCompile(`https://([a-zA-Z0-9._-]+)`)
	bareRe  = regexp.MustCompile(`([a-z0-9]([a-z0-9-]*[a-z0-9])?\.)+(com|net|org|io|ai|dev|cn|eu|cloud|app)`)

	// kwRe:遥测/控制面相关关键词。命中才保留(功能/SDK/文档域名如 github/npm/azure 不进基线——
	// 它们本就该直连,不是漂移守卫的关注对象)。新增遥测厂商时在此补关键词。
	kwRe = regexp.MustCompile(`(?i)anthropic|claude|datadog|intake|sentry|statsig|segment|amplitude|mixpanel|posthog|beacon|telemetry|metric|analytics`)

	// noisePrefix/noiseSeg:剔除 minify 后被误当域名的代码标识符(反向包名 com.x、JS 链 this.x、
	// proto 消息路径 x.proto.y 等)。启发式,随 CC 打包方式演化可能增补。
	noisePrefix = regexp.MustCompile(`^(this|com|org|[0-9]+)\.`)
	noiseSeg    = regexp.MustCompile(`\.(proto|types|models|collector|config|beta|segments|prototype)\.`)
)

// knownNoise:命中关键词、形态合法、却已人工确认是 minify 垃圾(非真 endpoint)的 2 段域名,
// 启发式正则压不掉。显式列出使扫描输出与基线一致;新发现的同类垃圾追加于此。
var knownNoise = map[string]bool{
	"telemetry.app": true,
	"log.co":        true,
	"logind.co":     true,
	"non-claude.ai": true,
}

// ScanHosts 从原始字节提取已审范围内的域名候选(排序去重)。纯函数,供单测以 fixture 覆盖。
func ScanHosts(data []byte) []string {
	set := map[string]bool{}
	s := string(data)
	add := func(h string) {
		h = strings.ToLower(strings.TrimSuffix(h, "."))
		if !strings.Contains(h, ".") { // 单段(被尾点截断的拼接片段如 aws-external-anthropic.)→ 丢
			return
		}
		if !kwRe.MatchString(h) {
			return
		}
		if noisePrefix.MatchString(h) || noiseSeg.MatchString(h) || knownNoise[h] {
			return
		}
		set[h] = true
	}
	for _, m := range httpsRe.FindAllStringSubmatch(s, -1) {
		add(m[1])
	}
	for _, m := range bareRe.FindAllString(s, -1) {
		add(m)
	}
	out := make([]string, 0, len(set))
	for h := range set {
		out = append(out, h)
	}
	sort.Strings(out)
	return out
}

// Monitored 返回需漂移监控的域名:ScanHosts 提取结果中排除自家域名(hosts.IsFirstParty——经后缀
// 自动收口、无需基线管理),只留需精确决策的第三方候选(新遥测厂商/新 datadog region 之类)。
func Monitored(data []byte) []string {
	var out []string
	for _, h := range ScanHosts(data) {
		if hosts.IsFirstParty(h) {
			continue
		}
		out = append(out, h)
	}
	return out
}

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: hostscan <path-to-claude-executable>")
		os.Exit(2)
	}
	data, err := os.ReadFile(os.Args[1])
	if err != nil {
		fmt.Fprintf(os.Stderr, "read %s: %v\n", os.Args[1], err)
		os.Exit(2)
	}
	for _, h := range Monitored(data) {
		fmt.Println(h)
	}
}
