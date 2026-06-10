package main

import (
	"reflect"
	"testing"
)

// fixture 混入:带 scheme 的真 endpoint、裸 host 的 datadog intake(纯 https 提取会漏的关键案例)、
// 非关键词功能域名(github——应被关键词过滤掉)、各类 minify 噪声(应被去噪)。
func TestScanHosts(t *testing.T) {
	data := []byte(`
		fetch("https://api.anthropic.com/v1/messages")
		ddSite = "http-intake.logs.us5.datadoghq.com"     // 裸 host,无 https://
		update = "https://downloads.claude.ai/stable/x"
		mcp = "https://api.datadoghq.com/mcp"              // 候选(MCP);分类交人,扫描器照提
		repo = "https://github.com/anthropics/claude-code" // 功能域名,非遥测关键词 → 滤
		s1 = this.config.telemetry.app                     // JS 链 minify 噪声
		s2 = com.anthropic.models.me                       // 反向包名 + 非 TLD me
		s3 = 0.co                                          // 数字前缀垃圾
		s4 = "https://aws-external-anthropic."             // 尾点拼接片段 → 丢
		s5 = telemetry.app                                 // 已知 minify 垃圾(knownNoise)
	`)
	got := ScanHosts(data)
	want := []string{
		"api.anthropic.com",
		"api.datadoghq.com",
		"downloads.claude.ai",
		"http-intake.logs.us5.datadoghq.com",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("ScanHosts mismatch\n got: %v\nwant: %v", got, want)
	}
}

// 关键案例单列:datadog intake 是裸 host(不带 https://),必须被裸域名分支抓到——
// 否则 PassthroughHosts 里唯一确定的生产遥测端点会从漂移守卫的视野里消失。
func TestScanHosts_bareDatadogIntake(t *testing.T) {
	got := ScanHosts([]byte(`x="http-intake.logs.us5.datadoghq.com";y=1`))
	if len(got) != 1 || got[0] != "http-intake.logs.us5.datadoghq.com" {
		t.Fatalf("bare datadog intake not captured: %v", got)
	}
}

// github 等功能域名不得进入候选(关键词子集只盯遥测/控制面;功能/MCP 域名本就直连)。
func TestScanHosts_dropsNonKeyword(t *testing.T) {
	got := ScanHosts([]byte(`https://github.com/x https://registry.npmjs.org/y https://login.microsoftonline.com/z`))
	if len(got) != 0 {
		t.Fatalf("non-keyword functional hosts leaked into candidates: %v", got)
	}
}
