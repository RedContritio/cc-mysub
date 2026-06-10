package connect

import "testing"

func TestParseConnect(t *testing.T) {
	host, ok := ParseConnect("CONNECT api.anthropic.com:443 HTTP/1.1\r\n")
	if !ok || host != "api.anthropic.com" {
		t.Fatalf("got %q %v", host, ok)
	}
	if _, ok := ParseConnect("GET / HTTP/1.1\r\n"); ok {
		t.Error("non-CONNECT accepted")
	}
}

// TestParseConnect_RejectsInvalidHost 验证 host 校验：因 host 直通证书签发，
// 须拒绝控制字符注入、通配符、缺端口、空 host 等。
func TestParseConnect_RejectsInvalidHost(t *testing.T) {
	bad := []string{
		"CONNECT api.anthropic.com HTTP/1.1\r\n",   // 缺 :port
		"CONNECT *.anthropic.com:443 HTTP/1.1\r\n", // 通配符
		"CONNECT ev\x00il:443 HTTP/1.1\r\n",        // 控制字符注入
		"CONNECT :443 HTTP/1.1\r\n",                // 空 host
		"CONNECT  HTTP/1.1\r\n",                    // 无 target
		"\r\n",                                     // 空行
	}
	for _, line := range bad {
		if h, ok := ParseConnect(line); ok {
			t.Errorf("expected reject for %q, got host=%q ok=true", line, h)
		}
	}
	// 合法: console.anthropic.com (Phase 2 token 端点也是合法 host) 与 IP 字面量
	if h, ok := ParseConnect("CONNECT console.anthropic.com:443 HTTP/1.1\r\n"); !ok || h != "console.anthropic.com" {
		t.Errorf("console host: got %q %v", h, ok)
	}
}

// TestParseConnect_Canonicalizes 验证 host 规范化为 DNS 等价小写、剥尾点 FQDN——否则
// API.ANTHROPIC.COM / api.anthropic.com. 等变体会绕过 hosts.Classify 的 fail-closed 收口(codex 对抗评审)。
func TestParseConnect_Canonicalizes(t *testing.T) {
	cases := []struct{ line, want string }{
		{"CONNECT API.ANTHROPIC.COM:443 HTTP/1.1\r\n", "api.anthropic.com"},   // 大写
		{"CONNECT api.anthropic.com.:443 HTTP/1.1\r\n", "api.anthropic.com"},  // 尾点 FQDN
		{"CONNECT Api.Anthropic.Com.:443 HTTP/1.1\r\n", "api.anthropic.com"},  // 混合大小写 + 尾点
		{"CONNECT api.anthropic.com..:443 HTTP/1.1\r\n", "api.anthropic.com"}, // 多尾点
	}
	for _, c := range cases {
		if h, ok := ParseConnect(c.line); !ok || h != c.want {
			t.Errorf("ParseConnect(%q) = %q,%v; want %q,true", c.line, h, ok, c.want)
		}
	}
	// 纯尾点畸形 host 规范化后为空 → 拒
	if h, ok := ParseConnect("CONNECT .:443 HTTP/1.1\r\n"); ok {
		t.Errorf("bare-dot host should reject, got %q", h)
	}
}

// 注：ParseProxyAuthorization/ValidToken 已随信道 token 子系统删除（mTLS 证书取代），其测试一并移除。
