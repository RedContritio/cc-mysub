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
