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

// TestParseProxyAuthorization 镜像 TestParseConnect_RejectsInvalidHost:
// 因该 token 直通 CONNECT 准入(信道层),空/全空白为硬不变量(不委托 Lookup),
// 且 host 之外的注入向量(内部空格/控制字符/CR/LF/NUL/头名前缀影射)须一律拒。
// 真实调用方 forward.go 用 br.ReadString('\n') 读头行,故行尾带 \r\n,
// 解析须容忍恰一个行尾终止符,但拒绝任何内部 CR/LF。
func TestParseProxyAuthorization(t *testing.T) {
	bad := []struct {
		name string
		line string
	}{
		{"trailing space no value", "Proxy-Authorization: Bearer \r\n"},
		{"scheme only no value no space", "Proxy-Authorization: Bearer\r\n"},
		{"bearer then tabs", "Proxy-Authorization: Bearer\t\t\r\n"},
		{"interior space in token", "Proxy-Authorization: Bearer a b\r\n"},
		{"nul in token", "Proxy-Authorization: Bearer a\x00b\r\n"},
		{"interior CR in token", "Proxy-Authorization: Bearer a\rb\r\n"},
		{"interior LF in token", "Proxy-Authorization: Bearer a\nb\r\n"},
		{"name prefix X-", "X-Proxy-Authorization: Bearer cco_dev_abc\r\n"},
		{"name suffix -Foo", "Proxy-Authorization-Foo: Bearer cco_dev_abc\r\n"},
		{"space before colon", "Proxy-Authorization : Bearer cco_dev_abc\r\n"},
		{"wrong scheme Basic", "Proxy-Authorization: Basic cco_dev_abc\r\n"},
		{"no scheme", "Proxy-Authorization: cco_dev_abc\r\n"},
		{"no colon", "Proxy-Authorization Bearer cco_dev_abc\r\n"},
		{"empty line", "\r\n"},
	}
	for _, c := range bad {
		if tok, ok := ParseProxyAuthorization(c.line); ok {
			t.Errorf("%s: expected reject for %q, got token=%q ok=true", c.name, c.line, tok)
		}
	}

	// 正例: 含行尾 \r\n (真实调用方形态) 与不含(直传形态)均须 token,true。
	for _, line := range []string{
		"Proxy-Authorization: Bearer cco_dev_abc\r\n",
		"Proxy-Authorization: Bearer cco_dev_abc",
	} {
		if tok, ok := ParseProxyAuthorization(line); !ok || tok != "cco_dev_abc" {
			t.Errorf("positive %q: got token=%q ok=%v, want cco_dev_abc true", line, tok, ok)
		}
	}
	// 头名大小写不敏感 (EqualFold) 须 accept。
	if tok, ok := ParseProxyAuthorization("proxy-authorization: Bearer cco_dev_abc\r\n"); !ok || tok != "cco_dev_abc" {
		t.Errorf("lowercase name: got token=%q ok=%v, want cco_dev_abc true", tok, ok)
	}
	// scheme 大小写不敏感须 accept。
	if tok, ok := ParseProxyAuthorization("Proxy-Authorization: bearer cco_dev_abc\r\n"); !ok || tok != "cco_dev_abc" {
		t.Errorf("lowercase scheme: got token=%q ok=%v, want cco_dev_abc true", tok, ok)
	}
}
