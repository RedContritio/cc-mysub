package proxy

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// 起 mock 上游, 捕获它收到的请求供断言
func newMockUpstream(t *testing.T, capture *http.Request, body *string) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		*capture = *r.Clone(r.Context())
		b, _ := io.ReadAll(r.Body)
		*body = string(b)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(200)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
}

func TestProxyRewritesAuthAndPassesThrough(t *testing.T) {
	var got http.Request
	var gotBody string
	up := newMockUpstream(t, &got, &gotBody)
	defer up.Close()

	p, err := New(up.URL, "sk-ant-oat01-REAL")
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(p.Handler())
	defer srv.Close()

	req, _ := http.NewRequest("POST", srv.URL+"/v1/messages?beta=true", strings.NewReader(`{"x":1}`))
	req.Header.Set("Authorization", "Bearer cco_dev_PLACEHOLDER")
	req.Header.Set("X-Api-Key", "cco_dev_PLACEHOLDER")
	req.Header.Set("anthropic-beta", "oauth-2025-04-20")
	req.Header.Set("anthropic-version", "2023-06-01")
	req.Header.Set("user-agent", "claude-cli/2.1.162")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	// 替换: 上游看到真 token
	if got.Header.Get("Authorization") != "Bearer sk-ant-oat01-REAL" {
		t.Errorf("upstream Authorization = %q", got.Header.Get("Authorization"))
	}
	// 安全不变量: per-device token 一个字节都没出门
	if strings.Contains(got.Header.Get("Authorization"), "cco_dev") {
		t.Error("per-device token leaked into Authorization")
	}
	// 清理: x-api-key 被删
	if got.Header.Get("X-Api-Key") != "" {
		t.Errorf("X-Api-Key not stripped: %q", got.Header.Get("X-Api-Key"))
	}
	// 透传: 指纹头原样
	if got.Header.Get("anthropic-beta") != "oauth-2025-04-20" {
		t.Errorf("anthropic-beta not passed through")
	}
	if got.Header.Get("user-agent") != "claude-cli/2.1.162" {
		t.Errorf("user-agent not passed through")
	}
	// 透传: query + body + path
	if got.URL.RawQuery != "beta=true" {
		t.Errorf("query = %q", got.URL.RawQuery)
	}
	if got.URL.Path != "/v1/messages" {
		t.Errorf("path = %q", got.URL.Path)
	}
	if gotBody != `{"x":1}` {
		t.Errorf("body = %q", gotBody)
	}
}
