package proxy

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestBaselineInboundWarnings(t *testing.T) {
	cases := []struct {
		name      string
		setup     func(*http.Request)
		wantWarns []string
	}{
		{"missing oauth beta", func(r *http.Request) {
			r.Header.Set("Authorization", "Bearer x")
		}, []string{"missing_oauth_beta"}},
		{"creds in x-api-key", func(r *http.Request) {
			r.Header.Set("X-Api-Key", "x")
			r.Header.Set("anthropic-beta", "oauth-2025-04-20")
		}, []string{"creds_in_xapikey"}},
		{"clean", func(r *http.Request) {
			r.Header.Set("Authorization", "Bearer x")
			r.Header.Set("anthropic-beta", "oauth-2025-04-20")
		}, nil},
		// P3-3: 真匿名遥测/注册表请求按设计无 oauth beta 头,不应误报 missing_oauth_beta(否则噪声淹没真信号)。
		{"anonymous no creds no beta", func(r *http.Request) {}, nil},
		// 带凭据(x-api-key)却缺 oauth beta 才是异常:既报 creds_in_xapikey 也报 missing_oauth_beta。
		{"x-api-key only missing beta", func(r *http.Request) {
			r.Header.Set("X-Api-Key", "x")
		}, []string{"creds_in_xapikey", "missing_oauth_beta"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := httptest.NewRequest("POST", "/v1/messages", nil)
			c.setup(r)
			got := CheckInboundBaseline(r)
			if len(got) != len(c.wantWarns) {
				t.Fatalf("warns=%v want %v", got, c.wantWarns)
			}
			for i := range got {
				if got[i] != c.wantWarns[i] {
					t.Errorf("warn[%d]=%q want %q", i, got[i], c.wantWarns[i])
				}
			}
		})
	}
}

func TestBaselineOutbound(t *testing.T) {
	if w := CheckOutboundBaseline(401); w != "upstream_auth_rejected" {
		t.Errorf("got %q", w)
	}
	if w := CheckOutboundBaseline(200); w != "" {
		t.Errorf("got %q", w)
	}
}
