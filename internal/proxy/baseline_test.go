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
