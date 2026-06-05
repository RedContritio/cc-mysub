package proxy

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/redcontritio/cc-mysub/internal/config"
)

// TestContractFullChain is the CI guardrail for the v4 forward-proxy serving
// chain (conditionalAuth → RateLimit → AccessLog → forwardSwap, as assembled by
// NewForwardProxy). A CC-style request carrying a per-device token must reach the
// mock upstream rewritten to that device's pool token, with no per-device token
// leakage and x-api-key stripped; anthropic-beta passes through untouched. The
// v4 handler forwards to the request's OWN scheme/host, so the request URL IS the
// upstream — mirror TestRewrite_Conditional: drive the chain's ServeHTTP directly
// on a recorder with the inbound URL set to the live httptest upstream.
func TestContractFullChain(t *testing.T) {
	var got http.Request
	var mu sync.Mutex
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		got = *r.Clone(r.Context())
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer up.Close()

	// 池：设备 dev-secret → upstream id "b" → 真 token sk-ant-oat01-REAL。
	store := newTestStore(t, map[string]string{"dev-secret": "b"})
	cfgUp := &config.Upstream{OAuthTokens: []config.UpstreamToken{{ID: "b", Token: "sk-ant-oat01-REAL"}}}

	// Build the serving chain exactly as NewForwardProxy does. rt=nil → default
	// retryTransport; the inbound request URL (up.URL) IS the upstream.
	chain := conditionalAuth(store, cfgUp)(
		RateLimitByDevice(120)(
			AccessLog(nil)(
				forwardSwap(nil),
			),
		),
	)

	// Legit request: per-device token + CC fingerprint headers.
	req := httptest.NewRequest("POST", up.URL+"/v1/messages", strings.NewReader(`{}`))
	req.Header.Set("Authorization", "Bearer dev-secret")
	req.Header.Set("X-Api-Key", "dev-secret")
	req.Header.Set("anthropic-beta", "oauth-2025-04-20")
	rec := httptest.NewRecorder()
	chain.ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Fatalf("status %d", rec.Code)
	}

	mu.Lock()
	defer mu.Unlock()
	if got.Header.Get("Authorization") != "Bearer sk-ant-oat01-REAL" {
		t.Errorf("auth not rewritten: %q", got.Header.Get("Authorization"))
	}
	if strings.Contains(got.Header.Get("Authorization"), "dev-secret") {
		t.Error("SECURITY: per-device token leaked upstream")
	}
	if got.Header.Get("X-Api-Key") != "" {
		t.Error("x-api-key not stripped")
	}
	if got.Header.Get("anthropic-beta") != "oauth-2025-04-20" {
		t.Error("anthropic-beta not passed through")
	}

	// Unknown token → 401, not forwarded.
	bad := httptest.NewRequest("POST", up.URL+"/v1/messages", nil)
	bad.Header.Set("Authorization", "Bearer wrong")
	rec2 := httptest.NewRecorder()
	chain.ServeHTTP(rec2, bad)
	if rec2.Code != 401 {
		t.Errorf("unknown token status = %d want 401", rec2.Code)
	}
}
