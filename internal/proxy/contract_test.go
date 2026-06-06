package proxy

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/redcontritio/cc-mysub/internal/auth"
	"github.com/redcontritio/cc-mysub/internal/config"
)

// TestContractFullChain is the CI guardrail for the v4 forward-proxy serving
// chain (conditionalAuth → RateLimit → AccessLog → forwardSwap, as assembled by
// NewForwardProxy). Device identity comes from the outer mTLS client cert, injected
// into the request ctx by handle() via BaseContext — here we simulate that injection.
// A request carrying an inbound credential must reach the mock upstream rewritten to
// the device's pool token, with no inbound-credential leakage and x-api-key stripped;
// anthropic-beta passes through untouched. The v4 handler forwards to the request's
// OWN scheme/host, so the inbound URL IS the upstream — drive the chain's ServeHTTP
// directly on a recorder with the URL set to the live httptest upstream.
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

	// 池：设备 upstream id "b" → 真 token sk-ant-oat01-REAL。
	cfgUp := &config.Upstream{OAuthTokens: []config.UpstreamToken{{ID: "b", Token: "sk-ant-oat01-REAL"}}}

	// Build the serving chain exactly as NewForwardProxy does. rt=nil → default
	// retryTransport; the inbound request URL (up.URL) IS the upstream.
	chain := conditionalAuth(cfgUp)(
		RateLimitByDevice(120)(
			AccessLog(nil)(
				forwardSwap(nil),
			),
		),
	)

	// Legit request: inbound credential + CC fingerprint headers; device injected into ctx.
	dev := auth.Device{Label: "laptop", Upstream: "b"}
	req := httptest.NewRequest("POST", up.URL+"/v1/messages", strings.NewReader(`{}`))
	req.Header.Set("Authorization", "Bearer placeholder")
	req.Header.Set("X-Api-Key", "placeholder")
	req.Header.Set("anthropic-beta", "oauth-2025-04-20")
	req = req.WithContext(context.WithValue(req.Context(), deviceKey, dev))
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
	if strings.Contains(got.Header.Get("Authorization"), "placeholder") {
		t.Error("SECURITY: inbound credential leaked upstream")
	}
	if got.Header.Get("X-Api-Key") != "" {
		t.Error("x-api-key not stripped")
	}
	if got.Header.Get("anthropic-beta") != "oauth-2025-04-20" {
		t.Error("anthropic-beta not passed through")
	}
}
