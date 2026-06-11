package proxy

import (
	"context"
	"io"
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
// A request carrying an inbound credential must reach the upstream rewritten to the
// device's pool token, with no inbound-credential leakage and x-api-key stripped;
// anthropic-beta passes through untouched. The v4 handler binds the upstream to the
// ctx-injected connectHost (handle's verified MITM CONNECT host), NOT the inbound
// request — so we capture the outbound request via a roundTripFunc and assert on it.
func TestContractFullChain(t *testing.T) {
	var got http.Request
	var mu sync.Mutex
	rt := roundTripFunc(func(r *http.Request) (*http.Response, error) {
		mu.Lock()
		got = *r.Clone(r.Context())
		mu.Unlock()
		h := make(http.Header)
		h.Set("Content-Type", "application/json")
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(`{"ok":true}`)), Header: h, Request: r}, nil
	})

	// 池：设备 upstream id "b" → 真 token sk-ant-oat01-REAL。
	cfgUp := &config.Upstream{OAuthTokens: []config.UpstreamToken{{ID: "b", Token: "sk-ant-oat01-REAL"}}}

	// Build the serving chain exactly as NewForwardProxy does (AccessLog outermost, P2-2).
	chain := AccessLog(nil)(
		conditionalAuth(cfgUp)(
			RateLimitByDevice(120)(
				forwardSwap(rt),
			),
		),
	)

	// Legit request: inbound credential + CC fingerprint headers; device + connectHost
	// injected into ctx (生产由 handle BaseContext 注入).
	dev := auth.Device{Label: "laptop", Upstream: "b", CertSHA256: fpHex('5')}
	req := httptest.NewRequest("POST", "https://api.anthropic.com/v1/messages", strings.NewReader(`{}`))
	req.Header.Set("Authorization", "Bearer placeholder")
	req.Header.Set("X-Api-Key", "placeholder")
	req.Header.Set("anthropic-beta", "oauth-2025-04-20")
	ctx := context.WithValue(req.Context(), deviceKey, dev)
	ctx = context.WithValue(ctx, connectHostKey, "api.anthropic.com")
	req = req.WithContext(ctx)
	rec := httptest.NewRecorder()
	chain.ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Fatalf("status %d", rec.Code)
	}
	// 出站绑定 ctx connectHost,不取内层请求 Host(P0 回归)。
	if got.URL.Host != "api.anthropic.com" {
		t.Errorf("SECURITY: 出站 host=%q, 应绑定 connectHost api.anthropic.com", got.URL.Host)
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
