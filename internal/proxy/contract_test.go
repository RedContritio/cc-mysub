package proxy

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/redcontritio/cc-mysub/internal/auth"
)

type oneDevice struct{ hash string }

func (o oneDevice) Lookup(tok string) (auth.Device, bool) {
	if auth.HashToken(tok) == o.hash {
		return auth.Device{Label: "laptop", RateLimit: 1000}, true
	}
	return auth.Device{}, false
}

// TestContractFullChain is the CI guardrail: a CC-style request with a
// per-device placeholder token must reach the mock upstream rewritten to the
// real token, with no per-device token leakage and x-api-key stripped.
func TestContractFullChain(t *testing.T) {
	var got http.Request
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = *r.Clone(r.Context())
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer up.Close()

	p, err := New(up.URL, "sk-ant-oat01-REAL")
	if err != nil {
		t.Fatal(err)
	}
	chain := AuthMiddleware(oneDevice{hash: auth.HashToken("dev-secret")})(
		RateLimitByDevice(1000)(
			AccessLog(nil)(p.Handler()),
		),
	)
	srv := httptest.NewServer(chain)
	defer srv.Close()

	// Legit request: per-device token + CC fingerprint headers.
	req, _ := http.NewRequest("POST", srv.URL+"/v1/messages", strings.NewReader(`{}`))
	req.Header.Set("Authorization", "Bearer dev-secret")
	req.Header.Set("X-Api-Key", "dev-secret")
	req.Header.Set("anthropic-beta", "oauth-2025-04-20")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("status %d", resp.StatusCode)
	}
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

	// Unknown token → 401.
	bad, _ := http.NewRequest("POST", srv.URL+"/v1/messages", nil)
	bad.Header.Set("Authorization", "Bearer wrong")
	r2, err := http.DefaultClient.Do(bad)
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, r2.Body)
	r2.Body.Close()
	if r2.StatusCode != 401 {
		t.Errorf("unknown token status = %d want 401", r2.StatusCode)
	}
}
