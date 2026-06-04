package proxy

import (
	"bytes"
	"compress/gzip"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/redcontritio/cc-mysub/internal/auth"
)

type fakeAuth struct {
	ok    bool
	limit int
}

func (f fakeAuth) Lookup(token string) (auth.Device, bool) {
	if f.ok {
		return auth.Device{Label: "test", RateLimit: f.limit}, true
	}
	return auth.Device{}, false
}

func TestAuthMiddlewareRejectsUnknown(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(200) })
	h := AuthMiddleware(fakeAuth{ok: false})(next)
	r := httptest.NewRequest("POST", "/v1/messages", nil)
	r.Header.Set("Authorization", "Bearer nope")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("code = %d want 401", w.Code)
	}
}

func TestAuthMiddlewarePassesKnown(t *testing.T) {
	var sawLabel string
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sawLabel = DeviceLabel(r.Context())
		w.WriteHeader(200)
	})
	h := AuthMiddleware(fakeAuth{ok: true})(next)
	r := httptest.NewRequest("POST", "/v1/messages", nil)
	r.Header.Set("Authorization", "Bearer good")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 200 || sawLabel != "test" {
		t.Errorf("code=%d label=%q", w.Code, sawLabel)
	}
}

func TestRateLimitByDevice429(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(200) })
	h := AuthMiddleware(fakeAuth{ok: true, limit: 1})(RateLimitByDevice(1)(next))
	mk := func() int {
		w := httptest.NewRecorder()
		r := httptest.NewRequest("POST", "/v1/messages", nil)
		r.Header.Set("Authorization", "Bearer good")
		h.ServeHTTP(w, r)
		return w.Code
	}
	if mk() != 200 {
		t.Fatal("first should pass")
	}
	if mk() != http.StatusTooManyRequests {
		t.Error("second should be 429")
	}
}

func TestAccessLogCapturesStatusAndUsage(t *testing.T) {
	var got AccessRecord
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(200)
		_, _ = w.Write([]byte(`{"model":"claude-opus","usage":{"input_tokens":10,"output_tokens":5}}`))
	})
	h := AccessLog(func(rec AccessRecord) { got = rec })(next)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("POST", "/v1/messages", nil))
	if got.Status != 200 {
		t.Errorf("status = %d", got.Status)
	}
	if got.Model != "claude-opus" || got.InputTokens != 10 || got.OutputTokens != 5 {
		t.Errorf("usage not captured: %+v", got)
	}
}

func TestAccessLogOutboundWarn(t *testing.T) {
	var got AccessRecord
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(401) })
	h := AccessLog(func(rec AccessRecord) { got = rec })(next)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("POST", "/v1/messages", nil))
	if got.OutboundWarn != "upstream_auth_rejected" {
		t.Errorf("outbound warn = %q", got.OutboundWarn)
	}
}

func TestCaptureWriterReadFromTees(t *testing.T) {
	rec := httptest.NewRecorder()
	cw := &captureWriter{ResponseWriter: rec, status: 200}
	cw.Header().Set("Content-Type", "application/json")
	cw.WriteHeader(200)
	body := `{"model":"m","usage":{"input_tokens":3,"output_tokens":4}}`
	if _, err := cw.ReadFrom(strings.NewReader(body)); err != nil {
		t.Fatal(err)
	}
	u := cw.usage()
	if u.Model != "m" || u.InputTokens != 3 || u.OutputTokens != 4 {
		t.Errorf("usage via ReadFrom not captured: %+v", u)
	}
	if rec.Body.String() != body {
		t.Errorf("body not forwarded: %q", rec.Body.String())
	}
}

func TestCaptureWriterDecodesGzip(t *testing.T) {
	rec := httptest.NewRecorder()
	cw := &captureWriter{ResponseWriter: rec, status: 200}
	cw.Header().Set("Content-Type", "application/json")
	cw.Header().Set("Content-Encoding", "gzip")
	cw.WriteHeader(200)
	var gz bytes.Buffer
	zw := gzip.NewWriter(&gz)
	_, _ = zw.Write([]byte(`{"model":"gz","usage":{"input_tokens":7,"output_tokens":8}}`))
	_ = zw.Close()
	_, _ = cw.Write(gz.Bytes())
	u := cw.usage()
	if u.Model != "gz" || u.InputTokens != 7 || u.OutputTokens != 8 {
		t.Errorf("gzip usage not decoded: %+v", u)
	}
}
