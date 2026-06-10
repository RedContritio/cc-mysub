package proxy

import (
	"bytes"
	"compress/gzip"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/redcontritio/cc-mysub/internal/auth"
)

func TestRateLimitByDevice429(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(200) })
	dev := auth.Device{Label: "test", RateLimit: 1}
	h := injectDevice(dev, RateLimitByDevice(1)(next))
	mk := func() int {
		w := httptest.NewRecorder()
		r := httptest.NewRequest("POST", "/v1/messages", nil)
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

// injectDevice 把已认证设备塞进 ctx，模拟 conditionalAuth 的前置注入，使 RateLimit 能读到设备。
func injectDevice(dev auth.Device, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), deviceKey, dev)))
	})
}

// TestRateLimit_ExemptsTelemetry 验证 V7：免限流路径前缀（/api/）即使同一设备高频命中也永不 429，
// 而非豁免路径（/v1/messages）超出该设备限额后照常 429。匿名遥测的限流豁免由 dev.Label=="" 分支
// 单独保证（见 TestRewrite_Conditional 的匿名透传 + 此处的 isExempt 路径豁免）。
func TestRateLimit_ExemptsTelemetry(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(200) })
	dev := auth.Device{Label: "laptop", RateLimit: 1}
	h := injectDevice(dev, RateLimitByDevice(1)(next))

	hit := func(path string) int {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest("POST", path, nil))
		return w.Code
	}

	// 豁免遥测端点：远超 limit=1 的连打仍永不 429
	for i := 0; i < 20; i++ {
		if code := hit("/api/event_logging/v2/batch"); code != 200 {
			t.Fatalf("telemetry hit %d got %d want 200 (exempt path must never rate-limit)", i, code)
		}
	}

	// 非豁免推理端点：首发过、再发被限
	if code := hit("/v1/messages"); code != 200 {
		t.Fatalf("first /v1/messages got %d want 200", code)
	}
	if code := hit("/v1/messages"); code != http.StatusTooManyRequests {
		t.Errorf("second /v1/messages got %d want 429", code)
	}
}

// TestRateLimit_ExemptOnlyAnonymous 验证 P3-7:豁免路径只对匿名(无凭据)请求豁免;带凭据的同路径
// 走 per-device 限流,堵借 /api/ 前缀绕过。
func TestRateLimit_ExemptOnlyAnonymous(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(200) })
	dev := auth.Device{Label: "laptop", RateLimit: 1}
	h := injectDevice(dev, RateLimitByDevice(1)(next))

	anon := func() int {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest("POST", "/api/event_logging/v2/batch", nil))
		return w.Code
	}
	withCred := func() int {
		w := httptest.NewRecorder()
		r := httptest.NewRequest("POST", "/api/event_logging/v2/batch", nil)
		r.Header.Set("Authorization", "Bearer placeholder")
		h.ServeHTTP(w, r)
		return w.Code
	}

	// 匿名豁免:远超 limit=1 的连打仍永不 429(逐字节透传初衷保留)
	for i := 0; i < 10; i++ {
		if code := anon(); code != 200 {
			t.Fatalf("anon /api hit %d got %d want 200 (anonymous exempt)", i, code)
		}
	}
	// 带凭据:同豁免路径走 per-device 桶,首发过、再发被限(不得借豁免前缀绕过)
	if code := withCred(); code != 200 {
		t.Fatalf("first credentialed /api got %d want 200", code)
	}
	if code := withCred(); code != http.StatusTooManyRequests {
		t.Errorf("second credentialed /api got %d want 429 (must not bypass via exempt prefix)", code)
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
