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

// TestGlobalAnonCap 契约：匿名内层请求(conditionalAuth 未注入 device)受一个与
// device 无关的全局速率 cap(globalAnonPerMin=60)；第 61 个匿名请求 -> 429。
// 已鉴权请求走 device 分支、永不触碰全局 limiter -> 不受影响。豁免遥测路径
// 即便匿名也永不 cap(字节级保真)。
//
// 该测试直接驱动 RateLimitByDevice(全局 cap 内嵌于其匿名分支)，且每次构造新的
// 中间件实例以拿到 fresh 的全局 limiter(避免跨测试污染共享 bucket)。
func TestGlobalAnonCap(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(200) })
	// 不注入 device => 匿名分支。defaultPerMin 取大值，证明 cap 来自全局而非 per-device。
	h := RateLimitByDevice(100000)(next)

	anonHit := func(path string) int {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest("POST", path, nil))
		return w.Code
	}

	// 前 60 个匿名非豁免请求通过；第 61 个 -> 429。
	for i := 0; i < 60; i++ {
		if code := anonHit("/v1/messages"); code != 200 {
			t.Fatalf("anon request %d got %d want 200 (under global cap)", i, code)
		}
	}
	if code := anonHit("/v1/messages"); code != http.StatusTooManyRequests {
		t.Fatalf("61st anon request got %d want 429 (global anon cap)", code)
	}
}

// TestGlobalAnonCap_AuthedUnaffected 契约：已鉴权请求不被全局匿名 cap 影响。
// 即便全局 anon 桶已耗尽，带 device 的请求(高 per-device 限额)照常通过。
func TestGlobalAnonCap_AuthedUnaffected(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(200) })
	h := RateLimitByDevice(100000)(next)

	// 先耗尽全局匿名桶(>60 个匿名请求)。
	for i := 0; i < 70; i++ {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest("POST", "/v1/messages", nil))
	}
	// 带 device 的请求(高限额)不受全局匿名桶影响。
	dev := auth.Device{Label: "laptop", RateLimit: 100000}
	for i := 0; i < 5; i++ {
		w := httptest.NewRecorder()
		r := httptest.NewRequest("POST", "/v1/messages", nil)
		injectDevice(dev, h).ServeHTTP(w, r)
		if w.Code != 200 {
			t.Fatalf("authenticated request %d got %d want 200 (global anon cap must not throttle authed)", i, w.Code)
		}
	}
}

// TestGlobalAnonCap_ExemptTelemetryUncapped 契约：豁免遥测路径即便匿名也永不被全局
// cap(治理总纲 §0：遥测逐字节保真)。
func TestGlobalAnonCap_ExemptTelemetryUncapped(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(200) })
	h := RateLimitByDevice(100000)(next)
	for i := 0; i < 100; i++ {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest("POST", "/api/event_logging/v2/batch", nil))
		if w.Code != 200 {
			t.Fatalf("exempt anon telemetry hit %d got %d want 200 (never capped)", i, w.Code)
		}
	}
}
