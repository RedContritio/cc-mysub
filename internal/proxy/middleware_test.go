package proxy

import (
	"bytes"
	"compress/gzip"
	"context"
	"log/slog"
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
// 而非豁免路径（/v1/messages）超出该设备限额后照常 429。匿名遥测的限流豁免由
// isExempt(path) && !auth.HasInboundCredential(r) 保证（P3-7），与 dev.Label 无关。
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

// TestRateLimitByDevice_MissingDevice500 验证 P3-24:契约违规(ctx 无注入设备/空 Label)在 RateLimitByDevice
// 与同链 conditionalAuth 的 no_device 对称地 loud-fail(500),不静默落进 label=="" 共享桶、不调用下游。
func TestRateLimitByDevice_MissingDevice500(t *testing.T) {
	cases := []struct {
		name string
		ctx  func(*http.Request) *http.Request
	}{
		{"no device in ctx", func(r *http.Request) *http.Request { return r }},
		{"empty-label device", func(r *http.Request) *http.Request {
			return r.WithContext(context.WithValue(r.Context(), deviceKey, auth.Device{Label: ""}))
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			called := false
			next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { called = true; w.WriteHeader(200) })
			h := RateLimitByDevice(120)(next)
			w := httptest.NewRecorder()
			// 非豁免路径 + 带凭据,确保不走匿名豁免分支,直抵设备读取。
			r := httptest.NewRequest("POST", "/v1/messages", nil)
			r.Header.Set("Authorization", "Bearer x")
			h.ServeHTTP(w, c.ctx(r))
			if w.Code != http.StatusInternalServerError {
				t.Errorf("missing device must 500, got %d", w.Code)
			}
			if !strings.Contains(w.Body.String(), "no_device") {
				t.Errorf("body should carry no_device code: %q", w.Body.String())
			}
			if called {
				t.Error("downstream must not be called on contract violation")
			}
		})
	}
}

// TestIsExempt 验证 P3-8:豁免判定在规范化后做精确段匹配——dot-segment 与前缀蹭名都不豁免。
func TestIsExempt(t *testing.T) {
	cases := []struct {
		path string
		want bool
	}{
		{"/api/event_logging/v2/batch", true},
		{"/mcp-registry", true},
		{"/mcp-registry/servers", true},
		{"/v1/messages", false},
		{"/mcp-registryX", false},       // 前缀蹭名不豁免
		{"/api/../v1/messages", false},  // dot-segment 清洗后 → /v1/messages,不豁免
		{"/api//../v1/messages", false}, // 含 // + .. 的非规范路径不豁免
		{"/apiX/foo", false},            // /api 段边界
	}
	for _, c := range cases {
		if got := isExempt(c.path); got != c.want {
			t.Errorf("isExempt(%q)=%v want %v", c.path, got, c.want)
		}
	}
}

// TestRateLimit_DotSegmentNotExempt 验证 P3-8 的限流后果:dot-segment 匿名请求清洗后落 /v1/messages,
// 走 per-device 桶被限流(不再借 /api/ 前缀绕过豁免)。
func TestRateLimit_DotSegmentNotExempt(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(200) })
	dev := auth.Device{Label: "laptop", RateLimit: 1}
	h := injectDevice(dev, RateLimitByDevice(1)(next))
	hit := func() int {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest("POST", "/api/../v1/messages", nil))
		return w.Code
	}
	if hit() != 200 {
		t.Fatal("first dot-segment request should pass")
	}
	if hit() != http.StatusTooManyRequests {
		t.Error("second dot-segment request must be 429 (not exempt — bypass closed)")
	}
}

// TestAccessLog_AbortedStreamStillLogs 验证 P2-1:下游 panic(http.ErrAbortHandler)(客户端中途取消流式响应)
// 时,AccessLog 仍发一条标记 aborted 的记录,且重新抛出 panic 保留 server 的连接中止语义。
func TestAccessLog_AbortedStreamStillLogs(t *testing.T) {
	var got AccessRecord
	var sunk bool
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(200)
		_, _ = w.Write([]byte("event: message_start\ndata: {\"message\":{\"model\":\"m\",\"usage\":{\"input_tokens\":9}}}\n\n"))
		panic(http.ErrAbortHandler)
	})
	h := AccessLog(func(rec AccessRecord) { got = rec; sunk = true })(next)
	defer func() {
		p := recover()
		if p != http.ErrAbortHandler {
			t.Fatalf("AccessLog must re-panic ErrAbortHandler, got %v", p)
		}
		if !sunk {
			t.Fatal("sink not called on aborted stream (record lost)")
		}
		if !got.Aborted {
			t.Error("record not marked aborted")
		}
		if got.Status != 200 {
			t.Errorf("status=%d want 200", got.Status)
		}
		if got.InputTokens != 9 {
			t.Errorf("head usage lost: input=%d want 9", got.InputTokens)
		}
	}()
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("POST", "/v1/messages", nil))
	t.Fatal("handler did not panic")
}

// TestAccessLog_RecordsUpstreamHost 验证 P3-7:AccessRecord 携带出站上游 host(取自 ctx connectHost),
// 使 api 与 console.anthropic.com 的同名路径记录可区分。
func TestAccessLog_RecordsUpstreamHost(t *testing.T) {
	for _, host := range []string{"api.anthropic.com", "console.anthropic.com"} {
		var got AccessRecord
		next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(200) })
		h := AccessLog(func(rec AccessRecord) { got = rec })(next)
		r := httptest.NewRequest("POST", "/api/foo", nil)
		r = r.WithContext(context.WithValue(r.Context(), connectHostKey, host))
		h.ServeHTTP(httptest.NewRecorder(), r)
		if got.Host != host {
			t.Errorf("AccessRecord.Host=%q want %q", got.Host, host)
		}
	}
}

// capturingHandler 记录每条 slog.Record 的 level,供 defaultSink 级别断言。
type capturingHandler struct{ records []slog.Record }

func (h *capturingHandler) Enabled(context.Context, slog.Level) bool { return true }
func (h *capturingHandler) Handle(_ context.Context, r slog.Record) error {
	h.records = append(h.records, r)
	return nil
}
func (h *capturingHandler) WithAttrs([]slog.Attr) slog.Handler { return h }
func (h *capturingHandler) WithGroup(string) slog.Handler      { return h }

// TestDefaultSink_BaselineWarnsAtWarnLevel 验证 P3-4:含基线告警(入站/出站)的记录落 WARN,普通访问落 INFO,
// 与 ARCHITECTURE.md 承诺一致。
func TestDefaultSink_BaselineWarnsAtWarnLevel(t *testing.T) {
	h := &capturingHandler{}
	old := slog.Default()
	slog.SetDefault(slog.New(h))
	defer slog.SetDefault(old)

	defaultSink(AccessRecord{Device: "d", Status: 200, InboundWarns: []string{"missing_oauth_beta"}})
	defaultSink(AccessRecord{Device: "d", Status: 401, OutboundWarn: "upstream_auth_rejected"})
	defaultSink(AccessRecord{Device: "d", Status: 200}) // clean → INFO

	if len(h.records) != 3 {
		t.Fatalf("got %d records want 3", len(h.records))
	}
	if h.records[0].Level != slog.LevelWarn {
		t.Errorf("inbound baseline warn level=%v want WARN", h.records[0].Level)
	}
	if h.records[1].Level != slog.LevelWarn {
		t.Errorf("outbound baseline warn level=%v want WARN", h.records[1].Level)
	}
	if h.records[2].Level != slog.LevelInfo {
		t.Errorf("clean access level=%v want INFO", h.records[2].Level)
	}
}

// TestCaptureWriter_OversizeStreamDropsTailUsage 钉住 P3-6 的已知近似:超过 captureCap(1 MiB)的流式响应
// 因缓冲截断丢失流尾 message_delta 的 output_tokens(记 0),流头 input_tokens 仍在——观测面的固有近似,
// 转发不受影响。
func TestCaptureWriter_OversizeStreamDropsTailUsage(t *testing.T) {
	rec := httptest.NewRecorder()
	cw := &captureWriter{ResponseWriter: rec, status: 200}
	cw.Header().Set("Content-Type", "text/event-stream")
	cw.WriteHeader(200)
	// 流头 message_start(model + input)在 cap 内。
	_, _ = cw.Write([]byte("event: message_start\ndata: {\"message\":{\"model\":\"claude\",\"usage\":{\"input_tokens\":11,\"output_tokens\":0}}}\n\n"))
	// >1 MiB 填充把缓冲推过 captureCap。
	filler := append([]byte("data: "), bytes.Repeat([]byte("x"), captureCap+4096)...)
	_, _ = cw.Write(filler)
	_, _ = cw.Write([]byte("\n\n"))
	// 流尾 message_delta(最终 output_tokens)落在 cap 之外,被丢弃。
	_, _ = cw.Write([]byte("event: message_delta\ndata: {\"usage\":{\"output_tokens\":4242}}\n\n"))
	if !cw.capped {
		t.Fatal("buffer should be capped past 1 MiB")
	}
	u := cw.usage()
	if u.OutputTokens != 0 {
		t.Errorf("known approximation: capped stream should drop tail output_tokens, got %d", u.OutputTokens)
	}
	if u.InputTokens != 11 {
		t.Errorf("head input_tokens must survive cap, got %d", u.InputTokens)
	}
}
