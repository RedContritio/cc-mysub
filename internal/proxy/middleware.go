package proxy

import (
	"bytes"
	"compress/gzip"
	"context"
	"io"
	"log/slog"
	"net/http"
	"strings"

	"github.com/redcontritio/cc-mysub/internal/auth"
	"github.com/redcontritio/cc-mysub/internal/ratelimit"
)

// Authenticator looks up a device by its presented token.
type Authenticator interface {
	Lookup(token string) (auth.Device, bool)
}

type ctxKey int

const deviceKey ctxKey = 0

// DeviceLabel returns the authenticated device label from the request context.
func DeviceLabel(ctx context.Context) string {
	if d, ok := ctx.Value(deviceKey).(auth.Device); ok {
		return d.Label
	}
	return ""
}

// AuthMiddleware validates the per-device token (Bearer or x-api-key) and
// injects the resolved device into the request context. Unknown tokens get 401.
func AuthMiddleware(a Authenticator) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			tok := auth.ExtractToken(r)
			dev, ok := a.Lookup(tok)
			if tok == "" || !ok {
				writeJSONError(w, http.StatusUnauthorized, "unauthorized", "invalid token")
				return
			}
			ctx := context.WithValue(r.Context(), deviceKey, dev)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// rateLimitExemptPrefixes 是免限流的路径前缀：匿名遥测/注册表查询走这些端点，限流它们会
// 干扰真客户端的正常带外流量（治理总纲 §0：遥测逐字节不动，不引入与直连可区分的行为）。
var rateLimitExemptPrefixes = []string{"/api/", "/mcp-registry"}

func isExempt(path string) bool {
	for _, p := range rateLimitExemptPrefixes {
		if strings.HasPrefix(path, p) {
			return true
		}
	}
	return false
}

// globalAnonPerMin is a coarse, device-INDEPENDENT cap on anonymous inner
// requests (those conditionalAuth lets through with no device). It bounds the
// blast radius of a leaked DEVICE_TOKEN, which otherwise opens an
// un-rate-limited anonymous relay through the channel (spec §3.7). It must NOT
// throttle authenticated requests (they take the device-keyed branch below) nor
// exempt telemetry paths (byte-faithful passthrough).
const globalAnonPerMin = 60

// newAnonLimiter constructs a fresh Limiter for the global anonymous bucket.
// Extracted so tests can substitute a fresh instance per test run without
// reaching into the ratelimit package directly.
func newAnonLimiter() *ratelimit.Limiter { return ratelimit.NewLimiter(nil) }

// globalAnonLimiter is the single shared bucket for all anonymous inner
// requests. Keyed by a fixed sentinel so every anon request draws from one
// global quota regardless of source.
var globalAnonLimiter = newAnonLimiter()

const globalAnonKey = "" // device-independent: one global anon bucket

// RateLimitByDevice limits per device using its RateLimit (or defaultPerMin
// when the device has none). Must run after conditionalAuth. Exempt path
// prefixes are never limited (telemetry passthrough stays byte-faithful).
// Anonymous non-exempt requests (no authed device) are bounded by a coarse
// device-independent global cap (globalAnonPerMin) instead — see §3.7.
func RateLimitByDevice(defaultPerMin int) func(http.Handler) http.Handler {
	l := ratelimit.NewLimiter(nil)
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if isExempt(r.URL.Path) {
				next.ServeHTTP(w, r) // 豁免遥测：永不限流(per-device 或全局)
				return
			}
			dev, ok := r.Context().Value(deviceKey).(auth.Device)
			if !ok || dev.Label == "" {
				// 匿名内层请求：受与 device 无关的粗粒度全局 cap。
				if !globalAnonLimiter.Allow(globalAnonKey, globalAnonPerMin) {
					writeJSONError(w, http.StatusTooManyRequests, "rate_limited", "too many requests")
					return
				}
				next.ServeHTTP(w, r)
				return
			}
			perMin := defaultPerMin
			if dev.RateLimit > 0 {
				perMin = dev.RateLimit
			}
			if !l.Allow(dev.Label, perMin) {
				writeJSONError(w, http.StatusTooManyRequests, "rate_limited", "too many requests")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// NOTE: globalAnonLimiter is package-shared across all RateLimitByDevice
// instances (the global cap is intentionally process-wide). Tests that exercise
// the anon non-exempt branch must save/restore globalAnonLimiter via
// t.Cleanup so they are hermetic regardless of execution order or -count.
// newAnonLimiter() is provided for exactly this purpose.

// AccessRecord is one structured access-log entry.
type AccessRecord struct {
	Device       string
	Method       string
	Path         string
	Status       int
	Model        string
	InputTokens  int
	OutputTokens int
	InboundWarns []string
	OutboundWarn string
}

const captureCap = 1 << 20 // 1 MiB cap for usage sniffing buffer

// captureWriter tees the response into a bounded buffer for usage sniffing
// while forwarding bytes through unbuffered (preserving SSE streaming).
type captureWriter struct {
	http.ResponseWriter
	status  int
	buf     bytes.Buffer
	isSSE   bool
	gzipEnc bool
	capped  bool
	wroteHd bool
}

func (c *captureWriter) WriteHeader(code int) {
	c.status = code
	c.isSSE = strings.Contains(c.Header().Get("Content-Type"), "text/event-stream")
	c.gzipEnc = strings.Contains(c.Header().Get("Content-Encoding"), "gzip")
	c.wroteHd = true
	c.ResponseWriter.WriteHeader(code)
}

func (c *captureWriter) Write(p []byte) (int, error) {
	if !c.wroteHd {
		c.WriteHeader(http.StatusOK)
	}
	if !c.capped {
		c.buf.Write(p)
		if c.buf.Len() > captureCap {
			c.capped = true
		}
	}
	return c.ResponseWriter.Write(p)
}

func (c *captureWriter) Flush() {
	if f, ok := c.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// ReadFrom forces ReverseProxy's io.Copy through Write so the buffer is teed.
// Without this, captureWriter would inherit the underlying ResponseWriter's
// ReadFrom (via embedding) and io.Copy would bypass Write, losing usage data.
func (c *captureWriter) ReadFrom(src io.Reader) (int64, error) {
	buf := make([]byte, 32*1024)
	var total int64
	for {
		n, rerr := src.Read(buf)
		if n > 0 {
			if _, werr := c.Write(buf[:n]); werr != nil {
				return total, werr
			}
			total += int64(n)
		}
		if rerr != nil {
			if rerr == io.EOF {
				return total, nil
			}
			return total, rerr
		}
	}
}

// Unwrap lets http.ResponseController reach the underlying writer.
func (c *captureWriter) Unwrap() http.ResponseWriter { return c.ResponseWriter }

// usage sniffs model + token counts from the buffered response, transparently
// gunzipping first when the upstream used Content-Encoding: gzip (Claude's API
// does when the client sends Accept-Encoding: gzip, which real CC always does).
func (c *captureWriter) usage() Usage {
	data := c.buf.Bytes()
	if c.gzipEnc {
		if zr, err := gzip.NewReader(bytes.NewReader(data)); err == nil {
			if dec, _ := io.ReadAll(zr); len(dec) > 0 {
				data = dec // partial decode tolerated when the buffer was capped
			}
		}
	}
	if c.isSSE {
		return SniffUsageSSE(data)
	}
	return SniffUsageJSON(data)
}

// AccessLog records device/status/usage/baseline for each request.
// sink==nil uses the default slog sink. Runs innermost (after auth) so it
// sees the injected device and the upstream status.
func AccessLog(sink func(AccessRecord)) func(http.Handler) http.Handler {
	if sink == nil {
		sink = defaultSink
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			warns := CheckInboundBaseline(r)
			cw := &captureWriter{ResponseWriter: w, status: http.StatusOK}
			next.ServeHTTP(cw, r)
			u := cw.usage()
			sink(AccessRecord{
				Device:       DeviceLabel(r.Context()),
				Method:       r.Method,
				Path:         r.URL.Path,
				Status:       cw.status,
				Model:        u.Model,
				InputTokens:  u.InputTokens,
				OutputTokens: u.OutputTokens,
				InboundWarns: warns,
				OutboundWarn: CheckOutboundBaseline(cw.status),
			})
		})
	}
}

func defaultSink(rec AccessRecord) {
	attrs := []any{"device", rec.Device, "method", rec.Method, "path", rec.Path, "status", rec.Status}
	if rec.Model != "" {
		attrs = append(attrs, "model", rec.Model, "input_tokens", rec.InputTokens, "output_tokens", rec.OutputTokens)
	}
	if rec.OutboundWarn != "" {
		attrs = append(attrs, "baseline_out", rec.OutboundWarn)
	}
	if len(rec.InboundWarns) > 0 {
		attrs = append(attrs, "baseline_in", rec.InboundWarns)
	}
	slog.Info("access", attrs...)
}

func writeJSONError(w http.ResponseWriter, status int, code, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write([]byte(`{"error":{"code":"` + code + `","message":"` + msg + `"}}`))
}
