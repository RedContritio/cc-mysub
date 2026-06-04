package proxy

import (
	"bytes"
	"context"
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
// injects the resolved device into the request context. Unknown tokens → 401.
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

// RateLimitByDevice limits per device using its RateLimit (or defaultPerMin
// when the device has none). Must run after AuthMiddleware.
func RateLimitByDevice(defaultPerMin int) func(http.Handler) http.Handler {
	l := ratelimit.NewLimiter(nil)
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			dev, _ := r.Context().Value(deviceKey).(auth.Device)
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
	capped  bool
	wroteHd bool
}

func (c *captureWriter) WriteHeader(code int) {
	c.status = code
	c.isSSE = strings.Contains(c.Header().Get("Content-Type"), "text/event-stream")
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

func (c *captureWriter) usage() Usage {
	if c.isSSE {
		return SniffUsageSSE(c.buf.Bytes())
	}
	return SniffUsageJSON(c.buf.Bytes())
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
