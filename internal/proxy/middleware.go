package proxy

import (
	"bytes"
	"compress/gzip"
	"context"
	"io"
	"log/slog"
	"net/http"
	"path"
	"strings"

	"github.com/redcontritio/cc-mysub/internal/auth"
	"github.com/redcontritio/cc-mysub/internal/ratelimit"
)

// Authenticator looks up a device by its presented client-cert fingerprint
// (SHA-256(DER), lowercase hex).
type Authenticator interface {
	Lookup(fingerprint string) (auth.Device, bool)
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

// rateLimitExemptPrefixes 是免限流的路径前缀：匿名遥测/注册表查询走这些端点，限流它们会
// 干扰真客户端的正常带外流量（治理总纲 §0：遥测逐字节不动，不引入与直连可区分的行为）。
var rateLimitExemptPrefixes = []string{"/api/", "/mcp-registry"}

// isExempt 在规范化后的路径上做精确段匹配，堵两个绕过(P3-8):
//   - dot-segment: `/api/../v1/messages`(或 %2e%2e 解码进 Path)经 path.Clean → `/v1/messages`,
//     不再蹭 `/api/` 前缀把任意上游路径套进豁免。清洗改变了路径(含 ..、//)= 非规范输入,
//     fail-closed 不豁免(宁可多走一次 per-device 限流,不放行可疑路径)。
//   - 前缀蹭名: `/mcp-registryX` 不得蹭 `/mcp-registry`——只放行该段本身或其子树。
func isExempt(p string) bool {
	clean := path.Clean(p)
	if clean != p {
		return false
	}
	for _, pre := range rateLimitExemptPrefixes {
		base := strings.TrimRight(pre, "/")
		if clean == base || strings.HasPrefix(clean, base+"/") {
			return true
		}
	}
	return false
}

// RateLimitByDevice limits per device using its RateLimit (or defaultPerMin when
// the device has none). Must run after conditionalAuth + BaseContext 注入设备。
// 豁免路径前缀永不限流（遥测逐字节透传）。mTLS 下每个连接都携带已认证设备（证书握手保证），
// 故无匿名连接分支：匿名内层请求（无入站凭据但连接已认证）归入其证书设备的桶。
func RateLimitByDevice(defaultPerMin int) func(http.Handler) http.Handler {
	l := ratelimit.NewLimiter(nil)
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// 仅匿名(无凭据)的遥测/注册表查询豁免限流——带凭据的同路径(/api/ 等)走 per-device 桶,
			// 堵借豁免前缀绕过 per-device 限流(P3-7)。匿名遥测逐字节透传的初衷由「无凭据」保留。
			if isExempt(r.URL.Path) && !auth.HasInboundCredential(r) {
				next.ServeHTTP(w, r)
				return
			}
			// 契约:BaseContext 必为每个内层请求注入已认证设备(连接级 mTLS 证书身份)。缺注入 = 编程错,
			// 与同链 conditionalAuth 的 no_device 502 对称地 loud-fail(500),绝不静默落进共享桶
			// (死防御:生产中 BaseContext 恒注入)。哨兵按设备身份字段校验:store.reload 保证表内
			// CertSHA256 恒为规范 64 位小写 hex,非规范=未注入/构造错(P3-24)。
			dev, ok := r.Context().Value(deviceKey).(auth.Device)
			if !ok || !auth.CanonicalFingerprint(dev.CertSHA256) {
				writeJSONError(w, http.StatusInternalServerError, "no_device", "rate limit: authenticated connection missing device identity")
				return
			}
			// RateLimit 契约:>=0。负值在登记期被 enroll.Resolve fail-closed 拒绝、在热重载期被 store.reload
			// 大声归零(P3-23),故这里 dev.RateLimit 恒 >=0;0/缺省 → defaultPerMin,>0 → 该设备配额。
			// 无 per-device「不限流」哨兵:代理对每设备恒强制一个上限(设计取舍)。
			perMin := defaultPerMin
			if dev.RateLimit > 0 {
				perMin = dev.RateLimit
			}
			// 桶 key=证书指纹(设备身份),与认证/吊销/连接登记同维度(Backlog P3):label 是可复用的
			// 展示别名,remove/add 复用 label 不得继承旧桶;rotate(换指纹保 label)拿全新满桶,属
			// 身份模型下的预期语义。访问日志仍展示 label(AccessLog 取 DeviceLabel)。
			if !l.Allow(dev.CertSHA256, perMin) {
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
	Host         string // 出站上游 host(MITM 类的 api/console.anthropic.com 之一),取自 ctx connectHost(P3-7)
	Method       string
	Path         string
	Status       int
	Model        string
	InputTokens  int
	OutputTokens int
	InboundWarns []string
	OutboundWarn string
	Aborted      bool // 下游在响应体拷贝中 panic(ErrAbortHandler)=客户端中途取消流式响应(P2-1)
}

// captureCap 限定 usage 嗅探缓冲为 1 MiB;逐字节转发不受影响(只截断嗅探用的副本)。已知近似(P3-6):
// 超过此上限的流式响应——最长的生成,SSE message_delta 帧在流尾才携带最终 output_tokens——会因缓冲在
// 1 MiB 处截断而嗅探不到尾帧 → 访问日志记 OutputTokens=0(InputTokens 来自流头 message_start 仍在,
// 呈"有输入无输出")。故用量归因对最贵请求系统性少计 output,属整流缓冲 vs 边写边扫的固有近似;转发
// 正确性不受影响,仅观测面。ARCHITECTURE.md 的「访问日志…用量」处亦标注此后果。
const captureCap = 1 << 20

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

// AccessLog records device/host/status/usage/baseline for each request. sink==nil
// uses the default slog sink. Runs OUTERMOST (wrapping conditionalAuth + RateLimitByDevice)
// so short-circuit rejections — 429 from rate-limit, 502 no_device/no_upstream_token from
// conditionalAuth — also produce an AccessRecord. 被拒流量(限流风暴 / upstream token 缺失)
// 是滥用与误配的第一信号,必须可见(P2-2)。设备身份由连接级 BaseContext 注入,任何链位都能读到,
// 故旧的「innermost 才看得到注入设备」理由(token-auth 时代经 WithContext 注入的遗留)已过期。
//
// sink 的发射放进 defer:下游 forwardSwap(ReverseProxy)在响应体拷贝失败(客户端 Esc 取消 / 断网 /
// idle 掐断流)时 panic(http.ErrAbortHandler),直线 sink 会被 panic 跳过,使被取消的流式请求(已在
// 上游消耗 token)永不进日志、per-device 用量系统性少计(P2-1)。defer 里补一条标记 aborted 的记录后
// 重新 panic,保留 http.Server 的连接中止语义。
func AccessLog(sink func(AccessRecord)) func(http.Handler) http.Handler {
	if sink == nil {
		sink = defaultSink
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			warns := CheckInboundBaseline(r)
			cw := &captureWriter{ResponseWriter: w, status: http.StatusOK}
			host, _ := r.Context().Value(connectHostKey).(string)
			defer func() {
				p := recover()
				u := cw.usage()
				sink(AccessRecord{
					Device:       DeviceLabel(r.Context()),
					Host:         host,
					Method:       r.Method,
					Path:         r.URL.Path,
					Status:       cw.status,
					Model:        u.Model,
					InputTokens:  u.InputTokens,
					OutputTokens: u.OutputTokens,
					InboundWarns: warns,
					OutboundWarn: CheckOutboundBaseline(cw.status),
					Aborted:      p != nil,
				})
				if p != nil {
					panic(p) // 重新抛出 ErrAbortHandler,保留 server 的连接中止语义
				}
			}()
			next.ServeHTTP(cw, r)
		})
	}
}

func defaultSink(rec AccessRecord) {
	attrs := []any{"device", rec.Device, "method", rec.Method, "path", rec.Path, "status", rec.Status}
	if rec.Host != "" {
		attrs = append(attrs, "host", rec.Host)
	}
	if rec.Model != "" {
		attrs = append(attrs, "model", rec.Model, "input_tokens", rec.InputTokens, "output_tokens", rec.OutputTokens)
	}
	if rec.Aborted {
		attrs = append(attrs, "aborted", true)
	}
	if rec.OutboundWarn != "" {
		attrs = append(attrs, "baseline_out", rec.OutboundWarn)
	}
	if len(rec.InboundWarns) > 0 {
		attrs = append(attrs, "baseline_in", rec.InboundWarns)
	}
	// 基线偏离(入站缺 oauth beta / Authorization 结构异常 / 凭据落 x-api-key / 上游 401·403)落 WARN,
	// 与 ARCHITECTURE.md 承诺一致——按 level>=WARN 过滤日志的 operator 才看得到告警(P3-4);其余访问记录 INFO。
	if len(rec.InboundWarns) > 0 || rec.OutboundWarn != "" {
		slog.Warn("access", attrs...)
		return
	}
	slog.Info("access", attrs...)
}

func writeJSONError(w http.ResponseWriter, status int, code, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write([]byte(`{"error":{"code":"` + code + `","message":"` + msg + `"}}`))
}
