package proxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"strings"
	"sync"
	"time"

	"github.com/redcontritio/cc-mysub/internal/auth"
	"github.com/redcontritio/cc-mysub/internal/config"
	"github.com/redcontritio/cc-mysub/internal/connect"
	"github.com/redcontritio/cc-mysub/internal/mitm"
)

type rewriteCtxKey int

const realTokenKey rewriteCtxKey = 0

// conditionalAuth 是前置认证中间件（凭据存在性分流，见 spec §4/§5.3）。它必须置于
// RateLimit/AccessLog 之前：handler 经 r.WithContext 注入的 ctx 只向下游传播，注入到内层
// 的 device/realToken 无法被外层 wrapper（RateLimit/AccessLog）看到。故把认证从转发 handler
// 拆出作为前置层，使后续中间件能读到 device。
//   - 入站无凭据（匿名遥测）→ 放行，不注入 device/realToken（匿名透传）
//   - 入站 per-device token 命中 → real=up.PickToken(d.Upstream)；real==""→502；
//     否则把 device(deviceKey) 与 realToken(realTokenKey) 注入 ctx 后放行
//   - 入站有 token 但未命中 → 401，不放行（认证门）
func conditionalAuth(a Authenticator, up *config.Upstream) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			tok := auth.ExtractToken(r)
			if tok == "" {
				next.ServeHTTP(w, r) // 匿名透传
				return
			}
			d, ok := a.Lookup(tok)
			if !ok {
				writeJSONError(w, http.StatusUnauthorized, "unauthorized", "invalid token")
				return
			}
			real := up.PickToken(d.Upstream)
			if real == "" {
				writeJSONError(w, http.StatusBadGateway, "no_upstream_token", "no upstream token for device")
				return
			}
			ctx := context.WithValue(r.Context(), deviceKey, d)
			ctx = context.WithValue(ctx, realTokenKey, real)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// forwardSwap 是转发 handler（换 token + 逐字节透传）：
//   - 上游 = 入站请求的 scheme/host（per-connection CONNECT 目标；scheme 缺省 https）
//   - 恒删出站 X-Api-Key
//   - ctx 有 realToken（命中设备，由 conditionalAuth 注入）→ 出站 Authorization 换成 Bearer real
//   - ctx 无 realToken（匿名）→ 不注入 cc-mysub 凭据，对入站 Authorization 逐字节透传——
//     保字节级不可区分于直连（治理总纲 §0）。真匿名遥测本就无 Authorization，此处为 no-op。
//
// rt 为 nil 时用默认 retryTransport（T7 注入自定义 transport 以重定向 dial / 信任假上游 CA）。
func forwardSwap(rt http.RoundTripper) http.Handler {
	if rt == nil {
		rt = &retryTransport{base: http.DefaultTransport, delays: []time.Duration{0, 200 * time.Millisecond, 600 * time.Millisecond}}
	}
	rp := &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			scheme := pr.In.URL.Scheme
			if scheme == "" {
				scheme = "https"
			}
			host := pr.In.URL.Host
			if host == "" {
				host = pr.In.Host
			}
			pr.Out.URL.Scheme = scheme
			pr.Out.URL.Host = host
			pr.Out.Host = "" // Host 头取 URL.Host
			pr.Out.Header.Del("X-Api-Key")
			if real, _ := pr.In.Context().Value(realTokenKey).(string); real != "" {
				pr.Out.Header.Set("Authorization", "Bearer "+real)
			}
		},
		Transport: rt,
		ErrorHandler: func(w http.ResponseWriter, _ *http.Request, _ error) {
			writeJSONError(w, http.StatusBadGateway, "upstream_error", "upstream request failed")
		},
	}
	return rp
}

// newRewriteHandler = 条件认证 + 换 token 转发（不含限流/访问日志）。保留此组合供单测
// （TestRewrite_*）直接覆盖认证分流 + 换 token 契约。生产 serving chain 见 NewForwardProxy。
func newRewriteHandler(a Authenticator, up *config.Upstream, rt http.RoundTripper) http.Handler {
	return conditionalAuth(a, up)(forwardSwap(rt))
}

// certMinter is the subset of *mitm.Minter that handle() needs: synthesize a
// leaf cert for a host. A package-local interface (not the concrete *mitm.Minter)
// lets forward_test inject a spy that records CertFor(host) calls, so the
// '407/400 path never mints a leaf for the CONNECT host' contract is observable.
// *mitm.Minter satisfies this unchanged.
type certMinter interface {
	CertFor(host string) (*tls.Certificate, error)
}

// ForwardProxy 是 CONNECT forward-proxy。整个 device↔cc-mysub 跳被外层 TLS 包裹
// （外层呈现 cc-mysub 自身身份证书 serverName，使 CONNECT 目标 host 不以明文上线）；
// 在外层 TLS 内读 CONNECT 目标、按 allowlist 拒非法 host（纵深防御），回 200 后再按 host
// 现签证书跑内层 MITM TLS（嵌套 TLS），把解密后的 HTTP 请求经 rewrite handler 转发到真目标 host。
type ForwardProxy struct {
	minter     certMinter      // 现签外层身份证书 + 内层 MITM 叶证书（spy 可注入）
	handler    http.Handler    // newRewriteHandler 的结果，逐请求按 req.Host 决定上游
	auth       Authenticator   // 信道层准入：CONNECT 头 Proxy-Authorization 校验（spec §3.2）
	allow      map[string]bool // 允许 MITM 的 CONNECT 目标 host（纵深防御，拒其余）
	serverName string          // 外层 TLS 身份（cc-mysub public_host），现签证书的 CN/SAN
	sema       chan struct{}   // 全局并发 self-cap：acquire 在 spawn 前、release 在 handle defer（§3.4）
	wg         sync.WaitGroup  // 跟踪在途 handle goroutine，Serve 退出前等待其收尾
}

// handshakeReadTimeout 限定外层 TLS 握手 + CONNECT 行/头读取的总时长，防 slowloris 把
// handle goroutine + FD 永久占住（写出 200 后清除，交内层 http.Server 的 ReadHeaderTimeout 接管）。
const handshakeReadTimeout = 15 * time.Second

// maxConnectHeaderBytes 限定 pre-200 阶段（CONNECT 行 + 全部 CONNECT 头）的累计字节数，
// 防超长头打爆 handle goroutine 内存。手动累加器，不用 io.LimitReader——后者会与 bufio 预读
// 互相误计并破坏 br.Buffered()/prefixConn 的流水线回放（spec §3.2 第 1 点）。
const maxConnectHeaderBytes = 8192

// NewForwardProxy 装配 forward-proxy。upstream 为到真目标的 transport（含 dial + TLS 验证）；
// nil 时 forwardSwap 用默认 retryTransport（生产：真 DNS + 验真证书）。
// allow 为允许 MITM 的 CONNECT 目标 host 列表；serverName 为外层 TLS 呈现的 cc-mysub 身份。
// maxInFlight 为全局并发上限（>0 强制要求，<=0 panic；饱和时 shed 新连接）。
//
// serving chain：conditionalAuth（前置，注入 device/realToken）→ RateLimitByDevice（按设备限流，
// 匿名遥测/豁免路径放行）→ AccessLog（记录设备/状态/用量）→ forwardSwap（换 token 转发）。
// 认证置于最外层，使 RateLimit/AccessLog 能读到注入的 device（ctx 仅向下游传播）。
func NewForwardProxy(m *mitm.Minter, a Authenticator, up *config.Upstream, upstream http.RoundTripper, allow []string, serverName string, maxInFlight int) *ForwardProxy {
	if maxInFlight <= 0 {
		panic("proxy: NewForwardProxy requires maxInFlight > 0")
	}
	allowSet := make(map[string]bool, len(allow))
	for _, h := range allow {
		allowSet[h] = true
	}
	handler := conditionalAuth(a, up)(
		RateLimitByDevice(120)(
			AccessLog(nil)(
				forwardSwap(upstream),
			),
		),
	)
	return &ForwardProxy{
		minter:     m,
		handler:    handler,
		auth:       a,
		allow:      allowSet,
		serverName: serverName,
		sema:       make(chan struct{}, maxInFlight),
	}
}

// Serve 接受连接并逐个 MITM 处理，直到 ln 关闭。
// 并发上限由 fp.sema 控制：获取 token 后才派发 goroutine；饱和时立即关闭连接（shed）。
func (fp *ForwardProxy) Serve(ln net.Listener) error {
	for {
		conn, err := ln.Accept()
		if err != nil {
			fp.wg.Wait() // 等在途连接收尾，避免孤儿 goroutine 在调用方释放资源后访问
			return err
		}
		select {
		case fp.sema <- struct{}{}:
		default:
			conn.Close() // shed: semaphore saturated
			continue
		}
		fp.wg.Add(1)
		go fp.handle(conn)
	}
}

func (fp *ForwardProxy) handle(rawConn net.Conn) {
	defer fp.wg.Done()
	defer func() { <-fp.sema }()
	// 外层 TLS：呈现 cc-mysub 自身身份证书（serverName），终结 device↔cc-mysub 跳。
	// 此后所有读写都走 outer（Close(outer) 即 Close(rawConn)）。
	outer := tls.Server(rawConn, &tls.Config{
		GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
			return fp.minter.CertFor(fp.serverName)
		},
	})
	// slowloris 防护：外层握手 + CONNECT 读取阶段设读 deadline；写出 200 后清除。
	_ = outer.SetReadDeadline(time.Now().Add(handshakeReadTimeout))
	br := bufio.NewReader(outer)
	// 手动字节累加器(pre-200 cap，§3.2 第 1 点):CONNECT 行 + 每个头行的长度累加,
	// 超 maxConnectHeaderBytes → 400 + Close。不用 io.LimitReader 包 conn——会被 bufio
	// 预读误计并破坏 br.Buffered()/prefixConn 回放。
	line, err := br.ReadString('\n')
	if err != nil {
		outer.Close()
		return
	}
	byteCount := len(line)
	if byteCount > maxConnectHeaderBytes {
		_, _ = outer.Write([]byte("HTTP/1.1 400 Bad Request\r\n\r\n"))
		outer.Close()
		return
	}
	host, ok := connect.ParseConnect(line)
	if !ok {
		// 非法/非 CONNECT 请求行 = 客户端错误（区别于 allowlist 策略拒绝的 403）
		_, _ = outer.Write([]byte("HTTP/1.1 400 Bad Request\r\n\r\n"))
		outer.Close()
		return
	}
	// 信道层准入(§3.2):读完 CONNECT 头到空行,精确计数 Proxy-Authorization。
	//   - 行首 SP/TAB(obs-fold 续行)→ 407(拒头折叠走私)
	//   - 每行调 connect.ParseProxyAuthorization,name 命中即计数
	//   - count != 1(0 或 >1,禁 last-wins)→ 407
	//   - count == 1 且 ok==false → 407
	// 校验置于 allowlist 之前:tokenless 一律 407、不泄露 allowlist 成员(消 host oracle)。
	var token string
	paCount := 0
	channelFail := false
	for {
		h, err := br.ReadString('\n')
		if err != nil {
			outer.Close()
			return
		}
		byteCount += len(h)
		if byteCount > maxConnectHeaderBytes {
			_, _ = outer.Write([]byte("HTTP/1.1 400 Bad Request\r\n\r\n"))
			outer.Close()
			return
		}
		if h == "\r\n" || h == "\n" {
			break
		}
		if len(h) > 0 && (h[0] == ' ' || h[0] == '\t') {
			channelFail = true // obs-fold 续行:拒
			continue
		}
		if tok, valid := connect.ParseProxyAuthorization(h); valid {
			paCount++
			token = tok
		} else if isProxyAuthName(h) {
			// 名命中但值非法(空/控制字符/CRLF):计入但标记失败,使 count==1&&ok==false → 407
			paCount++
			channelFail = true
		}
	}
	// 407 判定:折叠续行 / 名命中但值非法 / count != 1 / Lookup 未命中。任一不过 → 407,
	// 绝不写 200、不签 leaf、不 echo token、日志不含 token。
	if channelFail || paCount != 1 {
		_, _ = outer.Write([]byte("HTTP/1.1 407 Proxy Authentication Required\r\n\r\n"))
		outer.Close()
		return
	}
	if _, hit := fp.auth.Lookup(token); !hit {
		_, _ = outer.Write([]byte("HTTP/1.1 407 Proxy Authentication Required\r\n\r\n"))
		outer.Close()
		return
	}
	// 信道校验全部通过后才做 allowlist 纵深防御:已鉴权设备请求非白名单 host → 403。
	if !fp.allow[host] {
		_, _ = outer.Write([]byte("HTTP/1.1 403 Forbidden\r\n\r\n"))
		outer.Close()
		return
	}
	if _, err := outer.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")); err != nil {
		outer.Close()
		return
	}
	// 隧道已建立：清除握手 deadline，后续内层 TLS 握手与请求读取交内层 http.Server 的 ReadHeaderTimeout 管控。
	_ = outer.SetReadDeadline(time.Time{})
	// 内层 TLS（嵌套在外层 TLS 流之上）：按 CONNECT host 现签 MITM 证书。
	// 客户端在收到 200 后才发内层 ClientHello，故 br 通常无缓冲；但若已缓冲（流水线），
	// 必须把这些字节接回内层 TLS 流，否则握手丢字节。
	var base net.Conn = outer
	if n := br.Buffered(); n > 0 {
		b, _ := br.Peek(n)
		base = &prefixConn{Conn: outer, prefix: append([]byte(nil), b...)}
	}
	tlsConn := tls.Server(base, &tls.Config{
		GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
			return fp.minter.CertFor(host)
		},
	})
	// 在该 TLS conn 上跑一个 per-connection http server（支持隧道内 keep-alive 多请求）。
	// notifyConn + oneConnListener 让 http.Serve 在该连接关闭后才返回（避免提前 Close 正在服务的连接）。
	closed := make(chan struct{})
	nc := &notifyConn{Conn: tlsConn, closed: closed}
	srv := &http.Server{Handler: fp.handler, ReadHeaderTimeout: 30 * time.Second}
	_ = srv.Serve(&oneConnListener{conn: nc, closed: closed})
}

// isProxyAuthName reports whether headerLine's field-name is exactly
// Proxy-Authorization (case-insensitive, no whitespace before ':', no prefix
// shadow like X-Proxy-Authorization / Proxy-Authorization-Foo). Used to count a
// name-matching header even when its VALUE is malformed (so count==1 && bad-value
// still yields 407 rather than being silently dropped as 'unrelated header').
func isProxyAuthName(headerLine string) bool {
	i := strings.IndexByte(headerLine, ':')
	if i < 0 {
		return false
	}
	name := headerLine[:i]
	if name != strings.TrimRight(name, " \t") { // 名与 ':' 间空白 → 拒
		return false
	}
	return strings.EqualFold(name, "Proxy-Authorization")
}

// prefixConn 在读取底层 conn 之前先回放 prefix（被 bufio 预读的 TLS 字节）。
type prefixConn struct {
	net.Conn
	prefix []byte
}

func (c *prefixConn) Read(p []byte) (int, error) {
	if len(c.prefix) > 0 {
		n := copy(p, c.prefix)
		c.prefix = c.prefix[n:]
		return n, nil
	}
	return c.Conn.Read(p)
}

// notifyConn 在 Close 时关闭 closed 通道，通知 oneConnListener 该连接已结束。
type notifyConn struct {
	net.Conn
	once   sync.Once
	closed chan struct{}
}

func (c *notifyConn) Close() error {
	c.once.Do(func() { close(c.closed) })
	return c.Conn.Close()
}

// oneConnListener 只产出一个连接：首次 Accept 返回它，其后阻塞直到该连接关闭再返回 EOF，
// 使 http.Server.Serve 在连接生命周期内不返回。
type oneConnListener struct {
	conn   net.Conn
	closed chan struct{}
	mu     sync.Mutex
	used   bool
}

func (l *oneConnListener) Accept() (net.Conn, error) {
	l.mu.Lock()
	if !l.used {
		l.used = true
		l.mu.Unlock()
		return l.conn, nil
	}
	l.mu.Unlock()
	<-l.closed
	return nil, io.EOF
}

func (l *oneConnListener) Close() error   { return nil }
func (l *oneConnListener) Addr() net.Addr { return l.conn.LocalAddr() }
