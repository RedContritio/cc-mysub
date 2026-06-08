package proxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"sync"
	"time"

	"github.com/redcontritio/cc-mysub/internal/auth"
	"github.com/redcontritio/cc-mysub/internal/config"
	"github.com/redcontritio/cc-mysub/internal/connect"
	"github.com/redcontritio/cc-mysub/internal/mitm"
)

type rewriteCtxKey int

const realTokenKey rewriteCtxKey = 0

// conditionalAuth 是前置中间件（凭据存在性分流）。设备身份来自外层 mTLS 客户端证书
// （由 handle() 经 http.Server.BaseContext 注入 ctx 的 deviceKey），不再从内层 token 取。
//   - 入站无凭据（匿名遥测）→ 放行，不读 device、不注入 realToken、不碰任何头（匿名零注入）
//   - 入站有凭据 + ctx 有设备 D → real=up.PickToken(D.Upstream)；real==""→502；注入 realToken 放行
//   - 入站有凭据但 ctx 无设备 = 编程错（BaseContext 必注入）→ 502，绝不静默用默认 token
func conditionalAuth(up *config.Upstream) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !auth.HasInboundCredential(r) {
				next.ServeHTTP(w, r) // 匿名透传，零注入
				return
			}
			d, ok := r.Context().Value(deviceKey).(auth.Device)
			if !ok || d.Label == "" {
				writeJSONError(w, http.StatusBadGateway, "no_device", "authenticated connection missing device identity")
				return
			}
			real := up.PickToken(d.Upstream)
			if real == "" {
				writeJSONError(w, http.StatusBadGateway, "no_upstream_token", "no upstream token for device")
				return
			}
			next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), realTokenKey, real)))
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
			if real, _ := pr.In.Context().Value(realTokenKey).(string); real != "" {
				pr.Out.Header.Set("Authorization", "Bearer "+real)
				pr.Out.Header.Del("X-Api-Key") // 仅非匿名分支删；匿名请求一个头都不碰（§0）
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
func newRewriteHandler(up *config.Upstream, rt http.RoundTripper) http.Handler {
	return conditionalAuth(up)(forwardSwap(rt))
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
	minter    certMinter                                           // 内层 MITM 叶证书现签（spy 可注入）
	handler   http.Handler                                         // newRewriteHandler 的结果，逐请求按 req.Host 决定上游
	auth      Authenticator                                        // 外层 mTLS 准入：按客户端证书指纹查白名单（§5.1）
	allow     map[string]bool                                      // 允许 MITM 的 CONNECT 目标 host（纵深防御，拒其余）
	outerCert func(*tls.ClientHelloInfo) (*tls.Certificate, error) // 外层 TLS 身份（真 LE，续期热重载）
	sema      chan struct{}                                        // 全局并发 self-cap：acquire 在 spawn 前、release 在 handle defer（§3.4）
	wg        sync.WaitGroup                                       // 跟踪在途 handle goroutine，Serve 退出前等待其收尾
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
// allow 为允许 MITM 的 CONNECT 目标 host 列表；outerCert 为外层 TLS 身份证书来源（真 LE 加载器）。
// maxInFlight 为全局并发上限（>0 强制要求，<=0 panic；饱和时 shed 新连接）。
//
// serving chain：conditionalAuth（前置，按证书设备注入 realToken）→ RateLimitByDevice → AccessLog
// → forwardSwap（换 token 转发）。设备身份由外层 mTLS 证书在 handle() 经 BaseContext 注入。
func NewForwardProxy(m *mitm.Minter, a Authenticator, up *config.Upstream, upstream http.RoundTripper, allow []string, outerCert func(*tls.ClientHelloInfo) (*tls.Certificate, error), maxInFlight int) *ForwardProxy {
	if maxInFlight <= 0 {
		panic("proxy: NewForwardProxy requires maxInFlight > 0")
	}
	if outerCert == nil {
		panic("proxy: NewForwardProxy requires outerCert")
	}
	allowSet := make(map[string]bool, len(allow))
	for _, h := range allow {
		allowSet[h] = true
	}
	handler := conditionalAuth(up)(
		RateLimitByDevice(120)(
			AccessLog(nil)(
				forwardSwap(upstream),
			),
		),
	)
	return &ForwardProxy{
		minter:    m,
		handler:   handler,
		auth:      a,
		allow:     allowSet,
		outerCert: outerCert,
		sema:      make(chan struct{}, maxInFlight),
	}
}

// Serve 接受连接并逐个 MITM 处理,直到 ln 关闭。全局 semaphore self-cap(§3.4):
// 槽位满时 Accept 后立即 Close(shed),不 spawn handle——把 DoS 收敛上限钉死在
// maxInFlight,而非无界 goroutine。per-source-IP 限流委托 nftables(frp 塌源 IP)。
func (fp *ForwardProxy) Serve(ln net.Listener) error {
	for {
		conn, err := ln.Accept()
		if err != nil {
			fp.wg.Wait() // 等在途连接收尾,避免孤儿 goroutine 在调用方释放资源后访问
			return err
		}
		select {
		case fp.sema <- struct{}{}: // 抢到槽位
			fp.wg.Add(1)
			go fp.handle(conn)
		default: // 饱和:立即 shed,不 spawn handle、不握手
			conn.Close()
		}
	}
}

func (fp *ForwardProxy) handle(rawConn net.Conn) {
	defer fp.wg.Done()
	defer func() { <-fp.sema }() // 释放并发槽位(与 Serve 的 fp.sema<-struct{}{} 配对)
	// 外层 TLS（双向 mTLS）：呈现真 LE 身份证书；要求并按指纹白名单校验客户端证书。
	// 此后所有读写都走 outer（Close(outer) 即 Close(rawConn)）。
	var connDevice auth.Device // 由 VerifyPeerCertificate 在握手内捕获（消二次 Lookup 的热重载 TOCTOU）
	outer := tls.Server(rawConn, &tls.Config{
		GetCertificate: fp.outerCert,
		ClientAuth:     tls.RequireAnyClientCert,
		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			// no-cert 已被 RequireAnyClientCert 在此之前拒，故 rawCerts 必非空（不加死守卫）。
			d, ok := fp.auth.Lookup(auth.CertFingerprint(rawCerts[0]))
			if !ok {
				return fmt.Errorf("client cert fingerprint not registered")
			}
			connDevice = d
			return nil
		},
	})
	// slowloris 防护：外层握手 + CONNECT 读取阶段设读 deadline；写出 200 后清除。
	_ = outer.SetReadDeadline(time.Now().Add(handshakeReadTimeout))
	// 显式握手：无客户端证书 / 指纹不在白名单 → 握手失败、零应用字节（连接级掐断）。
	if err := outer.Handshake(); err != nil {
		outer.Close()
		return
	}
	br := bufio.NewReader(outer)
	// 手动字节累加器(pre-200 cap):CONNECT 行 + 每个头行长度累加,超 maxConnectHeaderBytes → 400 + Close。
	// 不用 io.LimitReader 包 conn——会被 bufio 预读误计并破坏 br.Buffered()/prefixConn 回放。
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
	// drain CONNECT 头到空行（身份已由外层 mTLS 证书确定，不再解析 Proxy-Authorization）。
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
	}
	// allowlist 纵深防御：已认证设备请求非白名单 host → 403。
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
	// BaseContext 把外层 mTLS 证书识别出的设备注入该连接所有内层请求的 ctx，
	// 供 conditionalAuth/RateLimit/AccessLog 读取（ctx 仅向下游传播，故在连接层注入）。
	srv := &http.Server{
		Handler:           fp.handler,
		ReadHeaderTimeout: 30 * time.Second,
		BaseContext: func(net.Listener) context.Context {
			return context.WithValue(context.Background(), deviceKey, connDevice)
		},
	}
	_ = srv.Serve(&oneConnListener{conn: nc, closed: closed})
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
