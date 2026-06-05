package proxy

import (
	"bufio"
	"context"
	"crypto/tls"
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

// newRewriteHandler 构造 forward-proxy 的逐请求 handler（条件换 token，见 spec §4/§5.3）：
//   - 入站 per-device token 命中 → 出站 Authorization 换成该设备的 setup-token
//   - 入站无凭据（匿名遥测）→ 透传，不注入任何凭据
//   - 入站有 token 但未命中 → 401，不转发（认证门）
//   - 命中但其 upstream id 不在池（PickToken 返回 ""）→ 502，不转发
//   - 恒删出站 X-Api-Key
//
// 上游 = 入站请求的 scheme/host（per-connection CONNECT 目标；scheme 缺省 https）。
// rt 为 nil 时用默认 retryTransport（T7 注入自定义 transport 以重定向 dial / 信任假上游 CA）。
func newRewriteHandler(a Authenticator, up *config.Upstream, rt http.RoundTripper) http.Handler {
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
			// 匿名（real==""）：不注入 cc-mysub 凭据，且对入站 Authorization 逐字节透传——
			// 保字节级不可区分于直连（治理总纲 §0）。真匿名遥测本就无 Authorization，此处为 no-op。
		},
		Transport: rt,
		ErrorHandler: func(w http.ResponseWriter, _ *http.Request, _ error) {
			writeJSONError(w, http.StatusBadGateway, "upstream_error", "upstream request failed")
		},
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tok := auth.ExtractToken(r)
		if tok != "" {
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
			r = r.WithContext(context.WithValue(r.Context(), realTokenKey, real))
		}
		rp.ServeHTTP(w, r)
	})
}

// ForwardProxy 是 CONNECT forward-proxy。整个 device↔cc-mysub 跳被外层 TLS 包裹
// （外层呈现 cc-mysub 自身身份证书 serverName，使 CONNECT 目标 host 不以明文上线）；
// 在外层 TLS 内读 CONNECT 目标、按 allowlist 拒非法 host（纵深防御），回 200 后再按 host
// 现签证书跑内层 MITM TLS（嵌套 TLS），把解密后的 HTTP 请求经 rewrite handler 转发到真目标 host。
type ForwardProxy struct {
	minter     *mitm.Minter
	handler    http.Handler    // newRewriteHandler 的结果，逐请求按 req.Host 决定上游
	allow      map[string]bool // 允许 MITM 的 CONNECT 目标 host（纵深防御，拒其余）
	serverName string          // 外层 TLS 身份（cc-mysub public_host），现签证书的 CN/SAN
	wg         sync.WaitGroup  // 跟踪在途 handle goroutine，Serve 退出前等待其收尾
}

// handshakeReadTimeout 限定外层 TLS 握手 + CONNECT 行/头读取的总时长，防 slowloris 把
// handle goroutine + FD 永久占住（写出 200 后清除，交内层 http.Server 的 ReadHeaderTimeout 接管）。
const handshakeReadTimeout = 15 * time.Second

// NewForwardProxy 装配 forward-proxy。upstream 为到真目标的 transport（含 dial + TLS 验证）；
// nil 时 newRewriteHandler 用默认 retryTransport（生产：真 DNS + 验真证书）。
// allow 为允许 MITM 的 CONNECT 目标 host 列表；serverName 为外层 TLS 呈现的 cc-mysub 身份。
func NewForwardProxy(m *mitm.Minter, a Authenticator, up *config.Upstream, upstream http.RoundTripper, allow []string, serverName string) *ForwardProxy {
	allowSet := make(map[string]bool, len(allow))
	for _, h := range allow {
		allowSet[h] = true
	}
	return &ForwardProxy{
		minter:     m,
		handler:    newRewriteHandler(a, up, upstream),
		allow:      allowSet,
		serverName: serverName,
	}
}

// Serve 接受连接并逐个 MITM 处理，直到 ln 关闭。
func (fp *ForwardProxy) Serve(ln net.Listener) error {
	for {
		conn, err := ln.Accept()
		if err != nil {
			fp.wg.Wait() // 等在途连接收尾，避免孤儿 goroutine 在调用方释放资源后访问
			return err
		}
		fp.wg.Add(1)
		go fp.handle(conn)
	}
}

func (fp *ForwardProxy) handle(rawConn net.Conn) {
	defer fp.wg.Done()
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
	line, err := br.ReadString('\n')
	if err != nil {
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
	// allowlist 纵深防御：只 MITM 白名单内的 host，其余一律 403，不签证书、不建内层隧道。
	if !fp.allow[host] {
		_, _ = outer.Write([]byte("HTTP/1.1 403 Forbidden\r\n\r\n"))
		outer.Close()
		return
	}
	// 读完剩余 CONNECT 请求头直到空行
	for {
		h, err := br.ReadString('\n')
		if err != nil {
			outer.Close()
			return
		}
		if h == "\r\n" || h == "\n" {
			break
		}
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
