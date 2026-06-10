package proxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"strings"
	"sync"
	"time"

	"github.com/redcontritio/cc-mysub/internal/auth"
	"github.com/redcontritio/cc-mysub/internal/config"
	"github.com/redcontritio/cc-mysub/internal/connect"
	"github.com/redcontritio/cc-mysub/internal/hosts"
	"github.com/redcontritio/cc-mysub/internal/mitm"
)

type rewriteCtxKey int

const (
	realTokenKey rewriteCtxKey = iota
	// connectHostKey 持 handle() 已验证分类为 MITM 的 CONNECT host(经 BaseContext 注入)。
	// forwardSwap 用它强制出站目标,绝不信内层请求的 Host/URL.Host——否则不可信设备发
	// Host: attacker 就能把换上的真 token 导向任意域名(P0,codex 全仓审查)。
	connectHostKey
)

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
//   - 上游 = ctx 注入的 connectHost（handle 验证过的 MITM CONNECT host）；scheme 固定 https。
//     绝不取内层请求的 Host/URL.Host（不可信设备控制 → 真 token 旁路，见 connectHostKey 注释）
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
			// 出站目标强制绑定 handle() 已验证分类为 MITM 的 CONNECT host(经 BaseContext 注入 connectHostKey)——
			// 绝不信内层请求的 URL.Host/Host 头(不可信设备控制),否则设备发 Host: attacker 就能把真 token 导走(P0)。
			// scheme 固定 https(MITM 上游恒 https,防设备发 http:// 降级)。connectHost 空(无注入)→ 出站 host 空,
			// Transport 报错走 ErrorHandler 502,fail-closed(绝不转发到不受控目标)。
			connectHost, _ := pr.In.Context().Value(connectHostKey).(string)
			pr.Out.URL.Scheme = "https"
			pr.Out.URL.Host = connectHost
			pr.Out.Host = "" // Host 头取 URL.Host(=connectHost)
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

// dialFunc 拨号一个原始 TCP 连接（透传隧道用）；nil → 默认 net.Dialer。测试注入以把透传上游
// 重定向到假服务端（与 MITM 路径的 upstream http.RoundTripper 注入对应）。
type dialFunc func(ctx context.Context, network, addr string) (net.Conn, error)

// ForwardProxy 是 CONNECT forward-proxy。整个 device↔cc-mysub 跳被外层 TLS 包裹
// （外层呈现 cc-mysub 自身身份证书 serverName，使 CONNECT 目标 host 不以明文上线）；
// 在外层 TLS 内读 CONNECT 目标，按 hosts.Classify 分类:
//   - MITM 类: 回 200 后按 host 现签证书跑内层 MITM TLS（嵌套 TLS），把解密后的 HTTP
//     请求经 rewrite handler 换 token 转发到真目标 host。
//   - 透传类（自家域名后缀 + 第三方精确）: 先拨真上游、成功才回 200，再盲转发原始字节（不解密、
//     不碰 token）——经统一出口出网，避免设备直连泄漏真实 IP；不扩解密面、不破坏 cert pinning。
//   - Direct → 403（纵深防御）。
type ForwardProxy struct {
	minter    certMinter                                           // 内层 MITM 叶证书现签（spy 可注入）
	handler   http.Handler                                         // newRewriteHandler 的结果，逐请求按 req.Host 决定上游
	auth      Authenticator                                        // 外层 mTLS 准入：按客户端证书指纹查白名单（§5.1）
	passDial  dialFunc                                             // 透传隧道拨真上游（nil→默认 net.Dialer；测试注入重定向）
	outerCert func(*tls.ClientHelloInfo) (*tls.Certificate, error) // 外层 TLS 身份（真 LE，续期热重载）
	sema      chan struct{}                                        // 全局并发 self-cap：acquire 在 spawn 前、release 在 handle defer（§3.4）
	wg        sync.WaitGroup                                       // 跟踪在途 handle goroutine，Serve 退出前等待其收尾
	connMu    sync.Mutex                                           // 保护 conns
	conns     map[string]map[net.Conn]struct{}                     // fingerprint → 活跃外层连接（P1-2：吊销时主动断开）
}

// handshakeReadTimeout 限定外层 TLS 握手 + CONNECT 行/头读取的总时长，防 slowloris 把
// handle goroutine + FD 永久占住（写出 200 后清除，交内层 http.Server 的 ReadHeaderTimeout 接管）。
const handshakeReadTimeout = 15 * time.Second

// maxConnectHeaderBytes 限定 pre-200 阶段（CONNECT 行 + 全部 CONNECT 头）的累计字节数，
// 防超长头打爆 handle goroutine 内存。手动累加器，不用 io.LimitReader——后者会与 bufio 预读
// 互相误计并破坏 br.Buffered()/prefixConn 的流水线回放（spec §3.2 第 1 点）。
const maxConnectHeaderBytes = 8192

// idleTimeout 是已建立隧道(内层 MITM keep-alive / passthrough relay)的空闲回收超时:双向无字节流动
// 超过此值即断、释放并发槽(§3.4 的 sema),防被盗设备开满空闲连接占满槽(P2-6)。10 分钟覆盖 claude
// 正常 turn 内工具执行 + turn 间思考,挂机超 10 分钟才回收;claude 断后重连透明(见 P1-2 研究)。
const idleTimeout = 10 * time.Minute

// NewForwardProxy 装配 forward-proxy。upstream 为到真目标的 transport（含 dial + TLS 验证）；
// nil 时 forwardSwap 用默认 retryTransport（生产：真 DNS + 验真证书）。
// CONNECT 目标的分类（MITM 换 token / 透传盲隧道 / 403）由 internal/hosts.Classify 权威裁决——
// 不再从参数收 host 列表（单一事实源，消除设备 splitter 与本代理两端清单漂移）。
// outerCert 为外层 TLS 身份证书来源（真 LE 加载器）。
// maxInFlight 为全局并发上限（>0 强制要求，<=0 panic；饱和时 shed 新连接）。
//
// serving chain：conditionalAuth（前置，按证书设备注入 realToken）→ RateLimitByDevice → AccessLog
// → forwardSwap（换 token 转发）。设备身份由外层 mTLS 证书在 handle() 经 BaseContext 注入。
func NewForwardProxy(m *mitm.Minter, a Authenticator, up *config.Upstream, upstream http.RoundTripper, outerCert func(*tls.ClientHelloInfo) (*tls.Certificate, error), maxInFlight int) *ForwardProxy {
	if maxInFlight <= 0 {
		panic("proxy: NewForwardProxy requires maxInFlight > 0")
	}
	if outerCert == nil {
		panic("proxy: NewForwardProxy requires outerCert")
	}
	handler := conditionalAuth(up)(
		RateLimitByDevice(120)(
			AccessLog(nil)(
				forwardSwap(upstream),
			),
		),
	)
	return &ForwardProxy{
		minter:  m,
		handler: handler,
		auth:    a,
		passDial: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, addr)
		},
		outerCert: outerCert,
		sema:      make(chan struct{}, maxInFlight),
		conns:     make(map[string]map[net.Conn]struct{}),
	}
}

// registerConn 把外层连接登记到其设备指纹(P1-2:供 RevokeConns 主动断开)。
func (fp *ForwardProxy) registerConn(fingerprint string, c net.Conn) {
	fp.connMu.Lock()
	defer fp.connMu.Unlock()
	set := fp.conns[fingerprint]
	if set == nil {
		set = make(map[net.Conn]struct{})
		fp.conns[fingerprint] = set
	}
	set[c] = struct{}{}
}

// unregisterConn 在 handle 退出时注销连接。
func (fp *ForwardProxy) unregisterConn(fingerprint string, c net.Conn) {
	fp.connMu.Lock()
	defer fp.connMu.Unlock()
	if set := fp.conns[fingerprint]; set != nil {
		delete(set, c)
		if len(set) == 0 {
			delete(fp.conns, fingerprint)
		}
	}
}

// RevokeConns 关闭这些 fingerprint 的所有既有外层连接——吊销即时生效:既有长连接被断,claude 重连时
// 新外层 mTLS 握手被 VerifyPeerCertificate 拒(指纹已不在 devices.json)。供 DeviceStore.SetOnRevoke 回调。
// 先锁内收集、锁外 Close:Close 触发 handle 退出 → unregisterConn 再取 connMu,锁外避免重入死锁。
func (fp *ForwardProxy) RevokeConns(fingerprints []string) {
	fp.connMu.Lock()
	var toClose []net.Conn
	for _, f := range fingerprints {
		for c := range fp.conns[f] {
			toClose = append(toClose, c)
		}
	}
	fp.connMu.Unlock()
	for _, c := range toClose {
		_ = c.Close()
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
	// 握手成功:把该外层连接登记到其设备指纹,供吊销时主动断开(P1-2);handle 退出时注销。
	fp.registerConn(connDevice.CertSHA256, outer)
	defer fp.unregisterConn(connDevice.CertSHA256, outer)
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
	// host 分类（internal/hosts.Classify）：MITM 类（解密换 token）/ 透传类（盲隧道）/ Direct→403（纵深防御）。
	class := hosts.Classify(host)
	if class == hosts.Direct {
		_, _ = outer.Write([]byte("HTTP/1.1 403 Forbidden\r\n\r\n"))
		outer.Close()
		return
	}
	if class == hosts.Passthrough {
		// 透传类盲隧道。allowlist 是 host-only，但透传仅放行标准 HTTPS :443——与 MITM 路径恒拨
		// :443 对称，且防止借盲隧道把 cc-mysub 出口当任意端口 port-forward（最小权限）。CONNECT
		// 端口非 443 = 越权,显式 403（不静默改写）。ParseConnect 已校验 host:port 合法。
		target := strings.Fields(line)[1]
		_, port, err := net.SplitHostPort(target)
		if err != nil || port != "443" {
			_, _ = outer.Write([]byte("HTTP/1.1 403 Forbidden\r\n\r\n"))
			outer.Close()
			return
		}
		// 拨真上游成功才回 200，再盲转发原始字节（不现签叶证书、不进 MITM）。
		fp.tunnel(outer, br, host)
		return
	}
	// MITM 类：回 200 后跑内层嵌套 TLS。
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
			// 注入设备(认证身份)+ connectHost(已验证 MITM 的 CONNECT 目标)——后者使 forwardSwap 把出站
			// 绑定到此 host,杜绝内层请求 Host 头把真 token 导向任意域名(P0)。host 已经 ParseConnect
			// 规范化且 ∈ MITMHosts(Classify=MITM 才走到这),故是 api/console.anthropic.com 之一。
			ctx := context.WithValue(context.Background(), deviceKey, connDevice)
			return context.WithValue(ctx, connectHostKey, host)
		},
	}
	_ = srv.Serve(&oneConnListener{conn: nc, closed: closed})
}

// tunnel 处理透传类 host：拨真上游（passDial）→ 成功才回 200 → 盲双向转发原始字节。
// 不现签叶证书、不解密、不碰任何头——claude 与真上游端到端做 TLS（cc-mysub 只搬 TCP 字节），
// 故不扩解密面、不破坏 cert pinning，仅把出口 IP 收敛到统一出口。outerR 为 outer 的 bufio 读端
// （可能已缓冲 claude 流水线发来的内层 ClientHello，必须从它读以免丢字节）。
func (fp *ForwardProxy) tunnel(outer net.Conn, outerR io.Reader, host string) {
	// 拨号设超时：上游黑洞时不让 handle goroutine + 并发槽位无限期挂住（outer 的握手 deadline
	// 此刻不读 outer、管不到拨号）。透传仅放行 :443（见 handle 的端口校验）。
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	up, err := fp.passDial(ctx, "tcp", net.JoinHostPort(host, "443"))
	if err != nil {
		// 拨上游失败：CONNECT 尚未回 200，可如实回 502（区别于 MITM 路径 200 后才连上游）。
		_, _ = outer.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
		outer.Close()
		return
	}
	defer up.Close()
	if _, err := outer.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")); err != nil {
		outer.Close()
		return
	}
	// 隧道已建立：清除握手 deadline，否则长连接 relay 会被 15s 读超时打断。
	_ = outer.SetReadDeadline(time.Time{})
	// 可观测性：记录经出口透传的 host（不解密 body，仅目标 host——已知于 allowlist，非用户内容）。
	// 与 MITM 路径的 AccessLog 对称，亦供 egress 审计断言 cc-mysub 确实经此转发遥测/更新。
	slog.Info("passthrough", "host", host)
	relayBlind(outer, outerR, up, idleTimeout)
}

// relayBlind 双向盲拷贝 outer<->up，任一方向结束即收尾（关闭两端解除另一方向阻塞）。
// outerR 为 outer 的读端（可能已缓冲），写仍用裸 outer。idle>0 时加空闲回收（P2-6）:任一方向有字节
// 流动就把双向 read deadline 刷新到 now+idle（故单向流量如下载不会误断），双向静默超 idle → Read
// 超时 → 断、释放 sema 槽。
func relayBlind(outer net.Conn, outerR io.Reader, up net.Conn, idle time.Duration) {
	touch := func() {
		if idle > 0 {
			d := time.Now().Add(idle)
			_ = outer.SetReadDeadline(d)
			_ = up.SetReadDeadline(d)
		}
	}
	touch()
	done := make(chan struct{}, 2)
	cp := func(dst net.Conn, src io.Reader) {
		buf := make([]byte, 32*1024)
		for {
			n, err := src.Read(buf)
			if n > 0 {
				touch() // 任一方向有流量 → 刷新双向 deadline（单向流量不误断）
				if _, werr := dst.Write(buf[:n]); werr != nil {
					break
				}
			}
			if err != nil {
				break
			}
		}
		done <- struct{}{}
	}
	go cp(up, outerR)
	go cp(outer, up)
	<-done
	outer.Close()
	up.Close()
	<-done
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
