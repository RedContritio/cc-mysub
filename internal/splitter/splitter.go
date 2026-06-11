// Package splitter 实现设备本地 CONNECT 分流器：属 hosts.Classify 收口集的 host 经外层 mTLS 链到
// cc-mysub forward-proxy（出示本设备客户端证书，cc-mysub 按指纹认证后做内层 MITM），其余 host 本地
// 直连盲转发。
// 分流器不终止 claude 的内层 TLS——它只盲转发原始字节；持有本设备客户端证书+私钥用于外层 mTLS，
// 外层服务端身份（真 LE）走设备系统信任验证，故不持有 cc-mysub CA。
package splitter

import (
	"bufio"
	"context"
	"crypto/tls"
	"io"
	"net"
	"strings"
	"time"

	"github.com/redcontritio/cc-mysub/internal/connect"
	"github.com/redcontritio/cc-mysub/internal/hosts"
)

// 链路有界性常量,镜像服务端 internal/proxy/forward.go——established TCP 上没有 OS 级读超时,
// cc-mysub(或直连目标)可达但停滞(established-but-idle)时,无 deadline 的 handle 会连同两个 FD
// 永久挂死且无自愈,长会话中持续累积。下列三个阶段各自封顶:
//   - defaultDialTimeout: 拨号阶段,黑洞/不可达目标不让 handle 永久挂在 dial。
//   - defaultSetupTimeout: chain 分支「外层 mTLS 握手 + 写 CONNECT + 读 cc-mysub 200 响应头」总时长
//     (对 forward.go 的 handshakeReadTimeout);收完 200 头后清除,交 relay 的 idle 回收。
//   - defaultIdleTimeout: 已建隧道双向空闲回收(对 forward.go 的 idleTimeout/P2-6);双向静默超此则
//     relay 的 Read 超时 → 断、回收 goroutine/FD,长期静默连接不永久占用。
const (
	defaultDialTimeout  = 10 * time.Second
	defaultSetupTimeout = 15 * time.Second
	defaultIdleTimeout  = 10 * time.Minute
)

type dialFunc func(ctx context.Context, network, addr string) (net.Conn, error)

// Splitter 是设备本地 CONNECT 分流器：白名单 host 经外层 mTLS 链到 cc-mysub，其余本地直连盲转发。
type Splitter struct {
	host   string          // cc-mysub 域名(public_host); 拨 host:443 + 外层 TLS ServerName
	tlsCfg *tls.Config     // 外层 mTLS: 出示本设备客户端证书 + 系统信任验真 LE 服务端身份
	extra  map[string]bool // --allow 额外强制 chain 的 host(精确); 默认收口判定走 hosts.Classify
	dial   dialFunc        // 拨号(nil→默认 net.Dialer); 测试注入(chain 与 direct 两分支都经此)
	// 链路有界性超时(New 默认 default*Timeout 常量);白盒测试调小以快速验证停滞被超时解除。
	dialTimeout  time.Duration // 拨号封顶
	setupTimeout time.Duration // chain 分支握手 + 读 200 响应封顶
	idleTimeout  time.Duration // 已建隧道双向空闲回收
}

// New 构造分流器。host = cc-mysub 域名(拨 host:443、外层 ServerName)；clientCert = 本设备客户端
// 证书+私钥，外层 mTLS 握手出示（cc-mysub 按其指纹认证）；extraAllow = 在 hosts.Classify 收口集之外
// 额外强制 chain 到 cc-mysub 的 host（--allow override，精确；默认收口集见 internal/hosts）；
// dial = 拨号(nil→默认)。外层服务端身份(真 LE)走系统信任验证，故不收 CA pool。
func New(host string, clientCert tls.Certificate, extraAllow []string, dial dialFunc) *Splitter {
	extra := make(map[string]bool, len(extraAllow))
	for _, h := range extraAllow {
		extra[h] = true
	}
	if dial == nil {
		dial = func(ctx context.Context, network, addr string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, addr)
		}
	}
	return &Splitter{
		host:         host,
		tlsCfg:       &tls.Config{ServerName: host, Certificates: []tls.Certificate{clientCert}},
		extra:        extra,
		dial:         dial,
		dialTimeout:  defaultDialTimeout,
		setupTimeout: defaultSetupTimeout,
		idleTimeout:  defaultIdleTimeout,
	}
}

// Serve 接受连接并分流，直到 ln 关闭或出错。
func (s *Splitter) Serve(ln net.Listener) error {
	for {
		c, err := ln.Accept()
		if err != nil {
			return err
		}
		go s.handle(c)
	}
}

func (s *Splitter) handle(c net.Conn) {
	defer c.Close()
	cbr := bufio.NewReader(c)
	line, err := cbr.ReadString('\n')
	if err != nil {
		return
	}
	host, ok := connect.ParseConnect(line)
	if !ok {
		c.Write([]byte("HTTP/1.1 400 Bad Request\r\n\r\n"))
		return
	}
	target := strings.Fields(line)[1] // host:port(保留 claude 的原始端口)
	// 读完 claude 的 CONNECT 头到空行
	for {
		h, err := cbr.ReadString('\n')
		if err != nil {
			return
		}
		if h == "\r\n" || h == "\n" {
			break
		}
	}
	// 收口判定：属 hosts.Classify 收口集(自家后缀+第三方精确)或 --allow 额外指定 → 经 cc-mysub；其余直连。
	if hosts.Classify(host) != hosts.Direct || s.extra[host] {
		// 外层 mTLS 到 cc-mysub(拨 host:443, 出示本设备客户端证书), 链式 CONNECT。
		// 身份由客户端证书承载，不再带 Proxy-Authorization 信道 token。
		// 拨号设超时:cc-mysub 黑洞/不可达时不让 handle 永久挂在 dial(established 后 cancel 不影响连接)。
		dctx, cancel := context.WithTimeout(context.Background(), s.dialTimeout)
		raw, err := s.dial(dctx, "tcp", net.JoinHostPort(s.host, "443"))
		cancel()
		if err != nil {
			c.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
			return
		}
		up := tls.Client(raw, s.tlsCfg)
		defer up.Close()
		// established-but-idle 的 cc-mysub(TCP 接通但不发字节)上,Handshake/ReadString 无 OS 级超时会
		// 永久阻塞;故握手+读 200 响应阶段对底层 raw 设 deadline,收完 200 头后清除交 relay 的 idle 回收。
		_ = raw.SetDeadline(time.Now().Add(s.setupTimeout))
		if err := up.Handshake(); err != nil {
			c.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
			return
		}
		if _, err := up.Write([]byte("CONNECT " + target + " HTTP/1.1\r\nHost: " + target + "\r\n\r\n")); err != nil {
			return
		}
		ubr := bufio.NewReader(up)
		status, err := ubr.ReadString('\n')
		if err != nil || !strings.Contains(status, "200") {
			c.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
			return
		}
		for { // drain cc-mysub 的 200 头
			h, err := ubr.ReadString('\n')
			if err != nil {
				return
			}
			if h == "\r\n" || h == "\n" {
				break
			}
		}
		// 隧道已建立:清除握手/响应 deadline(否则长连接 relay 会被 setupTimeout 打断),交 relay 的 idle 回收。
		_ = raw.SetDeadline(time.Time{})
		c.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
		relay(c, cbr, up, ubr, s.idleTimeout) // 双向盲转发(用 bufio 读端避免丢已缓冲字节)
		return
	}
	// 直连盲转发
	dctx, cancel := context.WithTimeout(context.Background(), s.dialTimeout)
	d, err := s.dial(dctx, "tcp", target)
	cancel()
	if err != nil {
		c.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
		return
	}
	defer d.Close()
	c.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
	relay(c, cbr, d, bufio.NewReader(d), s.idleTimeout)
}

// relay 双向拷贝 a<->b, 任一方向结束即收尾(关闭两端解除另一方向阻塞)。
// aR/bR 为各自的 bufio 读端(可能已缓冲), 写仍用裸 conn。idle>0 时加空闲回收(对服务端
// forward.go 的 relayBlind/P2-6):任一方向有字节流动就把双向 read deadline 刷新到 now+idle
// (单向流量如下载不误断),双向静默超 idle → Read 超时 → 断、回收 goroutine/FD。
func relay(a net.Conn, aR io.Reader, b net.Conn, bR io.Reader, idle time.Duration) {
	touch := func() {
		if idle > 0 {
			d := time.Now().Add(idle)
			_ = a.SetReadDeadline(d)
			_ = b.SetReadDeadline(d)
		}
	}
	touch()
	done := make(chan struct{}, 2)
	cp := func(dst net.Conn, src io.Reader) {
		buf := make([]byte, 32*1024)
		for {
			n, err := src.Read(buf)
			if n > 0 {
				touch() // 任一方向有流量 → 刷新双向 deadline(单向流量不误断)
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
	go cp(b, aR)
	go cp(a, bR)
	<-done
	a.Close()
	b.Close()
	<-done
}
