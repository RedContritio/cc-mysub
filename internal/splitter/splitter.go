// Package splitter 实现设备本地 CONNECT 分流器：白名单 host 经外层 TLS 链到 cc-mysub
// forward-proxy（由 cc-mysub 终止外层 TLS 后做内层 MITM），其余 host 本地直连盲转发。
// 分流器不终止 claude 的内层 TLS——它只盲转发原始字节；仅持有 CA 公钥 pool 用于
// 验证 cc-mysub 的外层身份，不持有任何 token/私钥。
package splitter

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"strings"

	"github.com/redcontritio/cc-mysub/internal/connect"
)

type dialFunc func(ctx context.Context, network, addr string) (net.Conn, error)

// Splitter 是设备本地 CONNECT 分流器：白名单 host 经外层 TLS 链到 cc-mysub，其余本地直连盲转发。
type Splitter struct {
	upstreamAddr string          // cc-mysub forward-proxy 入口(host:port)
	tlsCfg       *tls.Config     // 外层 TLS 验证 cc-mysub 身份(RootCAs + ServerName)
	channelToken string         // 信道 token: 链式 CONNECT 的 Proxy-Authorization Bearer 值
	allow        map[string]bool // 链到 cc-mysub 的 host(其余直连)
	dial         dialFunc        // 直连拨号(nil→默认 net.Dialer); 测试注入
}

// New 构造分流器。channelToken 作为链式 CONNECT 的 Proxy-Authorization Bearer 值出示给 cc-mysub；
// caPool/serverName 用于验证 cc-mysub 外层身份; dial 为直连拨号(nil→默认)。
// channelToken 由 connect.ValidToken 校验——字符集与 forward-proxy 接收侧完全一致，
// 保证构造时合法的 token 在对端 ParseProxyAuthorization 中不会被拒（silent HTTP 407 根因）。
func New(upstreamAddr string, caPool *x509.CertPool, channelToken string, serverName string, allow []string, dial dialFunc) (*Splitter, error) {
	if !connect.ValidToken(channelToken) {
		return nil, fmt.Errorf("splitter: channel token must be non-empty and contain only [a-zA-Z0-9\\-._~+/=]")
	}
	allowSet := make(map[string]bool, len(allow))
	for _, h := range allow {
		allowSet[h] = true
	}
	if dial == nil {
		dial = func(ctx context.Context, network, addr string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, addr)
		}
	}
	return &Splitter{
		upstreamAddr: upstreamAddr,
		tlsCfg:       &tls.Config{RootCAs: caPool, ServerName: serverName},
		channelToken: channelToken,
		allow:        allowSet,
		dial:         dial,
	}, nil
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
	if s.allow[host] {
		// 外层 TLS 到 cc-mysub, 链式 CONNECT
		up, err := tls.Dial("tcp", s.upstreamAddr, s.tlsCfg)
		if err != nil {
			c.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
			return
		}
		defer up.Close()
		if _, err := up.Write([]byte("CONNECT " + target + " HTTP/1.1\r\nHost: " + target + "\r\nProxy-Authorization: Bearer " + s.channelToken + "\r\n\r\n")); err != nil {
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
		c.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
		relay(c, cbr, up, ubr) // 双向盲转发(用 bufio 读端避免丢已缓冲字节)
		return
	}
	// 直连盲转发
	d, err := s.dial(context.Background(), "tcp", target)
	if err != nil {
		c.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
		return
	}
	defer d.Close()
	c.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
	relay(c, cbr, d, bufio.NewReader(d))
}

// relay 双向拷贝 a<->b, 任一方向结束即收尾(关闭两端解除另一方向阻塞)。
// aR/bR 为各自的 bufio 读端(可能已缓冲), 写仍用裸 conn。
func relay(a net.Conn, aR io.Reader, b net.Conn, bR io.Reader) {
	done := make(chan struct{}, 2)
	go func() { io.Copy(b, aR); done <- struct{}{} }()
	go func() { io.Copy(a, bR); done <- struct{}{} }()
	<-done
	a.Close()
	b.Close()
	<-done
}
