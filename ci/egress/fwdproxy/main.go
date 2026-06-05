// fwdproxy: 最小 HTTP CONNECT 转发代理（仅 CI 覆盖率测试用，不入产品二进制）。
// 用于实测 claude 是否把全部出网都经 HTTPS_PROXY 交出来:记录每个 CONNECT 目标主机,
// 把 PROXY_HOST 路由到 cc-mysub、其余路由到 collector-A(proxied 观测点)。
// 凡"经 proxy"的请求落 collector-A;凡绕过 proxy 直连的(走 catch-all DNS)落 collector-B。
package main

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"sort"
	"strings"
	"sync"
	"syscall"
)

func envOr(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}

func main() {
	addr := envOr("FWD_ADDR", "127.0.0.1:8080")
	proxyHost := os.Getenv("PROXY_HOST")
	ccAddr := envOr("CC_ADDR", "127.0.0.1:443")
	collAddr := envOr("COLL_A_ADDR", "127.0.0.2:443") // proxied 落点

	var mu sync.Mutex
	seen := map[string]int{}

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		fmt.Fprintln(os.Stderr, "fwdproxy listen:", err)
		os.Exit(1)
	}
	fmt.Fprintln(os.Stderr, "fwdproxy listening on", addr)

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sig
		mu.Lock()
		defer mu.Unlock()
		hosts := make([]string, 0, len(seen))
		for h := range seen {
			hosts = append(hosts, h)
		}
		sort.Strings(hosts)
		fmt.Println("=== FWDPROXY: CONNECT targets (claude 经 HTTPS_PROXY 交出的) ===")
		for _, h := range hosts {
			fmt.Printf("%-40s count=%d\n", h, seen[h])
		}
		os.Exit(0)
	}()

	for {
		c, err := ln.Accept()
		if err != nil {
			continue
		}
		go func(c net.Conn) {
			defer c.Close()
			br := bufio.NewReader(c)
			line, err := br.ReadString('\n')
			if err != nil {
				return
			}
			parts := strings.Fields(line)
			if len(parts) < 2 || strings.ToUpper(parts[0]) != "CONNECT" {
				_, _ = c.Write([]byte("HTTP/1.1 405 Method Not Allowed\r\n\r\n"))
				return
			}
			hostport := parts[1]
			host := hostport
			if i := strings.LastIndex(hostport, ":"); i >= 0 {
				host = hostport[:i]
			}
			// 读掉剩余请求头直到空行
			for {
				l, err := br.ReadString('\n')
				if err != nil || l == "\r\n" || l == "\n" {
					break
				}
			}
			mu.Lock()
			seen[host]++
			mu.Unlock()

			target := collAddr
			if host == proxyHost {
				target = ccAddr
			}
			up, err := net.Dial("tcp", target)
			if err != nil {
				_, _ = c.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
				return
			}
			defer up.Close()
			_, _ = c.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
			go func() { _, _ = io.Copy(up, br) }() // br: 含已缓冲的客户端字节 + 后续
			_, _ = io.Copy(c, up)
		}(c)
	}
}
