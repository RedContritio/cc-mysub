package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sort"
	"sync"
	"syscall"
	"time"
)

// mock 同时充当 v4 两跳审计里的「B = 统一出口」:
//   - 经 TLS 的 GetCertificate 回调枚举每个到达连接的 SNI（= B 收到哪些 host），不论握手是否完成。
//   - SNI=api.anthropic.com（cc-mysub MITM 换 token 后再发起的转发）→ 返回 audit-CA 签的 api 叶,
//     TLS 终结后由 mux 记录 Authorization（验证换 token）。
//   - 其余 SNI（datadog/downloads 等透传 host，claude/curl 与 B 端到端做 TLS）→ 现签自签叶;
//     只需记 SNI,客户端是否接受该叶无所谓。
//
// SIGINT 时同时 dump Authorization 列表与 SNI inventory。
func main() {
	addr := "127.0.0.1:9443"
	if a := os.Getenv("MOCK_ADDR"); a != "" {
		addr = a
	}
	rec := &Recorder{}

	// SNI inventory:每个 ClientHello 的 server_name 计数(= 到达 B 的 host 集合)。
	var smu sync.Mutex
	sni := map[string]int{}

	dumpAndExit := func() {
		auths := rec.Auths()
		sort.Strings(auths)
		fmt.Println("=== MOCK AUTHORIZATIONS (deduped) ===")
		last := ""
		for _, a := range auths {
			if a != last {
				fmt.Println(a)
				last = a
			}
		}
		smu.Lock()
		hosts := make([]string, 0, len(sni))
		for h := range sni {
			hosts = append(hosts, h)
		}
		smu.Unlock()
		sort.Strings(hosts)
		fmt.Println("=== B EGRESS SNI INVENTORY ===")
		for _, h := range hosts {
			fmt.Printf("%-44s count=%d\n", h, sni[h])
		}
		os.Exit(0)
	}
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	go func() { <-sig; dumpAndExit() }()

	// api 叶(audit-CA 签):cc-mysub 经 http.DefaultTransport 验系统信任,故 api.anthropic.com
	// 转发须见到这张系统信任的叶,换 token 链才走得通。未设则退回纯 HTTP(无 SNI inventory)。
	certFile, keyFile := os.Getenv("MOCK_TLS_CERT"), os.Getenv("MOCK_TLS_KEY")
	if certFile == "" || keyFile == "" {
		fmt.Fprintln(os.Stderr, "mock listening on", addr, "(HTTP, no SNI inventory)")
		if err := http.ListenAndServe(addr, newMux(rec)); err != nil {
			fmt.Fprintln(os.Stderr, "mock:", err)
			os.Exit(1)
		}
		return
	}
	apiLeaf, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		fmt.Fprintln(os.Stderr, "mock: load api leaf:", err)
		os.Exit(1)
	}

	var lmu sync.Mutex
	leafCache := map[string]*tls.Certificate{}
	getCert := func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
		name := hello.ServerName
		if name == "" {
			name = "unknown-sni"
		}
		smu.Lock()
		sni[name]++
		smu.Unlock()
		if name == "api.anthropic.com" {
			return &apiLeaf, nil
		}
		lmu.Lock()
		defer lmu.Unlock()
		if c, ok := leafCache[name]; ok {
			return c, nil
		}
		c := mintSelfSigned(name)
		leafCache[name] = c
		return c, nil
	}

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		fmt.Fprintln(os.Stderr, "mock listen:", err)
		os.Exit(1)
	}
	srv := &http.Server{Handler: newMux(rec), TLSConfig: &tls.Config{GetCertificate: getCert}}
	fmt.Fprintln(os.Stderr, "mock(B) listening on", addr, "(TLS + SNI inventory)")
	if err := srv.ServeTLS(ln, "", ""); err != nil {
		fmt.Fprintln(os.Stderr, "mock:", err)
		os.Exit(1)
	}
}

// mintSelfSigned 为透传 host 现签一张自签叶(仅为让 GetCertificate 有返回值;客户端是否接受无所谓,
// SNI 已在回调里记录)。
func mintSelfSigned(name string) *tls.Certificate {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: name},
		DNSNames:     []string{name},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	return &tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}
