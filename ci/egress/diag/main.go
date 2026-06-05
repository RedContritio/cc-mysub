// diag: TLS-MITM 诊断收集器（仅 Phase 1 调查用，不入产品二进制）。
// 为每个 SNI 现签叶证书（由传入 CA 签，claude 经 NODE_EXTRA_CA_CERTS 信任该 CA），
// 终结 TLS，记录到达的 host/method/path 及 Authorization 是否存在（只看请求行+头，
// 不记 body），返回最小合法响应让 claude 不挂。用于刻画 claude 绕过 base_url 的
// 直连（如 api.anthropic.com）究竟打什么端点、是否携带凭据。
package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
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

func envOr(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}

func loadCA(certPath, keyPath string) (*x509.Certificate, *rsa.PrivateKey) {
	cb, err := os.ReadFile(certPath)
	must(err)
	kb, err := os.ReadFile(keyPath)
	must(err)
	cblock, _ := pem.Decode(cb)
	kblock, _ := pem.Decode(kb)
	cert, err := x509.ParseCertificate(cblock.Bytes)
	must(err)
	var key *rsa.PrivateKey
	if k, e := x509.ParsePKCS8PrivateKey(kblock.Bytes); e == nil {
		key = k.(*rsa.PrivateKey)
	} else if k, e := x509.ParsePKCS1PrivateKey(kblock.Bytes); e == nil {
		key = k
	} else {
		fmt.Fprintln(os.Stderr, "diag: cannot parse CA key")
		os.Exit(1)
	}
	return cert, key
}

func mintLeaf(name string, caCert *x509.Certificate, caKey *rsa.PrivateKey) *tls.Certificate {
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
	der, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, &key.PublicKey, caKey)
	must(err)
	return &tls.Certificate{Certificate: [][]byte{der, caCert.Raw}, PrivateKey: key}
}

func presence(s string) string {
	if s == "" {
		return "no"
	}
	return "yes"
}

func authState(a string) string {
	if a == "" {
		return "NONE"
	}
	if len(a) > 22 {
		return a[:22] + "…"
	}
	return a
}

func must(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, "diag:", err)
		os.Exit(1)
	}
}

type hit struct {
	count  int
	sample string
}

func main() {
	addr := envOr("DIAG_ADDR", "127.0.0.2:443")
	caCert, caKey := loadCA(os.Getenv("CA_CERT"), os.Getenv("CA_KEY"))

	var cmu sync.Mutex
	cache := map[string]*tls.Certificate{}
	getCert := func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
		name := hello.ServerName
		if name == "" {
			name = "unknown.invalid"
		}
		cmu.Lock()
		defer cmu.Unlock()
		if c, ok := cache[name]; ok {
			return c, nil
		}
		c := mintLeaf(name, caCert, caKey)
		cache[name] = c
		return c, nil
	}

	var hmu sync.Mutex
	hits := map[string]*hit{}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		key := fmt.Sprintf("%s %s %s", r.Host, r.Method, r.URL.Path)
		sample := fmt.Sprintf("auth=%s x-api-key=%s clen=%s",
			authState(r.Header.Get("Authorization")), presence(r.Header.Get("x-api-key")), r.Header.Get("Content-Length"))
		hmu.Lock()
		h := hits[key]
		if h == nil {
			h = &hit{}
			hits[key] = h
		}
		h.count++
		h.sample = sample
		hmu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{}`))
	})

	ln, err := net.Listen("tcp", addr)
	must(err)
	fmt.Fprintln(os.Stderr, "diag listening on", addr)

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sig
		hmu.Lock()
		defer hmu.Unlock()
		keys := make([]string, 0, len(hits))
		for k := range hits {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		fmt.Println("=== DIAG: direct hits (host method path) ===")
		for _, k := range keys {
			fmt.Printf("%-50s count=%d  %s\n", k, hits[k].count, hits[k].sample)
		}
		os.Exit(0)
	}()

	srv := &http.Server{Handler: handler, TLSConfig: &tls.Config{GetCertificate: getCert}}
	_ = srv.ServeTLS(ln, "", "")
}
