package splitter

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

// selfSigned 生成 name 的自签证书 + 信任它的 pool（用作假 cc-mysub 的外层身份）。
func selfSigned(t *testing.T, name string) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: name},
		DNSNames:     []string{name},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, _ := x509.ParseCertificate(der)
	pool := x509.NewCertPool()
	pool.AddCert(leaf)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}, pool
}

// readConnectHost 从 conn 读 "CONNECT host:port ..." 首行, 返回 host:port 部分。
func readConnectHost(t *testing.T, conn net.Conn) string {
	t.Helper()
	br := bufio.NewReader(conn)
	line, err := br.ReadString('\n')
	if err != nil {
		t.Fatalf("read CONNECT: %v", err)
	}
	fields := strings.Fields(line)
	if len(fields) < 2 {
		t.Fatalf("bad CONNECT line %q", line)
	}
	return fields[1]
}

func TestSplitter_RoutesAnthropicToUpstreamElseDirect(t *testing.T) {
	const serverName = "cc.example"
	cert, caPool := selfSigned(t, serverName)

	// 假 cc-mysub: 外层 TLS 监听, 记录收到的(链式)CONNECT 目标
	var upHosts []string
	var upMu sync.Mutex
	upLn, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}})
	if err != nil {
		t.Fatal(err)
	}
	defer upLn.Close()
	go func() {
		for {
			c, err := upLn.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				h := readConnectHost(t, c)
				upMu.Lock()
				upHosts = append(upHosts, h)
				upMu.Unlock()
				c.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
				// 读弃后续(claude 内层 TLS 字节), 直到关闭
				buf := make([]byte, 4096)
				for {
					if _, e := c.Read(buf); e != nil {
						return
					}
				}
			}(c)
		}
	}()

	// 假 direct: 纯 TCP, 记录被命中的目标
	directLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer directLn.Close()
	go func() {
		for {
			c, err := directLn.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 4096)
				for {
					if _, e := c.Read(buf); e != nil {
						return
					}
				}
			}(c)
		}
	}()

	// splitter: 白名单=api.anthropic.com; dial 注入把直连重定向到 directLn(记录命中)
	var directDialed []string
	var dMu sync.Mutex
	sp := New(upLn.Addr().String(), caPool, serverName, []string{"api.anthropic.com"},
		func(ctx context.Context, network, addr string) (net.Conn, error) {
			dMu.Lock()
			directDialed = append(directDialed, addr)
			dMu.Unlock()
			return (&net.Dialer{}).DialContext(ctx, network, directLn.Addr().String())
		})
	spLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer spLn.Close()
	go sp.Serve(spLn)

	// 客户端经 splitter
	connectVia := func(target string) {
		c, err := net.Dial("tcp", spLn.Addr().String())
		if err != nil {
			t.Fatalf("dial splitter: %v", err)
		}
		defer c.Close()
		c.Write([]byte("CONNECT " + target + " HTTP/1.1\r\nHost: " + target + "\r\n\r\n"))
		br := bufio.NewReader(c)
		status, _ := br.ReadString('\n')
		if !strings.Contains(status, "200") {
			t.Errorf("CONNECT %s: status %q", target, status)
		}
		time.Sleep(20 * time.Millisecond) // 让 relay 把链式 CONNECT 送达
	}
	connectVia("api.anthropic.com:443")
	connectVia("evil.example:443")
	time.Sleep(50 * time.Millisecond)

	upMu.Lock()
	defer upMu.Unlock()
	dMu.Lock()
	defer dMu.Unlock()
	if len(upHosts) != 1 || upHosts[0] != "api.anthropic.com:443" {
		t.Errorf("cc-mysub should see only api.anthropic.com:443, got %v", upHosts)
	}
	if len(directDialed) != 1 || directDialed[0] != "evil.example:443" {
		t.Errorf("direct path should dial only evil.example:443, got %v", directDialed)
	}
}
