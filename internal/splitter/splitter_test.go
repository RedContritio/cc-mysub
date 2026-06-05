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
	"fmt"
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
// 出错返回 ("", err)，调用方负责处理——不在此处调用 t.Fatal，以便在 goroutine 中安全使用。
func readConnectHost(conn net.Conn) (string, error) {
	br := bufio.NewReader(conn)
	line, err := br.ReadString('\n')
	if err != nil {
		return "", fmt.Errorf("read CONNECT: %w", err)
	}
	fields := strings.Fields(line)
	if len(fields) < 2 {
		return "", fmt.Errorf("bad CONNECT line %q", line)
	}
	return fields[1], nil
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
				h, err := readConnectHost(c)
				if err != nil {
					t.Errorf("readConnectHost: %v", err)
					return
				}
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
	sp, err := New(upLn.Addr().String(), caPool, chTok, serverName, []string{"api.anthropic.com"},
		func(ctx context.Context, network, addr string) (net.Conn, error) {
			dMu.Lock()
			directDialed = append(directDialed, addr)
			dMu.Unlock()
			return (&net.Dialer{}).DialContext(ctx, network, directLn.Addr().String())
		})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
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

const chTok = "cco_dev_abc123"

// readConnectBlock reads the CONNECT request line + all header lines up to the
// blank line, returning the raw header lines (without the request line).
// 出错返回 ("", nil, err)，调用方负责处理——不在此处调用 t.Fatal，以便在 goroutine 中安全使用。
func readConnectBlock(conn net.Conn) (reqLine string, headers []string, err error) {
	br := bufio.NewReader(conn)
	line, err := br.ReadString('\n')
	if err != nil {
		return "", nil, fmt.Errorf("read CONNECT line: %w", err)
	}
	reqLine = line
	for {
		h, err := br.ReadString('\n')
		if err != nil {
			return "", nil, fmt.Errorf("read header: %w", err)
		}
		if h == "\r\n" || h == "\n" {
			break
		}
		headers = append(headers, h)
	}
	return reqLine, headers, nil
}

func TestSplitter_EmitsChannelTokenOnAllowBranch(t *testing.T) {
	const serverName = "cc.example"
	cert, caPool := selfSigned(t, serverName)

	var gotReq string
	var gotHeaders []string
	var mu sync.Mutex
	upLn, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}})
	if err != nil {
		t.Fatal(err)
	}
	defer upLn.Close()
	go func() {
		c, err := upLn.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		req, hs, err := readConnectBlock(c)
		if err != nil {
			t.Errorf("readConnectBlock: %v", err)
			return
		}
		mu.Lock()
		gotReq, gotHeaders = req, hs
		mu.Unlock()
		c.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
		buf := make([]byte, 4096)
		for {
			if _, e := c.Read(buf); e != nil {
				return
			}
		}
	}()

	sp, err := New(upLn.Addr().String(), caPool, chTok, serverName, []string{"api.anthropic.com"}, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	spLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer spLn.Close()
	go sp.Serve(spLn)

	c, err := net.Dial("tcp", spLn.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.Write([]byte("CONNECT api.anthropic.com:443 HTTP/1.1\r\nHost: api.anthropic.com:443\r\n\r\n"))
	br := bufio.NewReader(c)
	status, _ := br.ReadString('\n')
	if !strings.Contains(status, "200") {
		t.Fatalf("client status %q", status)
	}
	time.Sleep(50 * time.Millisecond)

	mu.Lock()
	defer mu.Unlock()
	// exactly one Proxy-Authorization header line, value = Bearer <chTok>
	var paCount int
	for _, h := range gotHeaders {
		name := strings.SplitN(h, ":", 2)[0]
		if strings.EqualFold(strings.TrimSpace(name), "Proxy-Authorization") {
			paCount++
			if strings.TrimSpace(h) != "Proxy-Authorization: Bearer "+chTok {
				t.Errorf("Proxy-Authorization line = %q, want Bearer %s", h, chTok)
			}
		}
	}
	if paCount != 1 {
		t.Errorf("Proxy-Authorization header count = %d, want 1 (headers=%v)", paCount, gotHeaders)
	}
	// token must appear NOWHERE else (not in request line, not in any other header)
	if strings.Contains(gotReq, chTok) {
		t.Errorf("token leaked into CONNECT request line %q", gotReq)
	}
	for _, h := range gotHeaders {
		name := strings.SplitN(h, ":", 2)[0]
		if !strings.EqualFold(strings.TrimSpace(name), "Proxy-Authorization") && strings.Contains(h, chTok) {
			t.Errorf("token leaked into header %q", h)
		}
	}
}

func TestSplitter_DirectBranchHasNoProxyAuth(t *testing.T) {
	cert, caPool := selfSigned(t, "cc.example")
	_ = cert // upstream not exercised on direct path

	// fake direct target: read everything the splitter forwards after its 200.
	directLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer directLn.Close()
	gotCh := make(chan string, 1)
	go func() {
		c, err := directLn.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		// the splitter relays claude's raw bytes; we only sent a CONNECT block from
		// the test client, so read it and check no Proxy-Authorization is present.
		buf := make([]byte, 4096)
		n, _ := c.Read(buf)
		gotCh <- string(buf[:n])
	}()

	sp, err := New("127.0.0.1:9", caPool, chTok, "cc.example", []string{"api.anthropic.com"},
		func(ctx context.Context, network, addr string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, directLn.Addr().String())
		})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	spLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer spLn.Close()
	go sp.Serve(spLn)

	c, err := net.Dial("tcp", spLn.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.Write([]byte("CONNECT evil.example:443 HTTP/1.1\r\nHost: evil.example:443\r\n\r\n"))
	br := bufio.NewReader(c)
	status, _ := br.ReadString('\n')
	if !strings.Contains(status, "200") {
		t.Fatalf("client status %q", status)
	}
	// after 200 the splitter blind-relays; push a probe so the direct target's Read returns.
	c.Write([]byte("probe-inner-bytes"))

	select {
	case forwarded := <-gotCh:
		if strings.Contains(forwarded, "Proxy-Authorization") {
			t.Errorf("direct branch leaked Proxy-Authorization: %q", forwarded)
		}
		if strings.Contains(forwarded, chTok) {
			t.Errorf("direct branch leaked channel token: %q", forwarded)
		}
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for direct-branch forwarded bytes")
	}
}

func TestSplitter_NewRejectsBadChannelToken(t *testing.T) {
	_, caPool := selfSigned(t, "cc.example")
	for _, bad := range []string{
		"tok\r\nInjected: x", // CRLF injection
		"tok\nx",             // bare LF
		"tok\rx",             // bare CR
		"tok with space",     // space (0x20, not VCHAR)
		"tok\tx",             // tab (control <0x21)
		"tok\x00x",           // NUL
		"tok\x7fx",           // DEL (0x7f)
		"",                   // empty: must be rejected (emits empty Bearer value)
		"tok\x80x",           // non-ASCII (0x80): malforms HTTP header line
		"tok\xc3\xa9x",       // multi-byte UTF-8 (é): non-ASCII via clipboard paste
	} {
		_, err := New("127.0.0.1:9", caPool, bad, "cc.example", []string{"api.anthropic.com"}, nil)
		if err == nil {
			t.Errorf("New(%q): want error, got nil", bad)
		}
	}
	// a clean token must still construct
	if _, err := New("127.0.0.1:9", caPool, "cco_dev_clean", "cc.example", nil, nil); err != nil {
		t.Errorf("New(clean token): unexpected error %v", err)
	}
}
