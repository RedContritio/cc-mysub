package splitter

import (
	"bufio"
	"bytes"
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

// selfSigned 生成 name 的自签服务端证书 + 信任它的 pool（用作假 cc-mysub 的外层 LE 身份）。
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

// clientLeaf 生成本设备自签客户端证书（splitter 外层 mTLS 出示）。
func clientLeaf(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "test-device"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, _ := x509.ParseCertificate(der)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}
}

// newTrusting 构造 splitter 并白盒注入测试 CA pool（生产走系统信任验真 LE；测试用自签需注入）。
func newTrusting(host string, clientCert tls.Certificate, caPool *x509.CertPool, extraAllow []string, dial dialFunc) *Splitter {
	sp := New(host, clientCert, extraAllow, dial)
	sp.tlsCfg.RootCAs = caPool
	return sp
}

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
					return
				}
				upMu.Lock()
				upHosts = append(upHosts, h)
				upMu.Unlock()
				c.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
				buf := make([]byte, 4096)
				for {
					if _, e := c.Read(buf); e != nil {
						return
					}
				}
			}(c)
		}
	}()

	// 假 direct: 纯 TCP
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

	// dial 注入: host:443(allow 分支)→ upLn; 其余(direct 分支)→ directLn 并记录。
	var directDialed []string
	var dMu sync.Mutex
	dial := func(ctx context.Context, network, addr string) (net.Conn, error) {
		if addr == net.JoinHostPort(serverName, "443") {
			return (&net.Dialer{}).DialContext(ctx, network, upLn.Addr().String())
		}
		dMu.Lock()
		directDialed = append(directDialed, addr)
		dMu.Unlock()
		return (&net.Dialer{}).DialContext(ctx, network, directLn.Addr().String())
	}
	sp := newTrusting(serverName, clientLeaf(t), caPool, nil, dial)
	spLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer spLn.Close()
	go sp.Serve(spLn)

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
		time.Sleep(20 * time.Millisecond)
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

func TestSplitter_AllowBranchPresentsClientCertNoProxyAuth(t *testing.T) {
	const serverName = "cc.example"
	cert, caPool := selfSigned(t, serverName)
	myCert := clientLeaf(t)

	var gotReq string
	var gotHeaders []string
	var gotPeer [][]byte // 服务端看到的客户端证书 DER
	var mu sync.Mutex
	// 假 cc-mysub 要求客户端证书(mTLS)，捕获 CONNECT 块 + peer 证书。
	upLn, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.RequireAnyClientCert,
	})
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
		req, hs, err := readConnectBlock(c) // 触发握手
		if err != nil {
			return
		}
		mu.Lock()
		gotReq, gotHeaders = req, hs
		if tc, ok := c.(*tls.Conn); ok {
			for _, pc := range tc.ConnectionState().PeerCertificates {
				gotPeer = append(gotPeer, pc.Raw)
			}
		}
		mu.Unlock()
		c.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
		buf := make([]byte, 4096)
		for {
			if _, e := c.Read(buf); e != nil {
				return
			}
		}
	}()

	dial := func(ctx context.Context, network, addr string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, upLn.Addr().String())
	}
	sp := newTrusting(serverName, myCert, caPool, nil, dial)
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
	// 链式 CONNECT 不得带任何 Proxy-Authorization（身份由客户端证书承载）。
	for _, h := range gotHeaders {
		if strings.Contains(strings.ToLower(h), "proxy-authorization") {
			t.Errorf("chained CONNECT must not carry Proxy-Authorization, got header %q", h)
		}
	}
	if strings.Contains(strings.ToLower(gotReq), "proxy-authorization") {
		t.Errorf("Proxy-Authorization in request line %q", gotReq)
	}
	// 服务端必须看到 splitter 出示的客户端证书（指纹匹配）。
	if len(gotPeer) == 0 {
		t.Fatal("upstream saw no client certificate (mTLS not presented)")
	}
	if !bytes.Equal(gotPeer[0], myCert.Certificate[0]) {
		t.Error("upstream peer cert != splitter client cert")
	}
}

func TestSplitter_DirectBranchHasNoProxyAuth(t *testing.T) {
	cert, caPool := selfSigned(t, "cc.example")
	_ = cert

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
		buf := make([]byte, 4096)
		n, _ := c.Read(buf)
		gotCh <- string(buf[:n])
	}()

	dial := func(ctx context.Context, network, addr string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, directLn.Addr().String())
	}
	sp := newTrusting("cc.example", clientLeaf(t), caPool, nil, dial)
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
	c.Write([]byte("probe-inner-bytes"))

	select {
	case forwarded := <-gotCh:
		if strings.Contains(strings.ToLower(forwarded), "proxy-authorization") {
			t.Errorf("direct branch leaked Proxy-Authorization: %q", forwarded)
		}
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for direct-branch forwarded bytes")
	}
}

// TestSplitter_ExtraAllowForceChains：--allow 把一个不在 hosts.Classify 收口集的 host
// （rogue.example→Direct）强制 chain 到 cc-mysub（设备侧 override）。证明 extraAllow 生效——
// 它走 chain 分支（拨 serverName:443）而非 direct 分支。cc-mysub 端是否放行是其 allowlist 的事
// （非清单 host 仍 403，见 proxy 测试与 stage_split Probe D）。
func TestSplitter_ExtraAllowForceChains(t *testing.T) {
	const serverName = "cc.example"
	cert, caPool := selfSigned(t, serverName)

	var upHost string
	gotCh := make(chan string, 1)
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
		h, err := readConnectHost(c)
		if err != nil {
			return
		}
		c.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
		gotCh <- h
		buf := make([]byte, 256)
		for {
			if _, e := c.Read(buf); e != nil {
				return
			}
		}
	}()

	directLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer directLn.Close()

	// dial 按 addr 分流：chain 分支拨 serverName:443→upLn；direct 分支拨 target→directLn。
	dial := func(ctx context.Context, network, addr string) (net.Conn, error) {
		if addr == net.JoinHostPort(serverName, "443") {
			return (&net.Dialer{}).DialContext(ctx, network, upLn.Addr().String())
		}
		return (&net.Dialer{}).DialContext(ctx, network, directLn.Addr().String())
	}
	sp := newTrusting(serverName, clientLeaf(t), caPool, []string{"rogue.example"}, dial)
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
	c.Write([]byte("CONNECT rogue.example:443 HTTP/1.1\r\nHost: rogue.example:443\r\n\r\n"))
	br := bufio.NewReader(c)
	status, _ := br.ReadString('\n')
	if !strings.Contains(status, "200") {
		t.Fatalf("client status %q", status)
	}

	select {
	case upHost = <-gotCh:
		if upHost != "rogue.example:443" {
			t.Errorf("cc-mysub should see force-chained rogue.example:443, got %q", upHost)
		}
	case <-time.After(time.Second):
		t.Fatal("timeout: --allow host was not chained to cc-mysub (extraAllow ignored?)")
	}
}
