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

// TestSplitter_DialTimeoutUnblocksBlackholeDial：黑洞拨号(honor ctx、永不连上)在 dialTimeout 后
// 被超时解除,handle 回 502 而非永久挂死——覆盖 chain(拨 host:443)与 direct(拨 target)两个拨号点。
// 无修复时 dial 用 context.Background() → `<-ctx.Done()` 永不返回 → 客户端读永久阻塞(测试超时失败)。
func TestSplitter_DialTimeoutUnblocksBlackholeDial(t *testing.T) {
	const serverName = "cc.example"
	_, caPool := selfSigned(t, serverName)
	// 黑洞拨号:遵守 ctx,直到 ctx 超时才返回(模拟 SYN 无响应的不可达目标)。
	dial := func(ctx context.Context, network, addr string) (net.Conn, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	sp := newTrusting(serverName, clientLeaf(t), caPool, nil, dial)
	sp.dialTimeout = 150 * time.Millisecond
	spLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer spLn.Close()
	go sp.Serve(spLn)

	for _, target := range []string{"api.anthropic.com:443" /*chain*/, "evil.example:443" /*direct*/} {
		t.Run(target, func(t *testing.T) {
			c, err := net.Dial("tcp", spLn.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			c.Write([]byte("CONNECT " + target + " HTTP/1.1\r\nHost: " + target + "\r\n\r\n"))
			_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
			br := bufio.NewReader(c)
			status, err := br.ReadString('\n')
			if err != nil {
				t.Fatalf("client read after blackhole dial: %v (dial 未设超时,handle 永久挂死?)", err)
			}
			if !strings.Contains(status, "502") {
				t.Errorf("黑洞拨号应回 502,得 %q", status)
			}
		})
	}
}

// TestSplitter_ChainSetupDeadlineUnblocksStalledServer：cc-mysub 完成 TCP+TLS 握手但永不回 CONNECT
// 200(established-but-idle 停滞),setupTimeout 后被超时解除,handle 回 502 而非永久挂死。无修复时
// `up.Handshake()`/`ubr.ReadString` 在 established TCP 上无 OS 级超时 → 永久阻塞、泄漏 goroutine/FD。
func TestSplitter_ChainSetupDeadlineUnblocksStalledServer(t *testing.T) {
	const serverName = "cc.example"
	cert, caPool := selfSigned(t, serverName)

	upLn, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}})
	if err != nil {
		t.Fatal(err)
	}
	defer upLn.Close()
	stall := make(chan struct{})
	defer close(stall)
	go func() {
		c, err := upLn.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		_, _, _ = readConnectBlock(c) // 驱动 TLS 握手 + 消费 CONNECT 块,然后停滞
		<-stall                       // 永不回 200(established-but-idle)
	}()

	dial := func(ctx context.Context, network, addr string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, upLn.Addr().String())
	}
	sp := newTrusting(serverName, clientLeaf(t), caPool, nil, dial)
	sp.setupTimeout = 200 * time.Millisecond
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
	_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
	br := bufio.NewReader(c)
	status, err := br.ReadString('\n')
	if err != nil {
		t.Fatalf("client read after stalled cc-mysub: %v (setup deadline 未解除挂起?)", err)
	}
	if !strings.Contains(status, "502") {
		t.Errorf("stalled cc-mysub 应回 502,得 %q", status)
	}
}

// TestSplitter_RelayIdleTimeoutRecoversSilentTunnel：隧道建立后双向静默,idleTimeout 后 relay 回收
// 并关闭连接(客户端读到 EOF/连接关闭,而非客户端自身的读 deadline 超时)。验证已建隧道不会永久占用
// goroutine/FD,与服务端 forward.go 的 idleTimeout 对称。
func TestSplitter_RelayIdleTimeoutRecoversSilentTunnel(t *testing.T) {
	const serverName = "cc.example"
	cert, caPool := selfSigned(t, serverName)

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
		if _, _, err := readConnectBlock(c); err != nil {
			return
		}
		c.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
		buf := make([]byte, 256) // 隧道建立后保持静默,等对端(splitter idle 回收)关闭
		for {
			if _, e := c.Read(buf); e != nil {
				return
			}
		}
	}()

	dial := func(ctx context.Context, network, addr string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, upLn.Addr().String())
	}
	sp := newTrusting(serverName, clientLeaf(t), caPool, nil, dial)
	sp.idleTimeout = 150 * time.Millisecond
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
	// 客户端自身设一个远大于 idleTimeout 的读 deadline,用以区分「idle 回收生效(EOF/连接关闭)」与
	//「回收未生效(读在客户端自身 deadline 上超时)」。
	_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
	br := bufio.NewReader(c)
	status, err := br.ReadString('\n')
	if err != nil || !strings.Contains(status, "200") {
		t.Fatalf("expected 200 Connection Established, got %q err=%v", status, err)
	}
	if _, err := br.ReadString('\n'); err != nil { // 读掉 200 后的空行,之后隧道内应无任何字节
		t.Fatalf("read blank line after 200: %v", err)
	}
	// 隧道已建立、双向静默:idle 回收应在 idleTimeout 后关闭连接,客户端读到 EOF/连接关闭。
	if _, err := br.Read(make([]byte, 64)); err == nil {
		t.Fatal("silent tunnel 未被 idle 回收(读到了数据?)")
	} else if ne, ok := err.(net.Error); ok && ne.Timeout() {
		t.Fatalf("idle 回收未触发:客户端读在自身 deadline 超时而非连接关闭: %v", err)
	}
}
