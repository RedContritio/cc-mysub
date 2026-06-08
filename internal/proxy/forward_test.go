package proxy

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/redcontritio/cc-mysub/internal/auth"
	"github.com/redcontritio/cc-mysub/internal/config"
	"github.com/redcontritio/cc-mysub/internal/mitm"
)

// newTestStore 写临时 devices.json，将 fpToUpstream（客户端证书指纹 → upstream id）映射编码进去，
// 返回真实 store。设备身份现由外层 mTLS 客户端证书指纹确定，故键是 cert_sha256 而非 token hash。
func newTestStore(t *testing.T, fpToUpstream map[string]string) *auth.DeviceStore {
	t.Helper()
	var devs []string
	i := 0
	for fp, up := range fpToUpstream {
		devs = append(devs, `{"label":"d`+strconv.Itoa(i)+`","cert_sha256":"`+fp+`","upstream":"`+up+`"}`)
		i++
	}
	p := filepath.Join(t.TempDir(), "devices.json")
	if err := os.WriteFile(p, []byte("["+strings.Join(devs, ",")+"]"), 0o600); err != nil {
		t.Fatal(err)
	}
	s, err := auth.NewDeviceStore(p)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// newTestClientCert 自签一张 ECDSA P-256 client-leaf（IsCA=false，含私钥），供外层 mTLS 客户端出示。
// 其指纹 = auth.CertFingerprint(cert.Certificate[0])，须登记进 store 才能通过握手白名单。
func newTestClientCert(t *testing.T, cn string) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

func TestRewrite_Conditional(t *testing.T) {
	var gotAuth, gotXAPIKey []string
	var mu sync.Mutex
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		gotAuth = append(gotAuth, r.Header.Get("Authorization"))
		gotXAPIKey = append(gotXAPIKey, r.Header.Get("X-Api-Key"))
		mu.Unlock()
		w.WriteHeader(200)
	}))
	defer up.Close()
	cfgUp := &config.Upstream{OAuthTokens: []config.UpstreamToken{{ID: "a", Token: "REAL-A"}, {ID: "b", Token: "REAL-B"}}}
	h := newRewriteHandler(cfgUp, nil)
	dev := auth.Device{Label: "laptop", Upstream: "b"}

	// (1) 有入站凭据 + ctx 设备(upstream b) → 换成该设备的 setup-token (b→REAL-B); X-Api-Key 须被删
	r1 := httptest.NewRequest("POST", up.URL+"/v1/messages", nil)
	r1.Header.Set("Authorization", "Bearer placeholder")
	r1.Header.Set("X-Api-Key", "should-be-stripped")
	r1 = r1.WithContext(context.WithValue(r1.Context(), deviceKey, dev))
	h.ServeHTTP(httptest.NewRecorder(), r1)
	// (2) 无任何入站凭据 (真匿名遥测) → 透传不注入、不碰任何头
	r2 := httptest.NewRequest("POST", up.URL+"/api/event_logging/v2/batch", nil)
	r2 = r2.WithContext(context.WithValue(r2.Context(), deviceKey, dev))
	h.ServeHTTP(httptest.NewRecorder(), r2)

	mu.Lock()
	defer mu.Unlock()
	if len(gotAuth) != 2 {
		t.Fatalf("upstream got %d requests, want 2: %v", len(gotAuth), gotAuth)
	}
	if gotAuth[0] != "Bearer REAL-B" {
		t.Errorf("swap: got %q want Bearer REAL-B", gotAuth[0])
	}
	if gotAuth[1] != "" {
		t.Errorf("anon injected: got %q want empty", gotAuth[1])
	}
	// X-Api-Key：命中路径(入站设了)须被删；匿名路径上游不应见到(本就没设)
	if gotXAPIKey[0] != "" {
		t.Errorf("X-Api-Key not stripped on hit: got %q", gotXAPIKey[0])
	}
	if gotXAPIKey[1] != "" {
		t.Errorf("X-Api-Key present on anon: got %q", gotXAPIKey[1])
	}
}

func TestRewrite_HitButUpstreamMissing(t *testing.T) {
	// ctx 设备命中，但其 upstream id 不在池 → PickToken 返回 "" → 502，不转发
	var hits int
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits++ }))
	defer up.Close()
	cfgUp := &config.Upstream{OAuthTokens: []config.UpstreamToken{{ID: "b", Token: "REAL-B"}}}
	h := newRewriteHandler(cfgUp, nil)
	dev := auth.Device{Label: "laptop", Upstream: "zzz"} // 指向不存在的 id
	r := httptest.NewRequest("POST", up.URL+"/v1/messages", nil)
	r.Header.Set("Authorization", "Bearer placeholder")
	r = r.WithContext(context.WithValue(r.Context(), deviceKey, dev))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	if rec.Code != http.StatusBadGateway {
		t.Errorf("missing upstream token: got %d want 502", rec.Code)
	}
	if hits != 0 {
		t.Errorf("must not forward, upstream hits=%d", hits)
	}
}

// genCA generates a self-signed ECDSA P-256 CA, returns PEM cert+key (proxy 包自带，
// 因 mitm 包的 genTestCA 是测试私有不可跨包调用)。
func genCA(t *testing.T) (certPEM, keyPEM []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "cc-mysub test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	return certPEM, keyPEM
}

// newMTLSProxy 装配一个 ForwardProxy：外层 TLS 身份用 ocWriteSelfSigned 产的自签证书经
// NewOuterCertLoader 加载；内层 MITM 用 genCA 产的 CA → minter；store 由 fpToUpstream（客户端
// 证书指纹 → upstream id）构造。返回 proxy + 内层 CA 池（client 验内层 api.anthropic.com 叶证书用）。
func newMTLSProxy(t *testing.T, fpToUpstream map[string]string, cfgUp *config.Upstream, upstream http.RoundTripper, allow []string, maxInFlight int) (*ForwardProxy, *x509.CertPool) {
	t.Helper()
	caPEM, keyPEM := genCA(t)
	ca, err := mitm.LoadCA(caPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	minter := mitm.NewMinter(ca, time.Hour)
	store := newTestStore(t, fpToUpstream)
	dir := t.TempDir()
	cp, kp := ocWriteSelfSigned(t, dir, "cc.example")
	fp := NewForwardProxy(minter, store, cfgUp, upstream, allow, NewOuterCertLoader(cp, kp), maxInFlight)
	caPool := x509.NewCertPool()
	caPool.AddCert(ca.Cert)
	return fp, caPool
}

// serveProxy 在 127.0.0.1:0 起监听并后台 Serve，返回地址；listener 在测试结束时关闭。
func serveProxy(t *testing.T, fp *ForwardProxy) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go fp.Serve(ln)
	return ln.Addr().String()
}

// outerDial 拨外层 mTLS：自签外层证书故 InsecureSkipVerify，但必须出示一张已登记指纹的
// client cert（否则 RequireAnyClientCert / VerifyPeerCertificate 令握手失败）。
func outerDial(t *testing.T, addr string, clientCert tls.Certificate) *tls.Conn {
	t.Helper()
	c, err := tls.Dial("tcp", addr, &tls.Config{InsecureSkipVerify: true, Certificates: []tls.Certificate{clientCert}})
	if err != nil {
		t.Fatalf("outer dial: %v", err)
	}
	return c
}

// connect200 在已建立的外层连接上发一条 CONNECT（不带 Proxy-Authorization，身份已由 mTLS 证书确定），
// 读到 200 状态行 + 头到空行，返回 bufio.Reader。状态非 200 即 Fatal。
func connect200(t *testing.T, outer net.Conn, host string) *bufio.Reader {
	t.Helper()
	if _, err := outer.Write([]byte("CONNECT " + host + ":443 HTTP/1.1\r\nHost: " + host + "\r\n\r\n")); err != nil {
		t.Fatal(err)
	}
	br := bufio.NewReader(outer)
	status, err := br.ReadString('\n')
	if err != nil || !strings.Contains(status, "200") {
		t.Fatalf("CONNECT status=%q err=%v", status, err)
	}
	for { // drain to blank line
		line, err := br.ReadString('\n')
		if err != nil {
			t.Fatal(err)
		}
		if line == "\r\n" || line == "\n" {
			break
		}
	}
	return br
}

func TestForwardProxy_EndToEnd(t *testing.T) {
	// 1) 假真上游 (TLS)，记录每个请求的 Authorization
	var gotAuth []string
	var mu sync.Mutex
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		gotAuth = append(gotAuth, r.Header.Get("Authorization"))
		mu.Unlock()
		w.WriteHeader(200)
	}))
	defer upstream.Close()
	upstreamAddr := upstream.Listener.Addr().String()

	// cc-mysub→真目标 的 transport：把 CONNECT 目标 (api.anthropic.com:443) 重定向到假上游；测试不验上游证书
	upstreamTransport := &http.Transport{
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, upstreamAddr)
		},
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}

	clientCert := newTestClientCert(t, "device-leaf")
	cfp := auth.CertFingerprint(clientCert.Certificate[0])
	cfgUp := &config.Upstream{OAuthTokens: []config.UpstreamToken{{ID: "a", Token: "REAL-A"}, {ID: "b", Token: "REAL-B"}}}
	fp, caPool := newMTLSProxy(t, map[string]string{cfp: "b"}, cfgUp, upstreamTransport, []string{"api.anthropic.com", "console.anthropic.com"}, 8)
	addr := serveProxy(t, fp)

	// helper-style client: 外层 mTLS 到 cc-mysub(出示已登记 client cert) → CONNECT(无 Proxy-Auth) → 200 → 内层 TLS
	doReq := func(t *testing.T, authHeader, path string) {
		t.Helper()
		outer := outerDial(t, addr, clientCert)
		defer outer.Close()
		br := connect200(t, outer, "api.anthropic.com")
		// 此处 br.Buffered() 应为 0(服务端在 200 后等内层 ClientHello)；直接在 outer 上跑内层 TLS
		if n := br.Buffered(); n != 0 {
			t.Fatalf("unexpected %d buffered bytes after CONNECT 200", n)
		}
		inner := tls.Client(outer, &tls.Config{RootCAs: caPool, ServerName: "api.anthropic.com"})
		req, _ := http.NewRequest("POST", "https://api.anthropic.com"+path, nil)
		if authHeader != "" {
			req.Header.Set("Authorization", authHeader)
		}
		if err := req.Write(inner); err != nil {
			t.Fatalf("write req: %v", err)
		}
		resp, err := http.ReadResponse(bufio.NewReader(inner), req)
		if err != nil {
			t.Fatalf("read resp: %v", err)
		}
		resp.Body.Close()
	}

	doReq(t, "Bearer placeholder", "/v1/messages") // (1) swap
	doReq(t, "", "/api/event_logging/v2/batch")    // (2) anon passthrough

	mu.Lock()
	defer mu.Unlock()
	if len(gotAuth) != 2 {
		t.Fatalf("upstream got %d requests, want 2: %v", len(gotAuth), gotAuth)
	}
	if gotAuth[0] != "Bearer REAL-B" {
		t.Errorf("swap: got %q want Bearer REAL-B", gotAuth[0])
	}
	if gotAuth[1] != "" {
		t.Errorf("anon: got %q want empty", gotAuth[1])
	}
}

func TestForwardProxy_AllowlistRejectsNonAnthropic(t *testing.T) {
	clientCert := newTestClientCert(t, "device-leaf")
	cfp := auth.CertFingerprint(clientCert.Certificate[0])
	cfgUp := &config.Upstream{OAuthTokens: []config.UpstreamToken{{ID: "b", Token: "REAL-B"}}}
	fp, _ := newMTLSProxy(t, map[string]string{cfp: "b"}, cfgUp, nil, []string{"api.anthropic.com"}, 8)
	addr := serveProxy(t, fp)

	outer := outerDial(t, addr, clientCert)
	defer outer.Close()
	// 外层 mTLS 通过(已登记证书) → CONNECT 非白名单 host → allowlist 403
	outer.Write([]byte("CONNECT evil.example:443 HTTP/1.1\r\nHost: evil.example\r\n\r\n"))
	status, _ := bufio.NewReader(outer).ReadString('\n')
	if !strings.Contains(status, "403") {
		t.Errorf("non-allowlisted host must get 403 (policy reject), got %q", status)
	}
}

// assertOuterRejected dials the outer TLS endpoint with cfg and asserts the mTLS
// handshake is rejected — zero application bytes get through. Under TLS 1.3 a client-
// auth failure is not reported by tls.Dial (the client "completes" its handshake before
// the server's alert arrives); the rejection surfaces only on the first Read. So when
// the dial itself succeeds we write a CONNECT and read: a rejected connection yields a
// read error with NO HTTP response, whereas an (erroneously) accepted one would reply.
func assertOuterRejected(t *testing.T, addr string, cfg *tls.Config) {
	t.Helper()
	c, err := tls.Dial("tcp", addr, cfg)
	if err != nil {
		return // rejected during the handshake itself
	}
	defer c.Close()
	_, _ = c.Write([]byte("CONNECT api.anthropic.com:443 HTTP/1.1\r\nHost: api.anthropic.com\r\n\r\n"))
	_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 64)
	n, rerr := c.Read(buf)
	if rerr == nil {
		t.Fatalf("SECURITY: outer mTLS handshake accepted; server replied %q", buf[:n])
	}
}

// TestForwardProxy_NoClientCertHandshakeFails：外层 dial 不出示 client cert →
// RequireAnyClientCert 令握手失败，零应用字节。
func TestForwardProxy_NoClientCertHandshakeFails(t *testing.T) {
	clientCert := newTestClientCert(t, "device-leaf")
	cfp := auth.CertFingerprint(clientCert.Certificate[0])
	cfgUp := &config.Upstream{OAuthTokens: []config.UpstreamToken{{ID: "b", Token: "REAL-B"}}}
	fp, _ := newMTLSProxy(t, map[string]string{cfp: "b"}, cfgUp, nil, []string{"api.anthropic.com"}, 8)
	addr := serveProxy(t, fp)

	assertOuterRejected(t, addr, &tls.Config{InsecureSkipVerify: true})
}

// TestForwardProxy_UnregisteredClientCertHandshakeFails：出示一张指纹未登记的 client cert →
// VerifyPeerCertificate 返回 error，握手失败、零应用字节。
func TestForwardProxy_UnregisteredClientCertHandshakeFails(t *testing.T) {
	registered := newTestClientCert(t, "device-leaf")
	rfp := auth.CertFingerprint(registered.Certificate[0])
	cfgUp := &config.Upstream{OAuthTokens: []config.UpstreamToken{{ID: "b", Token: "REAL-B"}}}
	fp, _ := newMTLSProxy(t, map[string]string{rfp: "b"}, cfgUp, nil, []string{"api.anthropic.com"}, 8)
	addr := serveProxy(t, fp)

	stranger := newTestClientCert(t, "stranger") // 指纹不在 store
	assertOuterRejected(t, addr, &tls.Config{InsecureSkipVerify: true, Certificates: []tls.Certificate{stranger}})
}

// TestPrefixConn_ReplaysPrefixThenConn 确定性验证 prefixConn 先回放 prefix 再读底层 conn，
// 字节顺序无丢失/错位（handle 流水线分支的握手关键路径，整跳难以确定性触发故单测此逻辑）。
func TestPrefixConn_ReplaysPrefixThenConn(t *testing.T) {
	c1, c2 := net.Pipe()
	defer c1.Close()
	go func() {
		c2.Write([]byte("WORLD"))
		c2.Close()
	}()
	pc := &prefixConn{Conn: c1, prefix: []byte("HELLO")}
	got, err := io.ReadAll(pc)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "HELLOWORLD" {
		t.Errorf("prefixConn replay: got %q want HELLOWORLD", got)
	}
}

// spyMinter wraps a real *mitm.Minter, recording every CertFor host. Lets tests
// assert the 400 path NEVER mints a leaf for the CONNECT host (no-cert-mint
// contract, spec §4): the 400 is written before the inner leaf is minted.
type spyMinter struct {
	inner *mitm.Minter
	mu    sync.Mutex
	hosts []string
}

func newSpyMinter(ca *mitm.CA) *spyMinter {
	return &spyMinter{inner: mitm.NewMinter(ca, time.Hour)}
}

func (s *spyMinter) CertFor(host string) (*tls.Certificate, error) {
	s.mu.Lock()
	s.hosts = append(s.hosts, host)
	s.mu.Unlock()
	return s.inner.CertFor(host)
}

func (s *spyMinter) called(host string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, h := range s.hosts {
		if h == host {
			return true
		}
	}
	return false
}

// newSpyProxy builds a running-ready ForwardProxy whose minter is a spy, plus the spy
// and a registered client cert for outer-mTLS dialing. inner RoundTripper is nil (no
// inner request is expected on the 400/403 paths). allow lists the MITM hosts.
func newSpyProxy(t *testing.T, allow []string) (*ForwardProxy, *spyMinter, tls.Certificate) {
	t.Helper()
	caPEM, keyPEM := genCA(t)
	ca, err := mitm.LoadCA(caPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	spy := newSpyMinter(ca)
	clientCert := newTestClientCert(t, "device-leaf")
	cfp := auth.CertFingerprint(clientCert.Certificate[0])
	store := newTestStore(t, map[string]string{cfp: "b"})
	cfgUp := &config.Upstream{OAuthTokens: []config.UpstreamToken{{ID: "b", Token: "REAL-B"}}}
	dir := t.TempDir()
	cp, kp := ocWriteSelfSigned(t, dir, "cc.example")
	fp := NewForwardProxy(spy.inner, store, cfgUp, nil, allow, NewOuterCertLoader(cp, kp), 8)
	fp.minter = spy // 覆写为 spy(both satisfy certMinter)
	return fp, spy, clientCert
}

func TestForwardProxy_OversizedConnectHeaderIs400(t *testing.T) {
	const host = "api.anthropic.com"
	fp, spy, clientCert := newSpyProxy(t, []string{host})
	addr := serveProxy(t, fp)
	outer := outerDial(t, addr, clientCert)
	defer outer.Close()
	// CONNECT line (valid) + a single header whose value exceeds maxConnectHeaderBytes.
	big := strings.Repeat("A", maxConnectHeaderBytes+100)
	outer.Write([]byte("CONNECT api.anthropic.com:443 HTTP/1.1\r\nX-Pad: " + big + "\r\n\r\n"))
	_ = outer.SetReadDeadline(time.Now().Add(3 * time.Second))
	all, _ := io.ReadAll(outer)
	if !strings.Contains(string(all), "400") {
		t.Errorf("oversized pre-200 header must be 400, got %q", all)
	}
	if strings.Contains(string(all), "200 Connection Established") {
		t.Errorf("SECURITY: 200 on oversized header: %q", all)
	}
	if spy.called(host) {
		t.Errorf("minted leaf despite oversized header reject")
	}
}

// rtSpy captures the exact outbound upstream request (headers + body) for leak-up
// assertions, then returns a canned 200.
type rtSpy struct {
	mu      sync.Mutex
	gotPA   string
	gotAuth string
	gotBody []byte
}

func (s *rtSpy) RoundTrip(req *http.Request) (*http.Response, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.gotPA = req.Header.Get("Proxy-Authorization")
	s.gotAuth = req.Header.Get("Authorization")
	if req.Body != nil {
		s.gotBody, _ = io.ReadAll(req.Body)
		req.Body.Close()
	}
	return &http.Response{
		StatusCode: 200,
		Body:       io.NopCloser(strings.NewReader("{}")),
		Header:     make(http.Header),
		Proto:      "HTTP/1.1", ProtoMajor: 1, ProtoMinor: 1,
		Request: req,
	}, nil
}

// TestForwardProxy_InnerSwapNoProxyAuthBodyIntact：外层 mTLS(已登记证书) + CONNECT(无 Proxy-Auth)，
// 内层带凭据 → 上游 Proxy-Authorization 空、Authorization 换成 Bearer 真 token、body 逐字节一致。
func TestForwardProxy_InnerSwapNoProxyAuthBodyIntact(t *testing.T) {
	spy := &rtSpy{}
	clientCert := newTestClientCert(t, "device-leaf")
	cfp := auth.CertFingerprint(clientCert.Certificate[0])
	cfgUp := &config.Upstream{OAuthTokens: []config.UpstreamToken{{ID: "b", Token: "sk-ant-oat01-REAL"}}}
	fp, caPool := newMTLSProxy(t, map[string]string{cfp: "b"}, cfgUp, spy, []string{"api.anthropic.com"}, 8)
	addr := serveProxy(t, fp)

	outer := outerDial(t, addr, clientCert)
	defer outer.Close()
	br := connect200(t, outer, "api.anthropic.com")
	if n := br.Buffered(); n != 0 {
		t.Fatalf("unexpected %d buffered bytes after CONNECT 200", n)
	}
	inner := tls.Client(outer, &tls.Config{RootCAs: caPool, ServerName: "api.anthropic.com"})
	body := `{"model":"claude","x":1}`
	req, _ := http.NewRequest("POST", "https://api.anthropic.com/v1/messages", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer placeholder") // inner inbound credential
	if err := req.Write(inner); err != nil {
		t.Fatalf("inner write: %v", err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(inner), req)
	if err != nil {
		t.Fatalf("inner read: %v", err)
	}
	resp.Body.Close()

	spy.mu.Lock()
	defer spy.mu.Unlock()
	if spy.gotPA != "" {
		t.Errorf("SECURITY: Proxy-Authorization leaked upstream: %q", spy.gotPA)
	}
	if spy.gotAuth != "Bearer sk-ant-oat01-REAL" {
		t.Errorf("upstream Authorization=%q want Bearer sk-ant-oat01-REAL", spy.gotAuth)
	}
	if string(spy.gotBody) != body {
		t.Errorf("body not byte-identical: got %q want %q", spy.gotBody, body)
	}
}

func TestForwardProxy_ShedsWhenSaturated(t *testing.T) {
	clientCert := newTestClientCert(t, "device-leaf")
	cfp := auth.CertFingerprint(clientCert.Certificate[0])
	cfgUp := &config.Upstream{OAuthTokens: []config.UpstreamToken{{ID: "b", Token: "REAL-B"}}}
	// maxInFlight=1: the proxy can hold exactly one in-flight handle.
	fp, _ := newMTLSProxy(t, map[string]string{cfp: "b"}, cfgUp, nil, []string{"api.anthropic.com"}, 1)
	addr := serveProxy(t, fp)

	// Client A: complete outer mTLS + CONNECT, then PARK (never send inner
	// ClientHello). handle() stays inside srv.Serve waiting on the inner conn,
	// so it never returns and never releases the semaphore.
	connA := outerDial(t, addr, clientCert)
	defer connA.Close()
	_ = connect200(t, connA, "api.anthropic.com")
	// A now holds the only semaphore slot (handle parked in srv.Serve).

	// Client B: the proxy must shed — Serve does Accept then immediate Close
	// WITHOUT spawning handle, so B's raw TCP conn is closed before any outer
	// TLS handshake completes. B presents the SAME registered cert, proving the
	// shed is the semaphore cap (not a cert rejection). tls.Dial must error
	// within the deadline rather than hang.
	dialer := &net.Dialer{Deadline: time.Now().Add(3 * time.Second)}
	connB, err := tls.DialWithDialer(dialer, "tcp", addr, &tls.Config{InsecureSkipVerify: true, Certificates: []tls.Certificate{clientCert}})
	if err == nil {
		connB.Close()
		t.Fatalf("B outer TLS succeeded but proxy was saturated — shed failed")
	}
	// err is the shed signal (closed conn during handshake). Test passes.
}

// TestForwardProxy_AnonInnerPassesThrough：外层 mTLS(已登记证书) + CONNECT(无 Proxy-Auth)，
// 内层无凭据(匿名遥测) → 上游 Authorization 空、无 Proxy-Authorization(零注入)。
func TestForwardProxy_AnonInnerPassesThrough(t *testing.T) {
	spy := &rtSpy{}
	clientCert := newTestClientCert(t, "device-leaf")
	cfp := auth.CertFingerprint(clientCert.Certificate[0])
	cfgUp := &config.Upstream{OAuthTokens: []config.UpstreamToken{{ID: "b", Token: "sk-ant-oat01-REAL"}}}
	fp, caPool := newMTLSProxy(t, map[string]string{cfp: "b"}, cfgUp, spy, []string{"api.anthropic.com"}, 8)
	addr := serveProxy(t, fp)

	outer := outerDial(t, addr, clientCert)
	defer outer.Close()
	br := connect200(t, outer, "api.anthropic.com")
	if n := br.Buffered(); n != 0 {
		t.Fatalf("unexpected %d buffered bytes after CONNECT 200", n)
	}
	inner := tls.Client(outer, &tls.Config{RootCAs: caPool, ServerName: "api.anthropic.com"})
	// Inner request with NO Authorization (anonymous telemetry).
	req, _ := http.NewRequest("POST", "https://api.anthropic.com/api/event_logging/v2/batch", nil)
	if err := req.Write(inner); err != nil {
		t.Fatalf("inner write: %v", err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(inner), req)
	if err != nil {
		t.Fatalf("inner read: %v", err)
	}
	resp.Body.Close()

	spy.mu.Lock()
	defer spy.mu.Unlock()
	if spy.gotAuth != "" {
		t.Errorf("anon passthrough broken: upstream Authorization=%q want empty (no real-token injection)", spy.gotAuth)
	}
	if spy.gotPA != "" {
		t.Errorf("SECURITY: Proxy-Authorization present on anon inner request: %q", spy.gotPA)
	}
}

func TestForwardProxy_PipelinedValidTokenDeliversInnerBytes(t *testing.T) {
	// Real fake upstream so the inner request actually round-trips, proving the
	// pipelined inner ClientHello bytes were spliced byte-faithfully (a corrupted
	// prefix would break the inner TLS handshake).
	var gotAuth string
	var mu sync.Mutex
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		gotAuth = r.Header.Get("Authorization")
		mu.Unlock()
		w.WriteHeader(200)
	}))
	defer upstream.Close()
	upstreamAddr := upstream.Listener.Addr().String()

	clientCert := newTestClientCert(t, "device-leaf")
	cfp := auth.CertFingerprint(clientCert.Certificate[0])
	cfgUp := &config.Upstream{OAuthTokens: []config.UpstreamToken{{ID: "a", Token: "REAL-A"}, {ID: "b", Token: "REAL-B"}}}
	upstreamTransport := &http.Transport{
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, upstreamAddr)
		},
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	fp, caPool := newMTLSProxy(t, map[string]string{cfp: "b"}, cfgUp, upstreamTransport, []string{"api.anthropic.com"}, 8)
	addr := serveProxy(t, fp)

	outer := outerDial(t, addr, clientCert)
	defer outer.Close()
	// Lazily build the inner conn; if any post-200 bytes ended up buffered (pipelined
	// inner ClientHello), splice them back via prefixConn — mirroring handle's own splice.
	innerConn := tls.Client(outer, &tls.Config{RootCAs: caPool, ServerName: "api.anthropic.com"})
	br := connect200(t, outer, "api.anthropic.com")
	if br.Buffered() > 0 {
		b, _ := br.Peek(br.Buffered())
		innerConn = tls.Client(&prefixConn{Conn: outer, prefix: append([]byte(nil), b...)}, &tls.Config{RootCAs: caPool, ServerName: "api.anthropic.com"})
	}
	req, _ := http.NewRequest("POST", "https://api.anthropic.com/v1/messages", nil)
	req.Header.Set("Authorization", "Bearer placeholder")
	if err := req.Write(innerConn); err != nil {
		t.Fatalf("inner write: %v", err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(innerConn), req)
	if err != nil {
		t.Fatalf("inner read: %v", err)
	}
	resp.Body.Close()
	mu.Lock()
	defer mu.Unlock()
	if gotAuth != "Bearer REAL-B" {
		t.Errorf("app-token swap: upstream Authorization=%q want Bearer REAL-B", gotAuth)
	}
}
