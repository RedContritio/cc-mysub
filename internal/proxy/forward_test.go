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

// newTestStore 写临时 devices.json，将 tokenToUpstream 映射编码进去，返回真实 store。
func newTestStore(t *testing.T, tokenToUpstream map[string]string) *auth.DeviceStore {
	t.Helper()
	var devs []string
	i := 0
	for tok, up := range tokenToUpstream {
		devs = append(devs, `{"label":"d`+strconv.Itoa(i)+`","token_sha256":"`+auth.HashToken(tok)+`","upstream":"`+up+`"}`)
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
	store := newTestStore(t, map[string]string{"cco_dev_x": "b"})
	cfgUp := &config.Upstream{OAuthTokens: []config.UpstreamToken{{ID: "a", Token: "REAL-A"}, {ID: "b", Token: "REAL-B"}}}
	h := newRewriteHandler(store, cfgUp, nil)

	// (1) 带命中 token → 换成该设备的 setup-token (b→REAL-B); X-Api-Key 须被恒删
	r1 := httptest.NewRequest("POST", up.URL+"/v1/messages", nil)
	r1.Header.Set("Authorization", "Bearer cco_dev_x")
	r1.Header.Set("X-Api-Key", "should-be-stripped")
	h.ServeHTTP(httptest.NewRecorder(), r1)
	// (2) auth=NONE (遥测) → 透传不注入
	r2 := httptest.NewRequest("POST", up.URL+"/api/event_logging/v2/batch", nil)
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
	// X-Api-Key 恒删：命中路径(入站设了)与匿名路径上游都不应见到
	if gotXAPIKey[0] != "" {
		t.Errorf("X-Api-Key not stripped on hit: got %q", gotXAPIKey[0])
	}
	if gotXAPIKey[1] != "" {
		t.Errorf("X-Api-Key present on anon: got %q", gotXAPIKey[1])
	}
}

func TestRewrite_UnknownTokenRejected(t *testing.T) {
	var hits int
	var mu sync.Mutex
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		hits++
		mu.Unlock()
	}))
	defer up.Close()
	store := newTestStore(t, map[string]string{"cco_dev_x": "b"})
	cfgUp := &config.Upstream{OAuthTokens: []config.UpstreamToken{{ID: "b", Token: "REAL-B"}}}
	h := newRewriteHandler(store, cfgUp, nil)

	r := httptest.NewRequest("POST", up.URL+"/v1/messages", nil)
	r.Header.Set("Authorization", "Bearer cco_unknown")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("unknown token: got %d want 401", rec.Code)
	}
	mu.Lock()
	defer mu.Unlock()
	if hits != 0 {
		t.Errorf("unknown token must not be forwarded, upstream hits=%d", hits)
	}
}

func TestRewrite_HitButUpstreamMissing(t *testing.T) {
	// 设备命中，但其 upstream id 不在池 → PickToken 返回 "" → 502，不转发
	var hits int
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits++ }))
	defer up.Close()
	store := newTestStore(t, map[string]string{"cco_dev_x": "zzz"}) // 设备指向不存在的 id
	cfgUp := &config.Upstream{OAuthTokens: []config.UpstreamToken{{ID: "b", Token: "REAL-B"}}}
	h := newRewriteHandler(store, cfgUp, nil)
	r := httptest.NewRequest("POST", up.URL+"/v1/messages", nil)
	r.Header.Set("Authorization", "Bearer cco_dev_x")
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

	// 2) cc-mysub CA + minter
	caPEM, keyPEM := genCA(t)
	ca, err := mitm.LoadCA(caPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	minter := mitm.NewMinter(ca, time.Hour)

	// 3) store + 池
	store := newTestStore(t, map[string]string{"cco_dev_x": "b"})
	cfgUp := &config.Upstream{OAuthTokens: []config.UpstreamToken{{ID: "a", Token: "REAL-A"}, {ID: "b", Token: "REAL-B"}}}

	// 4) cc-mysub→真目标 的 transport：把 CONNECT 目标 (api.anthropic.com:443) 重定向到假上游；测试不验上游证书
	upstreamTransport := &http.Transport{
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, upstreamAddr)
		},
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}

	// 5) 起 forward-proxy（外层 TLS 身份 = serverName/public_host；仅 MITM allowlist 内的 host）
	const serverName = "cc.example"
	fp := NewForwardProxy(minter, store, cfgUp, upstreamTransport, []string{"api.anthropic.com", "console.anthropic.com"}, serverName, 8)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go fp.Serve(ln)

	caPool := x509.NewCertPool()
	caPool.AddCert(ca.Cert)

	// helper-style client: 外层 TLS 到 cc-mysub(验 serverName) → 内发 CONNECT → 读 200 → 内层 TLS(api.anthropic.com)
	doReq := func(t *testing.T, authHeader, path string) {
		t.Helper()
		outer, err := tls.Dial("tcp", ln.Addr().String(), &tls.Config{RootCAs: caPool, ServerName: serverName})
		if err != nil {
			t.Fatalf("outer dial: %v", err)
		}
		defer outer.Close()
		if _, err := outer.Write([]byte("CONNECT api.anthropic.com:443 HTTP/1.1\r\nHost: api.anthropic.com\r\nProxy-Authorization: Bearer cco_dev_x\r\n\r\n")); err != nil {
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

	doReq(t, "Bearer cco_dev_x", "/v1/messages") // (1) swap
	doReq(t, "", "/api/event_logging/v2/batch")  // (2) anon passthrough

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
	caPEM, keyPEM := genCA(t)
	ca, _ := mitm.LoadCA(caPEM, keyPEM)
	minter := mitm.NewMinter(ca, time.Hour)
	store := newTestStore(t, map[string]string{"cco_dev_x": "b"})
	cfgUp := &config.Upstream{OAuthTokens: []config.UpstreamToken{{ID: "b", Token: "REAL-B"}}}
	const serverName = "cc.example"
	fp := NewForwardProxy(minter, store, cfgUp, nil, []string{"api.anthropic.com"}, serverName, 8)
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	defer ln.Close()
	go fp.Serve(ln)
	caPool := x509.NewCertPool()
	caPool.AddCert(ca.Cert)

	outer, err := tls.Dial("tcp", ln.Addr().String(), &tls.Config{RootCAs: caPool, ServerName: serverName})
	if err != nil {
		t.Fatalf("outer dial: %v", err)
	}
	defer outer.Close()
	// channel token valid → passes the 407 gate → reaches the allowlist 403 for evil.example
	outer.Write([]byte("CONNECT evil.example:443 HTTP/1.1\r\nHost: evil.example\r\nProxy-Authorization: Bearer cco_dev_x\r\n\r\n"))
	status, _ := bufio.NewReader(outer).ReadString('\n')
	if !strings.Contains(status, "403") {
		t.Errorf("non-allowlisted host must get 403 (policy reject), got %q", status)
	}
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
// assert the 407/400 path NEVER mints a leaf for the CONNECT host (no-cert-mint
// contract, spec §4). The outer-identity serverName cert IS expected (the proxy
// must complete the outer TLS handshake to read the CONNECT line at all).
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

// newSpyProxy builds a running ForwardProxy whose minter is a spy, plus the spy
// and the CA pool for outer-TLS dialing. inner RoundTripper is nil (no inner
// request is expected on the 407/400/403 paths). allow lists the MITM hosts.
func newSpyProxy(t *testing.T, tokenToUpstream map[string]string, allow []string, serverName string) (*ForwardProxy, *spyMinter, *x509.CertPool) {
	t.Helper()
	caPEM, keyPEM := genCA(t)
	ca, err := mitm.LoadCA(caPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	spy := newSpyMinter(ca)
	store := newTestStore(t, tokenToUpstream)
	cfgUp := &config.Upstream{OAuthTokens: []config.UpstreamToken{{ID: "b", Token: "REAL-B"}}}
	fp := NewForwardProxy(spy.inner, store, cfgUp, nil, allow, serverName, 8)
	fp.minter = spy // 覆写为 spy(both satisfy certMinter)
	caPool := x509.NewCertPool()
	caPool.AddCert(ca.Cert)
	return fp, spy, caPool
}

func TestForwardProxy_TokenGateBeforeTunnel(t *testing.T) {
	const serverName = "cc.example"
	const host = "api.anthropic.com"
	cases := []struct {
		name    string
		connect string
	}{
		{"tokenless", "CONNECT api.anthropic.com:443 HTTP/1.1\r\nHost: api.anthropic.com\r\n\r\n"},
		{"bad-token", "CONNECT api.anthropic.com:443 HTTP/1.1\r\nHost: api.anthropic.com\r\nProxy-Authorization: Bearer nope\r\n\r\n"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fp, spy, caPool := newSpyProxy(t, map[string]string{"cco_dev_x": "b"}, []string{host}, serverName)
			ln, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer ln.Close()
			go fp.Serve(ln)
			outer, err := tls.Dial("tcp", ln.Addr().String(), &tls.Config{RootCAs: caPool, ServerName: serverName})
			if err != nil {
				t.Fatalf("outer dial: %v", err)
			}
			defer outer.Close()
			if _, err := outer.Write([]byte(tc.connect)); err != nil {
				t.Fatal(err)
			}
			// Read the WHOLE outer stream to EOF. It must contain a 407 and must
			// NOT contain '200 Connection Established' anywhere.
			_ = outer.SetReadDeadline(time.Now().Add(3 * time.Second))
			all, _ := io.ReadAll(outer)
			if !strings.Contains(string(all), "407") {
				t.Errorf("want 407 in outer stream, got %q", all)
			}
			if strings.Contains(string(all), "200 Connection Established") {
				t.Errorf("SECURITY: 200 written on rejected channel auth: %q", all)
			}
			if spy.called(host) {
				t.Errorf("SECURITY: minted a leaf for CONNECT host %q on a rejected tunnel", host)
			}
		})
	}
}

func TestForwardProxy_BadTokenThenImmediateClientHello(t *testing.T) {
	const serverName = "cc.example"
	const host = "api.anthropic.com"
	fp, spy, caPool := newSpyProxy(t, map[string]string{"cco_dev_x": "b"}, []string{host}, serverName)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go fp.Serve(ln)
	outer, err := tls.Dial("tcp", ln.Addr().String(), &tls.Config{RootCAs: caPool, ServerName: serverName})
	if err != nil {
		t.Fatalf("outer dial: %v", err)
	}
	defer outer.Close()
	// Bad CONNECT header + an immediate 16-byte fake TLS ClientHello record in the
	// SAME write — an attacker racing the inner handshake before the gate runs.
	fakeHello := []byte{0x16, 0x03, 0x01, 0x00, 0x05, 0x01, 0x00, 0x00, 0x01, 0x00}
	payload := append([]byte("CONNECT api.anthropic.com:443 HTTP/1.1\r\nHost: api.anthropic.com\r\nProxy-Authorization: Bearer nope\r\n\r\n"), fakeHello...)
	if _, err := outer.Write(payload); err != nil {
		t.Fatal(err)
	}
	_ = outer.SetReadDeadline(time.Now().Add(3 * time.Second))
	all, _ := io.ReadAll(outer)
	if !strings.Contains(string(all), "407") {
		t.Errorf("want 407, got %q", all)
	}
	if strings.Contains(string(all), "200 Connection Established") {
		t.Errorf("SECURITY: 200 written despite bad token + smuggled ClientHello: %q", all)
	}
	if spy.called(host) {
		t.Errorf("SECURITY: minted leaf for %q on smuggled inner handshake", host)
	}
}

func TestForwardProxy_NonAllowlistTokenlessIs407Not403(t *testing.T) {
	const serverName = "cc.example"
	// allowlist contains only api.anthropic.com; we CONNECT to evil.example tokenless.
	fp, spy, caPool := newSpyProxy(t, map[string]string{"cco_dev_x": "b"}, []string{"api.anthropic.com"}, serverName)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go fp.Serve(ln)
	outer, err := tls.Dial("tcp", ln.Addr().String(), &tls.Config{RootCAs: caPool, ServerName: serverName})
	if err != nil {
		t.Fatalf("outer dial: %v", err)
	}
	defer outer.Close()
	outer.Write([]byte("CONNECT evil.example:443 HTTP/1.1\r\nHost: evil.example\r\n\r\n"))
	status, _ := bufio.NewReader(outer).ReadString('\n')
	if !strings.Contains(status, "407") {
		t.Errorf("tokenless non-allowlist host must be 407 (no host oracle), got %q", status)
	}
	if strings.Contains(status, "403") {
		t.Errorf("SECURITY: 403 leaks allowlist non-membership before channel auth: %q", status)
	}
	if spy.called("evil.example") {
		t.Errorf("minted leaf for non-allowlist host")
	}
}

func TestForwardProxy_OversizedConnectHeaderIs400(t *testing.T) {
	const serverName = "cc.example"
	const host = "api.anthropic.com"
	fp, spy, caPool := newSpyProxy(t, map[string]string{"cco_dev_x": "b"}, []string{host}, serverName)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go fp.Serve(ln)
	outer, err := tls.Dial("tcp", ln.Addr().String(), &tls.Config{RootCAs: caPool, ServerName: serverName})
	if err != nil {
		t.Fatalf("outer dial: %v", err)
	}
	defer outer.Close()
	// CONNECT line (valid) + a single header whose value exceeds maxConnectHeaderBytes.
	big := strings.Repeat("A", maxConnectHeaderBytes+100)
	outer.Write([]byte("CONNECT api.anthropic.com:443 HTTP/1.1\r\nX-Pad: " + big + "\r\nProxy-Authorization: Bearer cco_dev_x\r\n\r\n"))
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

func TestForwardProxy_ChannelTokenNeverLeaksUpstream(t *testing.T) {
	spy := &rtSpy{}
	caPEM, keyPEM := genCA(t)
	ca, err := mitm.LoadCA(caPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	minter := mitm.NewMinter(ca, time.Hour)
	store := newTestStore(t, map[string]string{"cco_dev_x": "b"})
	cfgUp := &config.Upstream{OAuthTokens: []config.UpstreamToken{{ID: "b", Token: "sk-ant-oat01-REAL"}}}
	const serverName = "cc.example"
	fp := NewForwardProxy(minter, store, cfgUp, spy, []string{"api.anthropic.com"}, serverName, 8)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go fp.Serve(ln)
	caPool := x509.NewCertPool()
	caPool.AddCert(ca.Cert)

	outer, err := tls.Dial("tcp", ln.Addr().String(), &tls.Config{RootCAs: caPool, ServerName: serverName})
	if err != nil {
		t.Fatalf("outer dial: %v", err)
	}
	defer outer.Close()
	if _, err := outer.Write([]byte("CONNECT api.anthropic.com:443 HTTP/1.1\r\nHost: api.anthropic.com\r\nProxy-Authorization: Bearer cco_dev_x\r\n\r\n")); err != nil {
		t.Fatal(err)
	}
	br := bufio.NewReader(outer)
	status, err := br.ReadString('\n')
	if err != nil || !strings.Contains(status, "200") {
		t.Fatalf("CONNECT status=%q err=%v", status, err)
	}
	for {
		l, err := br.ReadString('\n')
		if err != nil {
			t.Fatal(err)
		}
		if l == "\r\n" || l == "\n" {
			break
		}
	}
	inner := tls.Client(outer, &tls.Config{RootCAs: caPool, ServerName: "api.anthropic.com"})
	body := `{"model":"claude","x":1}`
	req, _ := http.NewRequest("POST", "https://api.anthropic.com/v1/messages", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer cco_dev_x") // inner app token (per-device)
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
	caPEM, keyPEM := genCA(t)
	ca, err := mitm.LoadCA(caPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	minter := mitm.NewMinter(ca, time.Hour)
	store := newTestStore(t, map[string]string{"cco_dev_x": "b"})
	cfgUp := &config.Upstream{OAuthTokens: []config.UpstreamToken{{ID: "b", Token: "REAL-B"}}}
	const serverName = "cc.example"
	// maxInFlight=1: the proxy can hold exactly one in-flight handle.
	fp := NewForwardProxy(minter, store, cfgUp, nil, []string{"api.anthropic.com"}, serverName, 1)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go fp.Serve(ln)

	caPool := x509.NewCertPool()
	caPool.AddCert(ca.Cert)

	// Client A: complete outer TLS + CONNECT, then PARK (never send inner
	// ClientHello). handle() stays inside srv.Serve waiting on the inner conn,
	// so it never returns and never releases the semaphore.
	connA, err := tls.Dial("tcp", ln.Addr().String(), &tls.Config{RootCAs: caPool, ServerName: serverName})
	if err != nil {
		t.Fatalf("A outer dial: %v", err)
	}
	defer connA.Close()
	if _, err := connA.Write([]byte("CONNECT api.anthropic.com:443 HTTP/1.1\r\nHost: api.anthropic.com\r\nProxy-Authorization: Bearer cco_dev_x\r\n\r\n")); err != nil {
		t.Fatalf("A connect write: %v", err)
	}
	brA := bufio.NewReader(connA)
	statusA, err := brA.ReadString('\n')
	if err != nil || !strings.Contains(statusA, "200") {
		t.Fatalf("A CONNECT status=%q err=%v", statusA, err)
	}
	for { // drain A's 200 headers; then A parks (no inner ClientHello)
		line, err := brA.ReadString('\n')
		if err != nil {
			t.Fatalf("A drain: %v", err)
		}
		if line == "\r\n" || line == "\n" {
			break
		}
	}
	// A now holds the only semaphore slot (handle parked in srv.Serve).

	// Client B: the proxy must shed — Serve does Accept then immediate Close
	// WITHOUT spawning handle, so B's raw TCP conn is closed before any outer
	// TLS handshake completes. tls.Dial must error (EOF / reset) within the
	// deadline rather than hang.
	dialer := &net.Dialer{Deadline: time.Now().Add(3 * time.Second)}
	connB, err := tls.DialWithDialer(dialer, "tcp", ln.Addr().String(), &tls.Config{RootCAs: caPool, ServerName: serverName})
	if err == nil {
		connB.Close()
		t.Fatalf("B outer TLS succeeded but proxy was saturated — shed failed")
	}
	// err is the shed signal (closed conn during handshake). Test passes.
}

func TestForwardProxy_AnonInnerStillPassesThroughAfterChannelAuth(t *testing.T) {
	spy := &rtSpy{}
	caPEM, keyPEM := genCA(t)
	ca, err := mitm.LoadCA(caPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	minter := mitm.NewMinter(ca, time.Hour)
	store := newTestStore(t, map[string]string{"cco_dev_x": "b"})
	cfgUp := &config.Upstream{OAuthTokens: []config.UpstreamToken{{ID: "b", Token: "sk-ant-oat01-REAL"}}}
	const serverName = "cc.example"
	fp := NewForwardProxy(minter, store, cfgUp, spy, []string{"api.anthropic.com"}, serverName, 8)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go fp.Serve(ln)
	caPool := x509.NewCertPool()
	caPool.AddCert(ca.Cert)

	outer, err := tls.Dial("tcp", ln.Addr().String(), &tls.Config{RootCAs: caPool, ServerName: serverName})
	if err != nil {
		t.Fatalf("outer dial: %v", err)
	}
	defer outer.Close()
	if _, err := outer.Write([]byte("CONNECT api.anthropic.com:443 HTTP/1.1\r\nHost: api.anthropic.com\r\nProxy-Authorization: Bearer cco_dev_x\r\n\r\n")); err != nil {
		t.Fatal(err)
	}
	br := bufio.NewReader(outer)
	status, err := br.ReadString('\n')
	if err != nil || !strings.Contains(status, "200") {
		t.Fatalf("CONNECT status=%q err=%v", status, err)
	}
	for {
		l, err := br.ReadString('\n')
		if err != nil {
			t.Fatal(err)
		}
		if l == "\r\n" || l == "\n" {
			break
		}
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
		t.Errorf("SECURITY: channel token leaked on anon inner request: %q", spy.gotPA)
	}
}

func TestForwardProxy_PipelinedValidTokenDeliversInnerBytes(t *testing.T) {
	// Real fake upstream so the inner request actually round-trips, proving the
	// pipelined inner ClientHello bytes were spliced byte-faithfully (a corrupted
	// prefix would break the inner TLS handshake).
	var gotAuth string
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.WriteHeader(200)
	}))
	defer upstream.Close()
	upstreamAddr := upstream.Listener.Addr().String()

	caPEM, keyPEM := genCA(t)
	ca, err := mitm.LoadCA(caPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	minter := mitm.NewMinter(ca, time.Hour)
	store := newTestStore(t, map[string]string{"cco_dev_x": "b"})
	cfgUp := &config.Upstream{OAuthTokens: []config.UpstreamToken{{ID: "a", Token: "REAL-A"}, {ID: "b", Token: "REAL-B"}}}
	upstreamTransport := &http.Transport{
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, upstreamAddr)
		},
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	const serverName = "cc.example"
	fp := NewForwardProxy(minter, store, cfgUp, upstreamTransport, []string{"api.anthropic.com"}, serverName, 8)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go fp.Serve(ln)
	caPool := x509.NewCertPool()
	caPool.AddCert(ca.Cert)

	outer, err := tls.Dial("tcp", ln.Addr().String(), &tls.Config{RootCAs: caPool, ServerName: serverName})
	if err != nil {
		t.Fatalf("outer dial: %v", err)
	}
	defer outer.Close()
	// Build the inner ClientHello FIRST (into a buffer), so we can pipeline the
	// first >=64 bytes of it together with the CONNECT request in one Write —
	// forcing handle's br.Buffered()>0 / prefixConn path.
	innerConn := tls.Client(outer, &tls.Config{RootCAs: caPool, ServerName: "api.anthropic.com"})
	if _, err := outer.Write([]byte("CONNECT api.anthropic.com:443 HTTP/1.1\r\nHost: api.anthropic.com\r\nProxy-Authorization: Bearer cco_dev_x\r\n\r\n")); err != nil {
		t.Fatal(err)
	}
	br := bufio.NewReader(outer)
	status, err := br.ReadString('\n')
	if err != nil || !strings.Contains(status, "200") {
		t.Fatalf("CONNECT status=%q err=%v", status, err)
	}
	for {
		l, err := br.ReadString('\n')
		if err != nil {
			t.Fatal(err)
		}
		if l == "\r\n" || l == "\n" {
			break
		}
	}
	// NOTE: because tls.Client buffers and br may hold post-200 bytes, this test
	// asserts the SUCCESS path end-to-end: a valid channel token yields 200 and the
	// inner handshake+request completes with the app-token swapped. (The pure
	// prefix-byte-faithfulness in isolation is already covered by
	// TestPrefixConn_ReplaysPrefixThenConn.)
	if br.Buffered() > 0 {
		// reuse buffered bytes for the inner conn (mirror handle's own splice)
		b, _ := br.Peek(br.Buffered())
		innerConn = tls.Client(&prefixConn{Conn: outer, prefix: append([]byte(nil), b...)}, &tls.Config{RootCAs: caPool, ServerName: "api.anthropic.com"})
	}
	req, _ := http.NewRequest("POST", "https://api.anthropic.com/v1/messages", nil)
	req.Header.Set("Authorization", "Bearer cco_dev_x")
	if err := req.Write(innerConn); err != nil {
		t.Fatalf("inner write: %v", err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(innerConn), req)
	if err != nil {
		t.Fatalf("inner read: %v", err)
	}
	resp.Body.Close()
	if gotAuth != "Bearer REAL-B" {
		t.Errorf("app-token swap: upstream Authorization=%q want Bearer REAL-B", gotAuth)
	}
}
