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
	fp := NewForwardProxy(minter, store, cfgUp, upstreamTransport, []string{"api.anthropic.com", "console.anthropic.com"}, serverName)
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
		if _, err := outer.Write([]byte("CONNECT api.anthropic.com:443 HTTP/1.1\r\nHost: api.anthropic.com\r\n\r\n")); err != nil {
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
	fp := NewForwardProxy(minter, store, cfgUp, nil, []string{"api.anthropic.com"}, serverName)
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
	outer.Write([]byte("CONNECT evil.example:443 HTTP/1.1\r\nHost: evil.example\r\n\r\n"))
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
