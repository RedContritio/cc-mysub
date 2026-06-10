package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

// writeTestDeviceCert 写一对自签客户端证书+私钥到临时目录，返回路径（helper 外层 mTLS 出示用）。
func writeTestDeviceCert(t *testing.T) (certPath, keyPath string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
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
	dir := t.TempDir()
	certPath = filepath.Join(dir, "device.crt")
	keyPath = filepath.Join(dir, "device.key")
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644); err != nil {
		t.Fatal(err)
	}
	keyDER, _ := x509.MarshalECPrivateKey(key)
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	return
}

func TestHelper_MissingClientCertFailsFast(t *testing.T) {
	// 缺 --client-cert/--client-key → fail-closed（提示先跑 device-init）。
	code := runHelper([]string{
		"--host", "cc.example",
		"--",
		"/bin/sh", "-c", "true",
	})
	if code != 2 {
		t.Fatalf("runHelper without --client-cert exit = %d, want 2", code)
	}
}

func TestHelper_BadClientCertFailsFast(t *testing.T) {
	// --client-cert/--client-key 指向不存在文件 → fail-closed。
	code := runHelper([]string{
		"--host", "cc.example",
		"--client-cert", filepath.Join(t.TempDir(), "nope.crt"),
		"--client-key", filepath.Join(t.TempDir(), "nope.key"),
		"--",
		"/bin/sh", "-c", "true",
	})
	if code != 2 {
		t.Fatalf("runHelper with missing cert files exit = %d, want 2", code)
	}
}

func TestHelper_InjectsProxyAndRunsChild(t *testing.T) {
	certPath, keyPath := writeTestDeviceCert(t)
	outPath := filepath.Join(t.TempDir(), "env.out")
	code := runHelper([]string{
		"--host", "cc.example", // 不会被本测试真正拨号（child 只 echo env）
		"--client-cert", certPath,
		"--client-key", keyPath,
		"--",
		"/bin/sh", "-c", `printf '%s|%s' "$HTTPS_PROXY" "$NODE_USE_ENV_PROXY" > ` + outPath,
	})
	if code != 0 {
		t.Fatalf("runHelper exit code = %d, want 0", code)
	}
	got, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatal(err)
	}
	re := regexp.MustCompile(`^http://127\.0\.0\.1:\d+\|1$`)
	if !re.Match(got) {
		t.Errorf("child env = %q, want HTTPS_PROXY=http://127.0.0.1:<port> and NODE_USE_ENV_PROXY=1", got)
	}
}

// TestProxyEnv 校验代理环境清理:残留的 NO_PROXY/任意大小写 *_proxy 全被剔(防绕过 splitter),
// 只注入 HTTPS_PROXY(splitter 只支持 CONNECT;HTTP_PROXY/ALL_PROXY 指向它会让 plain-HTTP 400,
// 故不注入、让 plain-HTTP 本地直连,id 49),非代理变量保留(codex 全仓审查 P2-5)。
func TestProxyEnv(t *testing.T) {
	base := []string{
		"PATH=/usr/bin",
		"NO_PROXY=anthropic.com",
		"no_proxy=claude.ai",
		"HTTPS_PROXY=http://old",
		"https_proxy=http://old2",
		"http_proxy=http://old3",
		"ALL_PROXY=socks://old",
		"HOME=/home/x",
	}
	m := map[string]string{}
	present := map[string]bool{}
	for _, kv := range proxyEnv(base, "http://127.0.0.1:9999") {
		k, v, _ := strings.Cut(kv, "=")
		m[k] = v
		present[k] = true
	}
	// 全部继承的代理变体被剔(NO_PROXY 防直连豁免;小写变体防绕过;HTTP_PROXY/ALL_PROXY 不再注入)。
	for _, k := range []string{"NO_PROXY", "no_proxy", "https_proxy", "http_proxy", "all_proxy"} {
		if _, ok := m[k]; ok {
			t.Errorf("%s 应被剔除,仍在(可绕过 splitter): %q", k, m[k])
		}
	}
	// HTTPS_PROXY 注入权威值,base 里的旧值(http://old)被替换。
	if m["HTTPS_PROXY"] != "http://127.0.0.1:9999" {
		t.Errorf("HTTPS_PROXY=%q want http://127.0.0.1:9999(旧值未替换?)", m["HTTPS_PROXY"])
	}
	// HTTP_PROXY/ALL_PROXY 不注入(否则 plain-HTTP 经 CONNECT-only splitter 必 400,id 49):
	// 继承的 HTTP_PROXY=http://old3 / ALL_PROXY=socks://old 被剔且不重设。
	for _, k := range []string{"HTTP_PROXY", "ALL_PROXY"} {
		if present[k] {
			t.Errorf("%s 不应被注入(plain-HTTP 须本地直连,非走 CONNECT-only splitter): %q", k, m[k])
		}
	}
	if m["NODE_USE_ENV_PROXY"] != "1" {
		t.Errorf("NODE_USE_ENV_PROXY=%q want 1", m["NODE_USE_ENV_PROXY"])
	}
	if m["PATH"] != "/usr/bin" || m["HOME"] != "/home/x" {
		t.Errorf("非代理变量丢失: PATH=%q HOME=%q", m["PATH"], m["HOME"])
	}
}

// TestParseAllow 守 id 18：--allow 条目按 connect.ParseConnect 同款规范化(TrimSpace+ToLower+剥尾点)
// 后才存入 extra map,与 splitter 的规范化查找一致;非法条目 loud-fail 而非静默 no-op。
func TestParseAllow(t *testing.T) {
	okCases := []struct {
		name string
		csv  string
		want []string
	}{
		{"empty→nil", "", nil},
		{"uppercase→lower", "Mcp.Notion.So", []string{"mcp.notion.so"}},
		{"space-padded trimmed", "a.com, b.com", []string{"a.com", "b.com"}},
		{"trailing dot stripped", "foo.example.", []string{"foo.example"}},
		{"mixed normalization", " Foo.Example. ", []string{"foo.example"}},
		{"empty segments skipped", "a.com,,b.com,", []string{"a.com", "b.com"}},
		{"ip literal", "10.0.0.1", []string{"10.0.0.1"}},
	}
	for _, c := range okCases {
		t.Run(c.name, func(t *testing.T) {
			got, err := parseAllow(c.csv)
			if err != nil {
				t.Fatalf("parseAllow(%q) unexpected err: %v", c.csv, err)
			}
			if len(got) != len(c.want) {
				t.Fatalf("parseAllow(%q)=%v want %v", c.csv, got, c.want)
			}
			for i := range got {
				if got[i] != c.want[i] {
					t.Fatalf("parseAllow(%q)=%v want %v", c.csv, got, c.want)
				}
			}
		})
	}

	// 非法条目(端口/通配/非法字符/空格内嵌)必须 loud-fail,而非静默落回直连。
	badCases := []struct {
		name string
		csv  string
	}{
		{"port not allowed", "foo.example:443"},
		{"wildcard not allowed", "*.anthropic.com"},
		{"embedded space invalid", "a.com,bad host"},
		{"illegal char", "foo_bar!.com"},
	}
	for _, c := range badCases {
		t.Run(c.name, func(t *testing.T) {
			if got, err := parseAllow(c.csv); err == nil {
				t.Fatalf("parseAllow(%q) expected error, got %v", c.csv, got)
			}
		})
	}
}
