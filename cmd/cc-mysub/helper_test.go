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

// TestProxyEnv 校验代理环境清理:残留的 NO_PROXY/任意大小写 *_proxy 被剔(防绕过 splitter),
// 权威大写值被设,非代理变量保留(codex 全仓审查 P2-5)。
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
	for _, kv := range proxyEnv(base, "http://127.0.0.1:9999") {
		k, v, _ := strings.Cut(kv, "=")
		m[k] = v
	}
	// NO_PROXY 剔除不重设(防直连豁免);小写代理变体剔除(改用权威大写)
	for _, k := range []string{"NO_PROXY", "no_proxy", "https_proxy", "http_proxy", "all_proxy"} {
		if _, ok := m[k]; ok {
			t.Errorf("%s 应被剔除,仍在(可绕过 splitter): %q", k, m[k])
		}
	}
	// 权威大写代理值已设,base 里的旧值(http://old / socks://old)被替换
	for _, k := range []string{"HTTPS_PROXY", "HTTP_PROXY", "ALL_PROXY"} {
		if m[k] != "http://127.0.0.1:9999" {
			t.Errorf("%s=%q want http://127.0.0.1:9999(旧值未替换?)", k, m[k])
		}
	}
	if m["NODE_USE_ENV_PROXY"] != "1" {
		t.Errorf("NODE_USE_ENV_PROXY=%q want 1", m["NODE_USE_ENV_PROXY"])
	}
	if m["PATH"] != "/usr/bin" || m["HOME"] != "/home/x" {
		t.Errorf("非代理变量丢失: PATH=%q HOME=%q", m["PATH"], m["HOME"])
	}
}
