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
	"testing"
	"time"
)

func writeTestCA(t *testing.T) string {
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
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	p := filepath.Join(t.TempDir(), "ca.crt")
	if err := os.WriteFile(p, pemBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestHelper_InjectsProxyAndRunsChild(t *testing.T) {
	// 设置合法 token：validChannelToken 现在拒绝空串（防止 Bearer 空值 → 407）
	t.Setenv("CLAUDE_CODE_OAUTH_TOKEN", "test_token_abc123")
	caPath := writeTestCA(t)
	outPath := filepath.Join(t.TempDir(), "env.out")
	code := runHelper([]string{
		"--upstream", "127.0.0.1:9", // 不会被本测试真正拨号（child 只 echo env）
		"--ca", caPath,
		"--server-name", "cc.example",
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
