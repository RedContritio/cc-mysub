package proxy

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
	"testing"
	"time"
)

// ocWriteSelfSigned 写一对自签 ECDSA cert/key 到 dir，返回路径（外层证书加载器测试用）。
func ocWriteSelfSigned(t *testing.T, dir, cn string) (certPath, keyPath string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		DNSNames:     []string{cn},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certPath = filepath.Join(dir, "c.crt")
	keyPath = filepath.Join(dir, "c.key")
	cb, _ := os.Create(certPath)
	_ = pem.Encode(cb, &pem.Block{Type: "CERTIFICATE", Bytes: der})
	cb.Close()
	kd, _ := x509.MarshalECPrivateKey(key)
	kb, _ := os.Create(keyPath)
	_ = pem.Encode(kb, &pem.Block{Type: "EC PRIVATE KEY", Bytes: kd})
	kb.Close()
	return
}

func TestOuterCertLoader_LoadsAndReloadsOnMtime(t *testing.T) {
	dir := t.TempDir()
	cp, kp := ocWriteSelfSigned(t, dir, "first.example")
	get := NewOuterCertLoader(cp, kp)

	c1, err := get(nil)
	if err != nil {
		t.Fatal(err)
	}
	leaf, _ := x509.ParseCertificate(c1.Certificate[0])
	if leaf.Subject.CommonName != "first.example" {
		t.Fatalf("cn=%s want first.example", leaf.Subject.CommonName)
	}

	// 模拟续期：用新 CN 的 cert/key 覆盖原文件，前移 mtime 确保被检测。
	dir2 := t.TempDir()
	cp2, kp2 := ocWriteSelfSigned(t, dir2, "renewed.example")
	ocCopy(t, cp2, cp)
	ocCopy(t, kp2, kp)
	future := time.Now().Add(time.Hour)
	if err := os.Chtimes(cp, future, future); err != nil {
		t.Fatal(err)
	}

	c2, err := get(nil)
	if err != nil {
		t.Fatal(err)
	}
	leaf2, _ := x509.ParseCertificate(c2.Certificate[0])
	if leaf2.Subject.CommonName != "renewed.example" {
		t.Fatalf("reload failed, cn=%s want renewed.example", leaf2.Subject.CommonName)
	}
}

func ocCopy(t *testing.T, src, dst string) {
	t.Helper()
	b, err := os.ReadFile(src)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dst, b, 0o644); err != nil {
		t.Fatal(err)
	}
}
