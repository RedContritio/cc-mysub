package mitm

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"
)

// genTestCA 生成自签名 ECDSA P-256 CA，返回 PEM 编码的证书和私钥字节。
// 作为包级 helper 供 Task 4 的 mint_test.go 复用。
func genTestCA(t *testing.T) (certPEM, keyPEM []byte) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "cc-mysub test CA"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		IsCA:         true,
		KeyUsage:     x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}

	// 自签名：template 同时作为 parent，公钥来自 key，签名者也是 key
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

// mintAndVerify 用已加载的 CA 实际签发一张叶证书并验链，证明 Signer 真正可用，
// 消除「仅断言 Signer != nil」的同义反复。
func mintAndVerify(t *testing.T, ca *CA) {
	t.Helper()
	m := NewMinter(ca, time.Hour)
	c, err := m.CertFor("verify.example")
	if err != nil {
		t.Fatalf("CertFor: %v", err)
	}
	leaf, err := x509.ParseCertificate(c.Certificate[0])
	if err != nil {
		t.Fatalf("parse leaf: %v", err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca.Cert)
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, DNSName: "verify.example"}); err != nil {
		t.Errorf("leaf signed by loaded CA failed to verify: %v", err)
	}
}

func TestLoadCA_SignsVerifiable(t *testing.T) {
	caPEM, keyPEM := genTestCA(t)
	ca, err := LoadCA(caPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	if !ca.Cert.IsCA {
		t.Error("not CA")
	}
	if ca.Signer == nil {
		t.Fatal("no signer")
	}
	// 真正用 EC SEC1 加载的 signer 签发并验链
	mintAndVerify(t, ca)
}

// TestLoadCA_MalformedCert 验证畸形 PEM 输入返回 error 而非 panic。
func TestLoadCA_MalformedCert(t *testing.T) {
	_, keyPEM := genTestCA(t)
	_, err := LoadCA([]byte("not-pem"), keyPEM)
	if err == nil {
		t.Error("expected error for malformed cert PEM, got nil")
	}
}

// TestLoadCA_MalformedKey 验证密钥 PEM 畸形时返回 error。
func TestLoadCA_MalformedKey(t *testing.T) {
	certPEM, _ := genTestCA(t)
	_, err := LoadCA(certPEM, []byte("not-pem"))
	if err == nil {
		t.Error("expected error for malformed key PEM, got nil")
	}
}

// TestLoadCA_PKCS8Key 验证 PKCS8 编码的 EC 私钥也能正常加载。
func TestLoadCA_PKCS8Key(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: "cc-mysub test CA pkcs8"},
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
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})

	// 用 PKCS8 编码密钥
	pkcs8DER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8DER})

	ca, err := LoadCA(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	if !ca.Cert.IsCA {
		t.Error("not CA")
	}
	if ca.Signer == nil {
		t.Fatal("no signer")
	}
	// 真正用 PKCS8 加载的 signer 签发并验链
	mintAndVerify(t, ca)
}

// TestLoadCA_BadDERKey 验证 PEM 头部合法但 DER 内容损坏时返回 error，
// 触达 EC SEC1 与 PKCS8 双解析失败的错误路径（含 %w 错误链）。
func TestLoadCA_BadDERKey(t *testing.T) {
	certPEM, _ := genTestCA(t)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: []byte("garbage-der")})
	if _, err := LoadCA(certPEM, keyPEM); err == nil {
		t.Error("expected error for corrupt DER key, got nil")
	}
}

// TestLoadCA_RejectsNonCACert 验证加载期 fail-fast：非 CA 证书（IsCA=false）须被拒绝。
func TestLoadCA_RejectsNonCACert(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(3),
		Subject:               pkix.Name{CommonName: "not-a-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  false,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	if _, err := LoadCA(certPEM, keyPEM); err == nil {
		t.Error("expected error loading non-CA cert, got nil")
	}
}
