package mitm

import (
	"crypto/x509"
	"encoding/pem"
	"math/big"
	"testing"
	"time"
)

// parseCertSerial 解析 PEM 证书并返回其序列号，供唯一性断言使用。
func parseCertSerial(t *testing.T, certPEM []byte) *big.Int {
	t.Helper()
	blk, _ := pem.Decode(certPEM)
	if blk == nil {
		t.Fatal("decode cert PEM")
	}
	c, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		t.Fatalf("parse cert: %v", err)
	}
	return c.SerialNumber
}

// TestGenerateCA_RoundTripsAndMints 验证 GenerateCA 产出的 CA 能被 LoadCA 解析
// （LoadCA 已断言 IsCA），且其 Signer 真正可用：现签 api.anthropic.com 叶证书并验链。
func TestGenerateCA_RoundTripsAndMints(t *testing.T) {
	certPEM, keyPEM, err := GenerateCA("cc-mysub CA")
	if err != nil {
		t.Fatalf("GenerateCA: %v", err)
	}

	ca, err := LoadCA(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("LoadCA on generated CA: %v", err)
	}
	if !ca.Cert.IsCA {
		t.Error("generated cert is not a CA")
	}
	if ca.Cert.Subject.CommonName != "cc-mysub CA" {
		t.Errorf("CommonName = %q, want %q", ca.Cert.Subject.CommonName, "cc-mysub CA")
	}

	// 10 年有效期（容忍小时级抖动）。
	wantExpiry := time.Now().Add(10 * 365 * 24 * time.Hour)
	if diff := ca.Cert.NotAfter.Sub(wantExpiry); diff < -2*time.Hour || diff > 2*time.Hour {
		t.Errorf("NotAfter = %v, want ~%v", ca.Cert.NotAfter, wantExpiry)
	}

	// 现签一张叶证书并验链，证明这是个可用的 CA（不止断言 IsCA）。
	m := NewMinter(ca, time.Hour)
	c, err := m.CertFor("api.anthropic.com")
	if err != nil {
		t.Fatalf("CertFor: %v", err)
	}
	leaf, err := x509.ParseCertificate(c.Certificate[0])
	if err != nil {
		t.Fatalf("parse leaf: %v", err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca.Cert)
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, DNSName: "api.anthropic.com"}); err != nil {
		t.Errorf("leaf signed by generated CA failed to verify: %v", err)
	}
}

// TestGenerateCA_UniqueSerials 验证每次生成的序列号随机（不撞号）。
func TestGenerateCA_UniqueSerials(t *testing.T) {
	c1, _, err := GenerateCA("cc-mysub CA")
	if err != nil {
		t.Fatal(err)
	}
	c2, _, err := GenerateCA("cc-mysub CA")
	if err != nil {
		t.Fatal(err)
	}
	if parseCertSerial(t, c1).Cmp(parseCertSerial(t, c2)) == 0 {
		t.Error("two GenerateCA calls produced identical serial")
	}
}
