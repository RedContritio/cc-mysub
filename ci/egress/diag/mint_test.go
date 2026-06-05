package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"
)

// 验证 mintLeaf 现签的叶证书确实由给定 CA 签发、可被 CA 校验通过、且 SAN 含请求的 SNI。
func TestMintLeaf_ChainsToCA(t *testing.T) {
	caKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test-CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCert, _ := x509.ParseCertificate(caDER)

	leaf := mintLeaf("api.anthropic.com", caCert, caKey)
	leafCert, err := x509.ParseCertificate(leaf.Certificate[0])
	if err != nil {
		t.Fatalf("parse leaf: %v", err)
	}
	if err := leafCert.VerifyHostname("api.anthropic.com"); err != nil {
		t.Errorf("leaf SAN missing requested SNI: %v", err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(caCert)
	if _, err := leafCert.Verify(x509.VerifyOptions{Roots: roots}); err != nil {
		t.Errorf("leaf does not chain to CA: %v", err)
	}
}
