package mitm

import (
	"crypto/tls"
	"crypto/x509"
	"sync"
	"testing"
	"time"
)

func TestMinter_SignsForHostChainsToCA_AndRejectsEmpty(t *testing.T) {
	caPEM, keyPEM := genTestCA(t)
	ca, err := LoadCA(caPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	m := NewMinter(ca, time.Hour)

	c, err := m.CertFor("api.anthropic.com")
	if err != nil {
		t.Fatal(err)
	}

	// 叶证书 SAN 必须含目标 host
	leaf, err := x509.ParseCertificate(c.Certificate[0])
	if err != nil {
		t.Fatalf("parse leaf: %v", err)
	}
	if err := leaf.VerifyHostname("api.anthropic.com"); err != nil {
		t.Errorf("SAN: %v", err)
	}

	// 叶证书必须能验证至 CA
	roots := x509.NewCertPool()
	roots.AddCert(ca.Cert)
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots}); err != nil {
		t.Errorf("chain: %v", err)
	}

	// 缓存命中：同一 host 返回同一 *tls.Certificate 指针
	c2, _ := m.CertFor("api.anthropic.com")
	if c != c2 {
		t.Error("cache miss for same host")
	}

	// 空 host 必须拒签
	if _, err := m.CertFor(""); err == nil {
		t.Error("empty host must error")
	}
}

func TestMinter_RemintAfterExpiry(t *testing.T) {
	caPEM, keyPEM := genTestCA(t)
	ca, err := LoadCA(caPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	m := NewMinter(ca, 10*time.Millisecond) // 短 TTL，余量足够大以抗时钟精度/调度抖动

	c1, _ := m.CertFor("x.example")
	time.Sleep(60 * time.Millisecond)
	// 缓存条目已过期 → 应重新签发（新指针）
	c2, _ := m.CertFor("x.example")
	if c1 == c2 {
		t.Error("expired cert not re-minted")
	}
}

// TestMinter_ConcurrentSafe 验证并发调用 CertFor 无数据竞争，
// 且多 goroutine 获取到的是同一个缓存指针。
func TestMinter_ConcurrentSafe(t *testing.T) {
	caPEM, keyPEM := genTestCA(t)
	ca, err := LoadCA(caPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	m := NewMinter(ca, time.Hour)

	const n = 50
	certs := make([]*tls.Certificate, n)
	errs := make([]error, n)

	var wg sync.WaitGroup
	wg.Add(n)
	for i := range n {
		go func() {
			defer wg.Done()
			c, err := m.CertFor("concurrent.example")
			certs[i] = c
			errs[i] = err
		}()
	}
	wg.Wait()

	for i := range n {
		if errs[i] != nil {
			t.Errorf("goroutine %d: %v", i, errs[i])
		}
	}

	// 所有返回值应为同一指针（缓存命中）
	first := certs[0]
	for i := 1; i < n; i++ {
		if certs[i] != first {
			t.Errorf("goroutine %d returned different pointer", i)
		}
	}
}
