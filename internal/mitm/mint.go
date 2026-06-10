package mitm

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"sync"
	"time"
)

// clockSkewMargin 是叶证书有效期在两端预留的时钟偏差裕量。
//
// 缓存窗口为 [mint, mint+ttl)（由 entry.expiry 钉死），设备时钟相对服务端可有分钟级漂移
// （休眠后恢复的 VM/容器、无 NTP 的机器都是常见场景）。若裕量过窄，缓存窗口内会周期性出现
// "certificate is not yet valid"（设备落后）或 "certificate has expired"（设备超前）的内层
// 握手失败，且随每个重签周期复现。两端对称预留同一裕量，与缓存 TTL 解耦：
//
//	NotBefore = now - clockSkewMargin        // 设备落后时窗口起点仍判已生效
//	NotAfter  = now + ttl + clockSkewMargin  // 设备超前时窗口终点仍判未过期
//
// 对私有 MITM CA 放宽零成本：叶私钥每次现签、CA 仅设备侧 NODE_EXTRA_CA_CERTS 信任，且真实
// 使用窗口由缓存 expiry(=mint+ttl) 钉死、与 NotAfter 无关——放宽 NotAfter 不延长任何实际使用。
// 取 1 小时，相对文档记述的分钟级漂移留足量级冗余。
const clockSkewMargin = time.Hour

// entry 是缓存中单条叶证书记录，附带过期时间。
type entry struct {
	cert   *tls.Certificate
	expiry time.Time
}

// Minter 按 host 现签叶证书，内置 TTL 缓存避免重复签发。
// 所有方法并发安全（mu 保护 cache）。
type Minter struct {
	ca    *CA
	ttl   time.Duration
	mu    sync.Mutex
	cache map[string]*entry
}

// NewMinter 创建 Minter，使用给定 CA 签发叶证书，TTL 控制缓存有效期。
func NewMinter(ca *CA, ttl time.Duration) *Minter {
	return &Minter{
		ca:    ca,
		ttl:   ttl,
		cache: make(map[string]*entry),
	}
}

// CertFor 返回针对 host 的 TLS 服务器证书。
// 空 host 直接拒绝（契约违规，不签发）。
// 缓存命中且未过期 → 返回同一指针；过期或首次访问 → 重新签发。
// 整个操作持有 mu，保证并发调用始终拿到同一缓存指针。
func (m *Minter) CertFor(host string) (*tls.Certificate, error) {
	if host == "" {
		return nil, fmt.Errorf("mitm: CertFor requires non-empty host")
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	now := time.Now()

	// 缓存命中且未过期
	if e, ok := m.cache[host]; ok && now.Before(e.expiry) {
		return e.cert, nil
	}

	// 签发新叶证书
	cert, err := m.mint(host, now)
	if err != nil {
		return nil, err
	}

	m.cache[host] = &entry{cert: cert, expiry: now.Add(m.ttl)}
	return cert, nil
}

// mint 实际签发叶证书，不访问缓存。调用方须持有 mu。
func (m *Minter) mint(host string, now time.Time) (*tls.Certificate, error) {
	// 生成叶证书专用 P-256 密钥
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("mitm: generate leaf key for %q: %w", host, err)
	}

	// 随机序列号，取值范围 [0, 2^128)
	maxSerial := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, maxSerial)
	if err != nil {
		return nil, fmt.Errorf("mitm: generate serial for %q: %w", host, err)
	}

	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: host},
		// SAN 是 VerifyHostname 的必要条件（CN 已废弃）
		DNSNames:              []string{host},
		NotBefore:             now.Add(-clockSkewMargin),
		NotAfter:              now.Add(m.ttl + clockSkewMargin),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	// 叶证书由 CA 签发：parent=CA 证书，签名者=CA 私钥
	der, err := x509.CreateCertificate(rand.Reader, tmpl, m.ca.Cert, &leafKey.PublicKey, m.ca.Signer)
	if err != nil {
		return nil, fmt.Errorf("mitm: sign leaf cert for %q: %w", host, err)
	}

	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("mitm: parse signed cert for %q: %w", host, err)
	}

	return &tls.Certificate{
		Certificate: [][]byte{der},
		PrivateKey:  leafKey,
		Leaf:        parsed,
	}, nil
}
