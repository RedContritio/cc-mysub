package mitm

import (
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"time"
)

// CA 持有已解析的 CA 证书与对应的签名私钥。
// Signer 供后续 Minter（Task 4）用于签发叶证书。
type CA struct {
	Cert   *x509.Certificate
	Signer crypto.Signer
}

// LoadCA 解析 PEM 编码的 CA 证书与私钥。
// 私钥先尝试 EC SEC1 格式（ParseECPrivateKey），失败后回退 PKCS8（ParsePKCS8PrivateKey）。
// 任意输入畸形均返回明确 error，不做静默默认。
func LoadCA(certPEM, keyPEM []byte) (*CA, error) {
	// 解析证书
	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil {
		return nil, fmt.Errorf("mitm: failed to decode certificate PEM block")
	}
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("mitm: parse certificate: %w", err)
	}
	// fail-fast：加载期即拒绝非 CA / 不能签发证书的证书，避免拖到客户端验链才以含糊的
	// "unknown authority" 暴露（治理总纲：错误可见、最该 fail-fast 的位置）。
	if !cert.IsCA {
		return nil, fmt.Errorf("mitm: certificate is not a CA (IsCA=false)")
	}
	if cert.KeyUsage != 0 && cert.KeyUsage&x509.KeyUsageCertSign == 0 {
		// KeyUsage==0 表示未限制用途，放行；非零但缺 CertSign 则不能签发叶证书。
		return nil, fmt.Errorf("mitm: CA certificate lacks KeyUsageCertSign")
	}
	// 过期的 CA：CreateCertificate 不校验 parent 有效期，mint 会照常成功，错误推迟到设备验链
	// 才以含糊提示暴露。加载期 fail-fast 让过期一目了然（治理总纲：错误可见、最该 fail-fast 的位置）。
	if now := time.Now(); now.After(cert.NotAfter) {
		return nil, fmt.Errorf("mitm: CA certificate expired at %s", cert.NotAfter.Format(time.RFC3339))
	}

	// 解析私钥：先试 EC SEC1，再试 PKCS8
	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return nil, fmt.Errorf("mitm: failed to decode private key PEM block")
	}

	var signer crypto.Signer

	ecKey, err := x509.ParseECPrivateKey(keyBlock.Bytes)
	if err == nil {
		// EC SEC1 解析成功；*ecdsa.PrivateKey 实现 crypto.Signer
		signer = ecKey
	} else {
		// 回退 PKCS8
		raw, err2 := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
		if err2 != nil {
			// 主因（EC SEC1）用 %w 保留 errors.Is/As 链；PKCS8 作为补充信息以 %v 附带。
			return nil, fmt.Errorf("mitm: parse private key (EC SEC1: %w; PKCS8: %v)", err, err2)
		}
		s, ok := raw.(crypto.Signer)
		if !ok {
			return nil, fmt.Errorf("mitm: PKCS8 key type %T does not implement crypto.Signer", raw)
		}
		signer = s
	}

	// 私钥必须与 CA 证书公钥配对。外层身份证书走 tls.X509KeyPair 自带该校验，内层 CA 这条手工
	// 解析路径需对称补上——否则 crt/key 错配（部分备份恢复、手工搬动其一）会通过 LoadCA，Minter
	// 用一把与 CA 证书不对应的私钥签发叶证书，错误推迟到每条 MITM 连接的设备握手才暴露。
	pub, ok := cert.PublicKey.(interface {
		Equal(crypto.PublicKey) bool
	})
	if !ok || !pub.Equal(signer.Public()) {
		return nil, fmt.Errorf("mitm: CA private key does not match certificate public key")
	}

	return &CA{Cert: cert, Signer: signer}, nil
}
