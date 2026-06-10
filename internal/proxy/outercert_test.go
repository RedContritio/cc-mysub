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
	"strconv"
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

// ocWriteSelfSignedSANs 与 ocWriteSelfSigned 同,但加 extraSANs 个 DNS SAN 撑大 DER/文件尺寸——
// 供「同 mtime 但 size 不同的替换须重载」测试构造一个与原证书尺寸明显不同的替换。
func ocWriteSelfSignedSANs(t *testing.T, dir, cn string, extraSANs int) (certPath, keyPath string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	dns := []string{cn}
	for i := 0; i < extraSANs; i++ {
		dns = append(dns, "pad-"+strconv.Itoa(i)+".example.invalid")
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		DNSNames:     dns,
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

// TestOuterCertLoader_ReloadsOnMtimeRollback 验证 P2-61:续期失败后从备份恢复旧证书(mtime 回退到过去,
// cp -p/rsync -a/tar 还原保留较旧 mtime)必须被重载——After() 会漏(回退 mtime 非 After 缓存值),Equal 覆盖。
func TestOuterCertLoader_ReloadsOnMtimeRollback(t *testing.T) {
	dir := t.TempDir()
	cp, kp := ocWriteSelfSigned(t, dir, "first.example")
	get := NewOuterCertLoader(cp, kp)
	if _, err := get(nil); err != nil {
		t.Fatal(err)
	}
	dir2 := t.TempDir()
	cp2, kp2 := ocWriteSelfSigned(t, dir2, "rolledback.example")
	ocCopy(t, cp2, cp)
	ocCopy(t, kp2, kp)
	past := time.Now().Add(-2 * time.Hour)
	if err := os.Chtimes(cp, past, past); err != nil {
		t.Fatal(err)
	}
	c2, err := get(nil)
	if err != nil {
		t.Fatal(err)
	}
	leaf, _ := x509.ParseCertificate(c2.Certificate[0])
	if leaf.Subject.CommonName != "rolledback.example" {
		t.Fatalf("mtime-rollback not reloaded (After() bug), cn=%s want rolledback.example", leaf.Subject.CommonName)
	}
}

// TestOuterCertLoader_ReloadsOnSameMtimeSizeChange 验证 P3-65:同 mtime 粒度内的替换(内容/尺寸变、mtime 不变)
// 须被重载——After() 与单纯 Equal(mtime) 都会漏,故判据叠加 size 比较。
func TestOuterCertLoader_ReloadsOnSameMtimeSizeChange(t *testing.T) {
	dir := t.TempDir()
	cp, kp := ocWriteSelfSigned(t, dir, "first.example")
	fixed := time.Now().Add(-time.Hour).Truncate(time.Second)
	if err := os.Chtimes(cp, fixed, fixed); err != nil {
		t.Fatal(err)
	}
	get := NewOuterCertLoader(cp, kp)
	if _, err := get(nil); err != nil {
		t.Fatal(err)
	}
	// 用 size 明显不同的新证书(额外 SAN 撑大)覆盖,mtime 设回同一刻。
	dir2 := t.TempDir()
	cp2, kp2 := ocWriteSelfSignedSANs(t, dir2, "samemtime.example", 8)
	ocCopy(t, cp2, cp)
	ocCopy(t, kp2, kp)
	if err := os.Chtimes(cp, fixed, fixed); err != nil {
		t.Fatal(err)
	}
	c2, err := get(nil)
	if err != nil {
		t.Fatal(err)
	}
	leaf, _ := x509.ParseCertificate(c2.Certificate[0])
	if leaf.Subject.CommonName != "samemtime.example" {
		t.Fatalf("same-mtime size-changed cert not reloaded, cn=%s want samemtime.example", leaf.Subject.CommonName)
	}
}
