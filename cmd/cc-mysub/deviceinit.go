package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"time"
)

// runDeviceInit 幂等生成 per-device client-leaf 自签证书 + 私钥(0600)，打印证书指纹与登记命令。
// 私钥唯一落点 device.key，绝不打印/外传——这是"私钥不离设备"数据安全属性的落点。返回退出码。
func runDeviceInit(args []string, cfgDir string, out io.Writer) int {
	fs := flag.NewFlagSet("device-init", flag.ContinueOnError)
	fs.SetOutput(out)
	label := fs.String("label", "", "device label (default: hostname)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	keyPath := filepath.Join(cfgDir, "device.key")
	crtPath := filepath.Join(cfgDir, "device.crt")

	// 幂等：已存在则只重打印指纹，绝不重生成（避免覆盖已登记的设备身份）。
	if fileExists(keyPath) && fileExists(crtPath) {
		der, err := readCertDER(crtPath)
		if err != nil {
			fmt.Fprintf(out, "device.crt 损坏，无法解析: %v\n", err)
			return 1
		}
		printEnroll(out, der, *label)
		return 0
	}

	if err := os.MkdirAll(cfgDir, 0o755); err != nil {
		fmt.Fprintln(out, "mkdir:", err)
		return 1
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		fmt.Fprintln(out, "生成密钥:", err)
		return 1
	}
	cn := *label
	if cn == "" {
		if h, _ := os.Hostname(); h != "" {
			cn = h
		} else {
			cn = "cc-mysub-device"
		}
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		fmt.Fprintln(out, "生成序列号:", err)
		return 1
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(10 * 365 * 24 * time.Hour), // 长有效期：mTLS 指纹钉忽略过期，吊销=删指纹行
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		fmt.Fprintln(out, "生成证书:", err)
		return 1
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		fmt.Fprintln(out, "编码私钥:", err)
		return 1
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	if err := writeFileAtomic(keyPath, keyPEM, 0o600); err != nil {
		fmt.Fprintln(out, "写私钥:", err)
		return 1
	}
	crtPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	if err := writeFileAtomic(crtPath, crtPEM, 0o644); err != nil {
		fmt.Fprintln(out, "写证书:", err)
		return 1
	}
	printEnroll(out, der, cn)
	return 0
}

// printEnroll 打印证书指纹（SHA-256(DER) 小写 hex）+ 可直接粘贴的 add-device 登记命令。
func printEnroll(out io.Writer, der []byte, label string) {
	sum := sha256.Sum256(der)
	fp := hex.EncodeToString(sum[:])
	fmt.Fprintf(out, "✓ 设备证书已就位。指纹(SHA-256):\n  %s\n", fp)
	fmt.Fprintf(out, "\n在代理主机登记本设备(逐设备认证)，然后重跑本命令:\n")
	fmt.Fprintf(out, "  cc-mysub add-device --label %q --fingerprint %s\n", label, fp)
}

func fileExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

func readCertDER(crtPath string) ([]byte, error) {
	b, err := os.ReadFile(crtPath)
	if err != nil {
		return nil, err
	}
	blk, _ := pem.Decode(b)
	if blk == nil {
		return nil, fmt.Errorf("no PEM block in %s", crtPath)
	}
	return blk.Bytes, nil
}

// writeFileAtomic 同目录 mktemp + 写 + chmod + rename，避免半写文件。
func writeFileAtomic(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // rename 成功后为 no-op
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmpName, perm); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}
