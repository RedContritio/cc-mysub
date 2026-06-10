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
	// label 仅用于打印 add-device 登记命令，绝不写入证书 CN（CN 恒为固定非 PII 占位，见下）。
	label := fs.String("label", "", "device label（仅用于打印 add-device 登记命令；不写入证书 CN）")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	keyPath := filepath.Join(cfgDir, "device.key")
	crtPath := filepath.Join(cfgDir, "device.crt")

	// 幂等：已存在则只重打印指纹，绝不重生成（避免覆盖已登记的设备身份）。
	// statExists 把非 NotExist 的 stat 错误（瞬时 EIO/路径异常等）原样 surface，而非误判为「不存在」
	// 走重生成分支、用新私钥原子覆盖既有 device.key（旧指纹随之作废且不可恢复）——对齐 enroll.EnsureCA。
	keyExists, err := statExists(keyPath)
	if err != nil {
		fmt.Fprintln(out, "检查 device.key:", err)
		return 1
	}
	crtExists, err := statExists(crtPath)
	if err != nil {
		fmt.Fprintln(out, "检查 device.crt:", err)
		return 1
	}
	if keyExists && crtExists {
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
	// CN 与 label 解耦：CN 恒为固定非 PII 占位，绝不取 label/主机名——避免把设备标识写进客户端证书
	// （TLS1.2 下证书在握手中明文，frps 透传虽不解密但链路上可被旁观；install.sh 默认以 hostname 作
	// label，若 label 进 CN 即把主机名泄漏进证书）。身份由指纹承载，CN 不参与认证；label 仅供打印登记命令。
	const cn = "cc-mysub-device"
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
	printEnroll(out, der, *label)
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

// statExists 报告 path 是否存在；NotExist → false,nil；其余 stat 错误（权限/IO/路径异常）原样
// surface——不能误判为「不存在」走重生成分支覆盖既存 device.key（对齐 enroll.EnsureCA 的 statExists）。
func statExists(path string) (bool, error) {
	if _, err := os.Stat(path); err == nil {
		return true, nil
	} else if os.IsNotExist(err) {
		return false, nil
	} else {
		return false, fmt.Errorf("stat %s: %w", path, err)
	}
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
