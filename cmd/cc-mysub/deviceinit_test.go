package main

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/redcontritio/cc-mysub/internal/auth"
)

func diReadCertDER(t *testing.T, crtPath string) []byte {
	t.Helper()
	b, err := os.ReadFile(crtPath)
	if err != nil {
		t.Fatal(err)
	}
	blk, _ := pem.Decode(b)
	if blk == nil {
		t.Fatal("no PEM block in device.crt")
	}
	return blk.Bytes
}

func TestDeviceInit_GeneratesKeyCertPrintsFingerprint(t *testing.T) {
	cfg := filepath.Join(t.TempDir(), "cc-mysub")
	var out bytes.Buffer
	if rc := runDeviceInit(nil, cfg, &out); rc != 0 {
		t.Fatalf("rc=%d out=%s", rc, out.String())
	}
	keyPath := filepath.Join(cfg, "device.key")
	crtPath := filepath.Join(cfg, "device.crt")

	fi, err := os.Stat(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("device.key mode=%v want 0600", fi.Mode().Perm())
	}

	der := diReadCertDER(t, crtPath)
	wantFP := auth.CertFingerprint(der)
	if !strings.Contains(out.String(), wantFP) {
		t.Fatalf("output lacks fingerprint %s:\n%s", wantFP, out.String())
	}

	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	if leaf.IsCA {
		t.Fatal("device cert must be IsCA=false (client-leaf)")
	}
	hasClientAuth := false
	for _, eku := range leaf.ExtKeyUsage {
		if eku == x509.ExtKeyUsageClientAuth {
			hasClientAuth = true
		}
	}
	if !hasClientAuth {
		t.Fatal("device cert must have ExtKeyUsageClientAuth")
	}

	// 私钥不得泄漏进证书文件或打印输出（"私钥不离设备"——只在 device.key）。
	crtBytes, _ := os.ReadFile(crtPath)
	if bytes.Contains(crtBytes, []byte("PRIVATE KEY")) || strings.Contains(out.String(), "PRIVATE KEY") {
		t.Fatal("private key leaked into cert file / stdout")
	}
}

// TestDeviceInit_LabelNotInCertCN 守 id 44：--label 仅用于打印登记命令，绝不写进证书 CN
// （install.sh 默认以 hostname 作 label；若 label 进 CN 即把主机名/PII 泄漏进客户端证书）。
// CN 恒为固定非 PII 占位 "cc-mysub-device"，身份由指纹承载。
func TestDeviceInit_LabelNotInCertCN(t *testing.T) {
	cfg := filepath.Join(t.TempDir(), "cc-mysub")
	var out bytes.Buffer
	const label = "my-secret-hostname"
	if rc := runDeviceInit([]string{"-label", label}, cfg, &out); rc != 0 {
		t.Fatalf("rc=%d out=%s", rc, out.String())
	}
	der := diReadCertDER(t, filepath.Join(cfg, "device.crt"))
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	if leaf.Subject.CommonName != "cc-mysub-device" {
		t.Errorf("cert CN = %q, want fixed non-PII placeholder cc-mysub-device (label must not enter CN)", leaf.Subject.CommonName)
	}
	if strings.Contains(leaf.Subject.CommonName, label) {
		t.Errorf("device label leaked into cert CN: %q", leaf.Subject.CommonName)
	}
	// label 仍出现在打印的 add-device 登记命令里（供 operator 直接粘贴）。
	if !strings.Contains(out.String(), label) {
		t.Errorf("printed enroll command should carry the label %q:\n%s", label, out.String())
	}
}

// TestDeviceInit_StatErrorIsVisible 守 id 64：非 NotExist 的 stat 错误不得被塌缩成「不存在」走
// 重生成分支（会覆盖既有 device.key）。把 cfgDir 设成一个普通文件 → stat 子路径返回 ENOTDIR
// （os.IsNotExist 为 false）→ runDeviceInit 须报错退出而非静默继续。
func TestDeviceInit_StatErrorIsVisible(t *testing.T) {
	// cfgDir 指向一个普通文件，使 filepath.Join(cfgDir, "device.key") 的 stat 触发 ENOTDIR。
	notADir := filepath.Join(t.TempDir(), "iam-a-file")
	if err := os.WriteFile(notADir, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	rc := runDeviceInit(nil, notADir, &out)
	if rc == 0 {
		t.Fatalf("expected nonzero rc when stat returns a non-NotExist error, got 0; out=%s", out.String())
	}
	if out.Len() == 0 {
		t.Errorf("stat error must be surfaced (错误可见), got empty output")
	}
}

func TestDeviceInit_Idempotent(t *testing.T) {
	cfg := filepath.Join(t.TempDir(), "cc-mysub")
	if rc := runDeviceInit(nil, cfg, &bytes.Buffer{}); rc != 0 {
		t.Fatalf("first run rc=%d", rc)
	}
	k1, err := os.ReadFile(filepath.Join(cfg, "device.key"))
	if err != nil {
		t.Fatal(err)
	}
	var out2 bytes.Buffer
	if rc := runDeviceInit(nil, cfg, &out2); rc != 0 {
		t.Fatalf("second run rc=%d", rc)
	}
	k2, _ := os.ReadFile(filepath.Join(cfg, "device.key"))
	if !bytes.Equal(k1, k2) {
		t.Fatal("not idempotent: device.key regenerated on second run")
	}
	// 幂等 re-run 仍重打印指纹（供再次登记参考）。
	der := diReadCertDER(t, filepath.Join(cfg, "device.crt"))
	if !strings.Contains(out2.String(), auth.CertFingerprint(der)) {
		t.Fatal("idempotent re-run should reprint fingerprint")
	}
}
