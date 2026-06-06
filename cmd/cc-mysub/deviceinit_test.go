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
