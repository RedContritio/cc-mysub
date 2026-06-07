package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func writeGenCfgDir(t *testing.T) string {
	t.Helper()
	d := t.TempDir()
	if err := os.WriteFile(filepath.Join(d, "config.json"),
		[]byte(`{"listen":"127.0.0.1:8788","client":{"public_host":"ccapi.example.com","subscription_type":"max"}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(d, "ca.crt"), []byte("-----BEGIN CERTIFICATE-----\nABC\n-----END CERTIFICATE-----\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	return d
}

func TestGenConfig_OutputsAllFields(t *testing.T) {
	d := writeGenCfgDir(t)
	var out bytes.Buffer
	if rc := runGenConfig([]string{"-release", "v1.2.3"}, d, &out); rc != 0 {
		t.Fatalf("rc=%d out=%s", rc, out.String())
	}
	var dc DeployConfig
	if err := json.Unmarshal(out.Bytes(), &dc); err != nil {
		t.Fatalf("output not valid JSON: %v\n%s", err, out.String())
	}
	if dc.PublicHost != "ccapi.example.com" || dc.SubscriptionType != "max" {
		t.Errorf("host/sub wrong: %+v", dc)
	}
	if dc.ReleaseTag != "v1.2.3" || dc.ReleaseRepo != "redcontritio/cc-mysub" {
		t.Errorf("release wrong: %+v", dc)
	}
	if !bytes.Contains([]byte(dc.CACertPEM), []byte("BEGIN CERTIFICATE")) {
		t.Errorf("CA not inlined: %q", dc.CACertPEM)
	}
	if bytes.Contains(out.Bytes(), []byte("PRIVATE KEY")) || bytes.Contains(out.Bytes(), []byte("sk-ant-oat")) {
		t.Errorf("secret leaked in config output")
	}
}

func TestGenConfig_FailsWithoutRelease(t *testing.T) {
	d := writeGenCfgDir(t)
	var out bytes.Buffer
	if rc := runGenConfig(nil, d, &out); rc == 0 {
		t.Fatalf("expected nonzero rc when --release missing")
	}
}

func TestGenConfig_FailsWithoutPublicHost(t *testing.T) {
	d := t.TempDir()
	os.WriteFile(filepath.Join(d, "config.json"), []byte(`{"listen":"127.0.0.1:8788"}`), 0o644)
	os.WriteFile(filepath.Join(d, "ca.crt"), []byte("x"), 0o644)
	var out bytes.Buffer
	if rc := runGenConfig([]string{"-release", "v1"}, d, &out); rc == 0 {
		t.Fatalf("expected nonzero rc when public_host missing")
	}
}
