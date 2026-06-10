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
	var out, errOut bytes.Buffer
	if rc := runGenConfig([]string{"-release", "v1.2.3"}, d, &out, &errOut); rc != 0 {
		t.Fatalf("rc=%d out=%s err=%s", rc, out.String(), errOut.String())
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

// TestGenConfig_ConfigDirFlag 验证 -config-dir flag 覆盖 main 分发的默认 cfgDir：
// 把一个不存在的目录作为默认 cfgDir 传入，再用 -config-dir 指向真实 tempdir，
// gen-config 仍能从 -config-dir 读到 config.json + ca.crt 并产出配置。
func TestGenConfig_ConfigDirFlag(t *testing.T) {
	d := writeGenCfgDir(t)
	bogusDefault := filepath.Join(t.TempDir(), "nonexistent")
	var out, errOut bytes.Buffer
	if rc := runGenConfig([]string{"-config-dir", d, "-release", "v9.9.9"}, bogusDefault, &out, &errOut); rc != 0 {
		t.Fatalf("rc=%d out=%s err=%s", rc, out.String(), errOut.String())
	}
	var dc DeployConfig
	if err := json.Unmarshal(out.Bytes(), &dc); err != nil {
		t.Fatalf("output not valid JSON: %v\n%s", err, out.String())
	}
	if dc.PublicHost != "ccapi.example.com" || dc.ReleaseTag != "v9.9.9" {
		t.Errorf("config from -config-dir wrong: %+v", dc)
	}
	if !bytes.Contains([]byte(dc.CACertPEM), []byte("BEGIN CERTIFICATE")) {
		t.Errorf("CA not inlined from -config-dir: %q", dc.CACertPEM)
	}
}

func TestGenConfig_FailsWithoutRelease(t *testing.T) {
	d := writeGenCfgDir(t)
	var out, errOut bytes.Buffer
	if rc := runGenConfig(nil, d, &out, &errOut); rc == 0 {
		t.Fatalf("expected nonzero rc when --release missing")
	}
}

func TestGenConfig_FailsWithoutPublicHost(t *testing.T) {
	d := t.TempDir()
	os.WriteFile(filepath.Join(d, "config.json"), []byte(`{"listen":"127.0.0.1:8788"}`), 0o644)
	os.WriteFile(filepath.Join(d, "ca.crt"), []byte("x"), 0o644)
	var out, errOut bytes.Buffer
	if rc := runGenConfig([]string{"-release", "v1"}, d, &out, &errOut); rc == 0 {
		t.Fatalf("expected nonzero rc when public_host missing")
	}
}

// TestGenConfig_FailsWithoutSubscriptionType 守 id 17：缺 subscription_type 不再静默默认 max，
// 而是与 public_host/--release 对称 fail-fast（错误可见 + SECURITY.md「按实际持有的档位填写」）。
func TestGenConfig_FailsWithoutSubscriptionType(t *testing.T) {
	d := t.TempDir()
	if err := os.WriteFile(filepath.Join(d, "config.json"),
		[]byte(`{"listen":"127.0.0.1:8788","client":{"public_host":"ccapi.example.com"}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(d, "ca.crt"),
		[]byte("-----BEGIN CERTIFICATE-----\nABC\n-----END CERTIFICATE-----\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	var out, errOut bytes.Buffer
	if rc := runGenConfig([]string{"-release", "v1"}, d, &out, &errOut); rc == 0 {
		t.Fatalf("expected nonzero rc when subscription_type missing, got 0; out=%s", out.String())
	}
	// 缺失档位绝不被静默补成 max（产物里不得出现任何档位）。
	if bytes.Contains(out.Bytes(), []byte("max")) {
		t.Errorf("missing subscription_type must not silently default to max; out=%s", out.String())
	}
	if !bytes.Contains(errOut.Bytes(), []byte("subscription_type")) {
		t.Errorf("error should name the missing field; err=%s", errOut.String())
	}
}

// TestGenConfig_ErrorsGoToErrOutNotStdout 守 id 43：错误文本写 errOut（stderr），stdout 保持干净，
// 避免 `gen-config ... > deploy.json` 把错误文本落进部署产物。
func TestGenConfig_ErrorsGoToErrOutNotStdout(t *testing.T) {
	d := writeGenCfgDir(t)
	var out, errOut bytes.Buffer
	// 缺 --release → 错误路径。
	if rc := runGenConfig(nil, d, &out, &errOut); rc == 0 {
		t.Fatalf("expected nonzero rc")
	}
	if out.Len() != 0 {
		t.Errorf("stdout must stay clean on error (else it pollutes deploy.json), got %q", out.String())
	}
	if errOut.Len() == 0 {
		t.Errorf("error text must be surfaced on errOut")
	}
}
