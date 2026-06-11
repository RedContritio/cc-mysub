package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
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
	if rc := runGenConfig([]string{"-config-dir", d, "-release", "v1.2.3"}, &out, &errOut); rc != 0 {
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

// TestGenConfig_ConfigDirFlag 守 Backlog P1：HOME/XDG 全缺时显式 -config-dir 仍正常工作
// （惰性解析下显式目录绝不触发默认解析）；缺 flag 则 loud-fail 到 errOut。
func TestGenConfig_ConfigDirFlag(t *testing.T) {
	t.Setenv("HOME", "")
	t.Setenv("XDG_CONFIG_HOME", "")
	d := writeGenCfgDir(t)
	var out, errOut bytes.Buffer
	if rc := runGenConfig([]string{"-config-dir", d, "-release", "v9.9.9"}, &out, &errOut); rc != 0 {
		t.Fatalf("rc=%d out=%s err=%s", rc, out.String(), errOut.String())
	}
	var dc DeployConfig
	if err := json.Unmarshal(out.Bytes(), &dc); err != nil {
		t.Fatalf("output not valid JSON: %v\n%s", err, out.String())
	}
	if dc.ReleaseTag != "v9.9.9" {
		t.Errorf("release wrong: %+v", dc)
	}
	out.Reset()
	errOut.Reset()
	if rc := runGenConfig([]string{"-release", "v1"}, &out, &errOut); rc != 1 {
		t.Fatalf("缺 flag 且无 HOME 应 rc=1, got %d", rc)
	}
	if !strings.Contains(errOut.String(), "无法确定配置目录") {
		t.Errorf("errOut 应含默认目录解析错误: %q", errOut.String())
	}
}

func TestGenConfig_FailsWithoutRelease(t *testing.T) {
	d := writeGenCfgDir(t)
	var out, errOut bytes.Buffer
	if rc := runGenConfig([]string{"-config-dir", d}, &out, &errOut); rc == 0 {
		t.Fatalf("expected nonzero rc when --release missing")
	}
}

func TestGenConfig_FailsWithoutPublicHost(t *testing.T) {
	d := t.TempDir()
	os.WriteFile(filepath.Join(d, "config.json"), []byte(`{"listen":"127.0.0.1:8788"}`), 0o644)
	os.WriteFile(filepath.Join(d, "ca.crt"), []byte("x"), 0o644)
	var out, errOut bytes.Buffer
	if rc := runGenConfig([]string{"-config-dir", d, "-release", "v1"}, &out, &errOut); rc == 0 {
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
	if rc := runGenConfig([]string{"-config-dir", d, "-release", "v1"}, &out, &errOut); rc == 0 {
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
	if rc := runGenConfig([]string{"-config-dir", d}, &out, &errOut); rc == 0 {
		t.Fatalf("expected nonzero rc")
	}
	if out.Len() != 0 {
		t.Errorf("stdout must stay clean on error (else it pollutes deploy.json), got %q", out.String())
	}
	if errOut.Len() == 0 {
		t.Errorf("error text must be surfaced on errOut")
	}
}
