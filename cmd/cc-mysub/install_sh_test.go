package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// plat 返回 install.sh 用的平台串。
func plat() string {
	osn := map[string]string{"linux": "linux", "darwin": "darwin"}[runtime.GOOS]
	arch := map[string]string{"amd64": "amd64", "arm64": "arm64"}[runtime.GOARCH]
	if osn == "" || arch == "" {
		return ""
	}
	return osn + "-" + arch
}

// startReleaseMock 起一个 release 服务: /<repo>/releases/download/<tag>/SHA256SUMS + cc-mysub-<plat>。
// goodSha=false 时 SHA256SUMS 写错 sha 以测 fail-closed。
func startReleaseMock(t *testing.T, repo, tag string, binBytes []byte, goodSha bool) string {
	t.Helper()
	sum := sha256.Sum256(binBytes)
	sha := hex.EncodeToString(sum[:])
	if !goodSha {
		sha = strings.Repeat("0", 64)
	}
	mux := http.NewServeMux()
	prefix := "/" + repo + "/releases/download/" + tag
	mux.HandleFunc(prefix+"/SHA256SUMS", func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprintf(w, "%s  cc-mysub-%s\n", sha, plat())
	})
	mux.HandleFunc(prefix+"/cc-mysub-"+plat(), func(w http.ResponseWriter, _ *http.Request) {
		w.Write(binBytes)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv.URL
}

func startConfigMock(t *testing.T, json string) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte(json))
	}))
	t.Cleanup(srv.Close)
	return srv.URL
}

// runInstall 跑 install.sh，stdin 给 configURL+label(走交互分支)，返回 (home, combinedOutput, err)。
func runInstall(t *testing.T, configURL string, releaseBase string) (string, string, error) {
	t.Helper()
	repoRoot, _ := filepath.Abs("../..")
	script := filepath.Join(repoRoot, "install.sh")
	home := t.TempDir()
	cmd := exec.Command("bash", script, configURL, "installtest")
	cmd.Env = append(os.Environ(),
		"HOME="+home,
		"CC_MYSUB_RELEASE_BASE_URL="+releaseBase,
		"CC_MYSUB_SKIP_POLL=1",
	)
	out, err := cmd.CombinedOutput()
	return home, string(out), err
}

func TestInstall_BinaryAndCA_Placed(t *testing.T) {
	if plat() == "" {
		t.Skip("unsupported platform")
	}
	// install.sh 现在跑到 device-init，被下载物需是真 cc-mysub 二进制（同源构建）。
	binBytes := buildRealBin(t)
	relBase := startReleaseMock(t, "redcontritio/cc-mysub", "v0.0.0-test", binBytes, true)
	confURL := startConfigMock(t, `{"public_host":"ccapi.example.com","subscription_type":"max","release_repo":"redcontritio/cc-mysub","release_tag":"v0.0.0-test","ca_cert_pem":"-----BEGIN CERTIFICATE-----\nABC\n-----END CERTIFICATE-----\n"}`)
	home, out, err := runInstall(t, confURL, relBase)
	if err != nil {
		t.Fatalf("install.sh err=%v out=%s", err, out)
	}
	if _, err := os.Stat(filepath.Join(home, ".local/bin/cc-mysub")); err != nil {
		t.Errorf("binary not installed: %v\n%s", err, out)
	}
	ca, _ := os.ReadFile(filepath.Join(home, ".config/cc-mysub/ca.crt"))
	if !strings.Contains(string(ca), "BEGIN CERTIFICATE") {
		t.Errorf("ca.crt not written: %q", ca)
	}
}

func TestInstall_BadSha_FailsClosed(t *testing.T) {
	if plat() == "" {
		t.Skip("unsupported platform")
	}
	binBytes := []byte("malicious")
	relBase := startReleaseMock(t, "redcontritio/cc-mysub", "v0.0.0-test", binBytes, false) // 错 sha
	confURL := startConfigMock(t, `{"public_host":"ccapi.example.com","subscription_type":"max","release_repo":"redcontritio/cc-mysub","release_tag":"v0.0.0-test","ca_cert_pem":"x"}`)
	home, out, err := runInstall(t, confURL, relBase)
	if err == nil {
		t.Fatalf("expected install.sh to fail on bad sha, out=%s", out)
	}
	if _, statErr := os.Stat(filepath.Join(home, ".local/bin/cc-mysub")); statErr == nil {
		t.Errorf("binary must NOT be installed on sha mismatch")
	}
	if !strings.Contains(out, "sha256 校验失败") {
		t.Errorf("expected sha failure message, got: %s", out)
	}
}

// buildRealBin 构建当前平台真 cc-mysub 二进制字节，供 release mock 下发(device-init 需真二进制)。
func buildRealBin(t *testing.T) []byte {
	t.Helper()
	repoRoot, _ := filepath.Abs("../..")
	out := filepath.Join(t.TempDir(), "cc-mysub")
	cmd := exec.Command("go", "build", "-o", out, "./cmd/cc-mysub")
	cmd.Dir = repoRoot
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build cc-mysub: %v\n%s", err, b)
	}
	b, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestInstall_DeviceInitAndWrapper(t *testing.T) {
	if plat() == "" {
		t.Skip("unsupported platform")
	}
	binBytes := buildRealBin(t)
	relBase := startReleaseMock(t, "redcontritio/cc-mysub", "v0.0.0-test", binBytes, true)
	confURL := startConfigMock(t, `{"public_host":"ccapi.example.com","subscription_type":"max","release_repo":"redcontritio/cc-mysub","release_tag":"v0.0.0-test","ca_cert_pem":"-----BEGIN CERTIFICATE-----\nABC\n-----END CERTIFICATE-----\n"}`)
	repoRoot, _ := filepath.Abs("../..")
	home := t.TempDir()
	cmd := exec.Command("bash", filepath.Join(repoRoot, "install.sh"), confURL, "installtest")
	cmd.Env = append(os.Environ(), "HOME="+home, "CC_MYSUB_RELEASE_BASE_URL="+relBase, "CC_MYSUB_SKIP_POLL=1")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("install.sh err=%v out=%s", err, out)
	}
	for _, f := range []string{".config/cc-mysub/device.key", ".config/cc-mysub/device.crt", ".local/bin/myclaude"} {
		if _, err := os.Stat(filepath.Join(home, f)); err != nil {
			t.Errorf("missing %s: %v", f, err)
		}
	}
	// device.key 0600
	if fi, _ := os.Stat(filepath.Join(home, ".config/cc-mysub/device.key")); fi != nil && fi.Mode().Perm() != 0o600 {
		t.Errorf("device.key perm = %o, want 600", fi.Mode().Perm())
	}
	// myclaude 含正确 host + 无 per-device 秘密
	w, _ := os.ReadFile(filepath.Join(home, ".local/bin/myclaude"))
	if !strings.Contains(string(w), "ccapi.example.com") || !strings.Contains(string(w), "helper --host") {
		t.Errorf("myclaude wrong: %s", w)
	}
	if strings.Contains(string(w), "PRIVATE KEY") || strings.Contains(string(w), "sk-ant-oat") {
		t.Errorf("myclaude leaked secret")
	}
}
