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
		"CC_MYSUB_SKIP_ENROLL=1",
	)
	out, err := cmd.CombinedOutput()
	return home, string(out), err
}

func TestInstall_BinaryAndCA_Placed(t *testing.T) {
	if plat() == "" {
		t.Skip("unsupported platform")
	}
	// 用真 cc-mysub 二进制(当前测试进程同源构建) 当被下载物 —— 简化: 用任意非空字节即可验证 sha-pin+落盘。
	binBytes := []byte("#!/bin/sh\necho fake-cc-mysub\n")
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
