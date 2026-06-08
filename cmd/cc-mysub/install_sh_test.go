package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
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

// TestInstall_UnreachableHost_FailsFast 验证轮询区分「host 不可达」与「未批准」(spec §6)：
// public_host 指向无人监听的 127.0.0.1:443 → 探针连续 unreachable → install.sh 快速非零退出，
// 不白等到 10 分钟超时、不写 myclaude。不设 CC_MYSUB_SKIP_POLL（真走轮询）。
func TestInstall_UnreachableHost_FailsFast(t *testing.T) {
	if plat() == "" {
		t.Skip("unsupported platform")
	}
	// 若本机 127.0.0.1:443 恰有服务在听，「拒连=不可达」前提不成立 → 跳过（探针会走别的分支）。
	if c, err := net.DialTimeout("tcp", "127.0.0.1:443", time.Second); err == nil {
		c.Close()
		t.Skip("something is listening on 127.0.0.1:443; cannot exercise unreachable path")
	}

	binBytes := buildRealBin(t)
	relBase := startReleaseMock(t, "redcontritio/cc-mysub", "v0.0.0-test", binBytes, true)
	// public_host=127.0.0.1 → 探针 openssl s_client connect 127.0.0.1:443 被拒（无人监听）。
	confURL := startConfigMock(t, `{"public_host":"127.0.0.1","subscription_type":"max","release_repo":"redcontritio/cc-mysub","release_tag":"v0.0.0-test","ca_cert_pem":"-----BEGIN CERTIFICATE-----\nABC\n-----END CERTIFICATE-----\n"}`)

	repoRoot, _ := filepath.Abs("../..")
	home := t.TempDir()
	// 60s 上限：fail-fast 应在十几秒内退出；命中上限即视为「没快退」失败（被 ctx kill）。
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "bash", filepath.Join(repoRoot, "install.sh"), confURL, "installtest")
	cmd.Env = append(os.Environ(), "HOME="+home, "CC_MYSUB_RELEASE_BASE_URL="+relBase) // 注意：不设 CC_MYSUB_SKIP_POLL
	start := time.Now()
	out, err := cmd.CombinedOutput()
	elapsed := time.Since(start)

	if ctx.Err() == context.DeadlineExceeded {
		t.Fatalf("install.sh 未快退（被 60s ctx 杀死）——轮询没把不可达判成 unreachable\n%s", out)
	}
	if err == nil {
		t.Fatalf("expected non-zero exit on unreachable host, out=%s", out)
	}
	if elapsed > 45*time.Second {
		t.Errorf("fail-fast 太慢: %v (期望十几秒内)", elapsed)
	}
	if !strings.Contains(string(out), "无法连接") && !strings.Contains(string(out), "不可达") {
		t.Errorf("缺少不可达提示: %s", out)
	}
	// device-init 仍会先跑（证书已生成），但轮询未通过 → 绝不写 myclaude。
	if _, err := os.Stat(filepath.Join(home, ".local/bin/myclaude")); err == nil {
		t.Errorf("myclaude must NOT be written when onboarding never approved")
	}
}

// TestInstall_Idempotent_Rerun 验证幂等重跑：第二次跳过二进制下载与 device-init 重生，
// 仍写出 myclaude、exit 0，且设备私钥不变（device-init 复用既有 key）。
func TestInstall_Idempotent_Rerun(t *testing.T) {
	if plat() == "" {
		t.Skip("unsupported platform")
	}
	binBytes := buildRealBin(t)
	relBase := startReleaseMock(t, "redcontritio/cc-mysub", "v0.0.0-test", binBytes, true)
	confURL := startConfigMock(t, `{"public_host":"ccapi.example.com","subscription_type":"max","release_repo":"redcontritio/cc-mysub","release_tag":"v0.0.0-test","ca_cert_pem":"-----BEGIN CERTIFICATE-----\nABC\n-----END CERTIFICATE-----\n"}`)
	repoRoot, _ := filepath.Abs("../..")
	home := t.TempDir()
	script := filepath.Join(repoRoot, "install.sh")

	run := func() (string, error) {
		cmd := exec.Command("bash", script, confURL, "installtest")
		cmd.Env = append(os.Environ(), "HOME="+home, "CC_MYSUB_RELEASE_BASE_URL="+relBase, "CC_MYSUB_SKIP_POLL=1")
		out, err := cmd.CombinedOutput()
		return string(out), err
	}

	if out, err := run(); err != nil {
		t.Fatalf("first install.sh: %v\n%s", err, out)
	}
	keyPath := filepath.Join(home, ".config/cc-mysub/device.key")
	key1, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatalf("device.key after first run: %v", err)
	}

	out2, err := run()
	if err != nil {
		t.Fatalf("second install.sh: %v\n%s", err, out2)
	}
	// 二跑应跳过下载（$BIN 已可执行）。
	if strings.Contains(out2, "下载二进制") {
		t.Errorf("rerun should skip binary download, got:\n%s", out2)
	}
	// 二跑仍写 myclaude。
	if _, err := os.Stat(filepath.Join(home, ".local/bin/myclaude")); err != nil {
		t.Errorf("rerun must still write myclaude: %v", err)
	}
	// device-init 幂等：私钥复用，未被重生。
	key2, _ := os.ReadFile(keyPath)
	if string(key1) != string(key2) {
		t.Errorf("device.key changed on rerun (device-init not idempotent)")
	}
}
