package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
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

// TestInstall_MissingSubType_FailsClosed 钉死 P3-17:部署配置缺 subscription_type 时 install.sh
// fail-closed 报错、不静默默认最高档 max。合法 deploy.json 由 gen-config 保证带此字段;缺失只来自
// 手编配置,据无静默默认纪律应拒绝而非默认。校验先于下载,故无需真 release。
func TestInstall_MissingSubType_FailsClosed(t *testing.T) {
	if plat() == "" {
		t.Skip("unsupported platform")
	}
	confURL := startConfigMock(t, `{"public_host":"ccapi.example.com","release_repo":"redcontritio/cc-mysub","release_tag":"v0.0.0-test","ca_cert_pem":"-----BEGIN CERTIFICATE-----\nABC\n-----END CERTIFICATE-----\n"}`)
	home, out, err := runInstall(t, confURL, "http://127.0.0.1:1") // release base 不该被触及
	if err == nil {
		t.Fatalf("expected install.sh to fail when subscription_type missing, out=%s", out)
	}
	if !strings.Contains(out, "subscription_type") {
		t.Errorf("expected subscription_type failure message, got: %s", out)
	}
	if _, statErr := os.Stat(filepath.Join(home, ".local/bin/cc-mysub")); statErr == nil {
		t.Errorf("binary must NOT be installed when config invalid")
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

// confJSON 构造部署配置 JSON。caBody 嵌入 PEM 正文行(\n 为 JSON 转义换行,原样写入)。
func confJSON(host, caBody string) string {
	return `{"public_host":"` + host +
		`","subscription_type":"max","release_repo":"redcontritio/cc-mysub","release_tag":"v0.0.0-test",` +
		`"ca_cert_pem":"-----BEGIN CERTIFICATE-----\n` + caBody + `\n-----END CERTIFICATE-----\n"}`
}

// startMutableConfigMock 起一个可在多次拉取间改变响应体的配置服务,用于模拟托管点事后被换内容。
func startMutableConfigMock(t *testing.T, initial string) (string, func(string)) {
	t.Helper()
	var mu sync.Mutex
	body := initial
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		mu.Lock()
		b := body
		mu.Unlock()
		w.Write([]byte(b))
	}))
	t.Cleanup(srv.Close)
	return srv.URL, func(s string) { mu.Lock(); body = s; mu.Unlock() }
}

// TestInstall_NoFingerprint_FailsLoud(id 26):device-init 不产出指纹时,指纹缺失必须走显式 guard
// 报「device-init 未产出指纹」,而非在 pipefail 下被 grep 无匹配的 rc=1 静默终止脚本(死防御变可达)。
// 用一个打印非指纹文本的假二进制(shell 脚本)驱动 device-init 路径。
func TestInstall_NoFingerprint_FailsLoud(t *testing.T) {
	if plat() == "" {
		t.Skip("unsupported platform")
	}
	fakeBin := []byte("#!/bin/sh\necho 'device-init produced no fingerprint here'\n")
	relBase := startReleaseMock(t, "redcontritio/cc-mysub", "v0.0.0-test", fakeBin, true)
	confURL := startConfigMock(t, confJSON("ccapi.example.com", "ABC"))
	home, out, err := runInstall(t, confURL, relBase)
	if err == nil {
		t.Fatalf("expected non-zero exit when device-init yields no fingerprint, out=%s", out)
	}
	if !strings.Contains(out, "device-init 未产出指纹") {
		t.Errorf("缺少显式指纹缺失报错(guard 不可达?): %s", out)
	}
	if _, e := os.Stat(filepath.Join(home, ".local/bin/myclaude")); e == nil {
		t.Errorf("myclaude must NOT be written when fingerprint missing")
	}
}

// TestInstall_MissingSumsEntry_FailsClosed(id 31):SHA256SUMS 缺本平台条目时供应链 fail-closed
// 分支必须非零退出、报「无 cc-mysub-<plat> 条目」且不安装二进制(此前无回归覆盖)。
func TestInstall_MissingSumsEntry_FailsClosed(t *testing.T) {
	if plat() == "" {
		t.Skip("unsupported platform")
	}
	repo, tag := "redcontritio/cc-mysub", "v0.0.0-test"
	prefix := "/" + repo + "/releases/download/" + tag
	mux := http.NewServeMux()
	mux.HandleFunc(prefix+"/SHA256SUMS", func(w http.ResponseWriter, _ *http.Request) {
		// 只给一个别的平台条目 → 本平台 WANT 为空 → 触发 fail-closed
		fmt.Fprintf(w, "%s  cc-mysub-some-other-plat\n", strings.Repeat("a", 64))
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	confURL := startConfigMock(t, confJSON("ccapi.example.com", "ABC"))
	home, out, err := runInstall(t, confURL, srv.URL)
	if err == nil {
		t.Fatalf("expected fail-closed on missing SHA256SUMS entry, out=%s", out)
	}
	if !strings.Contains(out, "无 cc-mysub-"+plat()+" 条目") {
		t.Errorf("缺少「无本平台条目」报错: %s", out)
	}
	if _, e := os.Stat(filepath.Join(home, ".local/bin/cc-mysub")); e == nil {
		t.Errorf("binary must NOT be installed when SHA256SUMS lacks platform entry")
	}
}

// TestInstall_Rerun_StaleBinary_Redownloads(id 30):重跑无条件按 SHA256SUMS 核对本地二进制。
// 已装二进制与配置钉定版本的 sha 不一致时必须重新下载替换,而非「本地已有即静默沿用旧二进制」。
func TestInstall_Rerun_StaleBinary_Redownloads(t *testing.T) {
	if plat() == "" {
		t.Skip("unsupported platform")
	}
	binBytes := buildRealBin(t)
	relBase := startReleaseMock(t, "redcontritio/cc-mysub", "v0.0.0-test", binBytes, true)
	confURL := startConfigMock(t, confJSON("ccapi.example.com", "ABC"))
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
	binPath := filepath.Join(home, ".local/bin/cc-mysub")
	// 模拟存量设备上的旧/陈二进制:就地换成与钉定版本 sha 不同的字节(仍 0755)。
	if err := os.WriteFile(binPath, []byte("stale-old-binary-bytes-not-pinned"), 0o755); err != nil {
		t.Fatal(err)
	}
	out2, err := run()
	if err != nil {
		t.Fatalf("rerun with stale binary should succeed by redownloading: %v\n%s", err, out2)
	}
	if !strings.Contains(out2, "重新下载替换") {
		t.Errorf("陈旧二进制重跑应触发重下载替换, got:\n%s", out2)
	}
	got, _ := os.ReadFile(binPath)
	if !bytes.Equal(got, binBytes) {
		t.Errorf("stale binary not restored to pinned version on rerun (len got=%d want=%d)", len(got), len(binBytes))
	}
}

// TestInstall_CATrustOnFirstUse(id 46):ca.crt 为 trust-on-FIRST-use。首次信任后,配置托管点
// 换了 CA 内容时任一次重跑必须拒绝(不静默轮换 NODE_EXTRA_CA_CERTS 信任锚),既有 ca.crt 不被覆盖。
func TestInstall_CATrustOnFirstUse(t *testing.T) {
	if plat() == "" {
		t.Skip("unsupported platform")
	}
	binBytes := buildRealBin(t)
	relBase := startReleaseMock(t, "redcontritio/cc-mysub", "v0.0.0-test", binBytes, true)
	confURL, setConf := startMutableConfigMock(t, confJSON("ccapi.example.com", "AAAFIRSTTRUST"))
	repoRoot, _ := filepath.Abs("../..")
	home := t.TempDir()
	script := filepath.Join(repoRoot, "install.sh")
	run := func() (string, error) {
		cmd := exec.Command("bash", script, confURL, "installtest")
		cmd.Env = append(os.Environ(), "HOME="+home, "CC_MYSUB_RELEASE_BASE_URL="+relBase, "CC_MYSUB_SKIP_POLL=1")
		out, err := cmd.CombinedOutput()
		return string(out), err
	}
	caPath := filepath.Join(home, ".config/cc-mysub/ca.crt")

	// 首次:信任 CA-A。
	if out, err := run(); err != nil {
		t.Fatalf("first install: %v\n%s", err, out)
	}
	if b, _ := os.ReadFile(caPath); !strings.Contains(string(b), "AAAFIRSTTRUST") {
		t.Fatalf("ca.crt not first-trusted: %q", b)
	}
	// 重跑同一 CA:幂等,不报错。
	if out, err := run(); err != nil {
		t.Fatalf("rerun with same CA should be idempotent: %v\n%s", err, out)
	}
	// 托管点换成 CA-B:重跑必须拒绝,不覆盖既有 ca.crt。
	setConf(confJSON("ccapi.example.com", "BBBROTATED"))
	out3, err := run()
	if err == nil {
		t.Fatalf("TOFU: rerun with rotated CA must be rejected, out=%s", out3)
	}
	if !strings.Contains(out3, "拒绝静默轮换信任锚") {
		t.Errorf("缺少 TOFU 拒绝信任锚轮换的报错: %s", out3)
	}
	b, _ := os.ReadFile(caPath)
	if strings.Contains(string(b), "BBBROTATED") || !strings.Contains(string(b), "AAAFIRSTTRUST") {
		t.Errorf("ca.crt must remain the first-trusted CA, got: %q", b)
	}
}

// stallingTCPServer 起一个接受 TCP 但不读不写的停滞服务器(模拟 blackhole:握手不应答),返回端口。
func stallingTCPServer(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	var mu sync.Mutex
	var held []net.Conn
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			held = append(held, c)
			mu.Unlock()
		}
	}()
	t.Cleanup(func() {
		ln.Close()
		mu.Lock()
		for _, c := range held {
			c.Close()
		}
		mu.Unlock()
	})
	return port
}

// selfSignedTLSServer 起一个自签证书(不在系统信任内)的 TLS 服务器,握手成功后对 CONNECT 回 200
// (模拟「任意能答 CONNECT 200 的 TLS 端点」)。返回端口。
func selfSignedTLSServer(t *testing.T) int {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "rogue-endpoint"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cfg := &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}},
		ClientAuth:   tls.RequestClientCert,
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				tc := tls.Server(c, cfg)
				if err := tc.Handshake(); err != nil {
					return // 修复后客户端 -verify_return_error 在此中止握手
				}
				br := bufio.NewReader(tc)
				_, _ = br.ReadString('\n') // 读 CONNECT 行
				_, _ = tc.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n"))
				time.Sleep(500 * time.Millisecond)
			}(c)
		}
	}()
	t.Cleanup(func() { ln.Close() })
	return port
}

// TestInstall_ProbeBlackhole_WatchdogFastFails(id 28):探针看门狗令握手停滞(blackhole)的 host
// 在 CC_MYSUB_PROBE_TIMEOUT 内被判 unreachable 并快退,而非吊死在 OS TCP/TLS 读超时上。
// 无看门狗时 openssl 会无限阻塞,install 永不退出 → 被 ctx 杀 → 本测试失败。
func TestInstall_ProbeBlackhole_WatchdogFastFails(t *testing.T) {
	if plat() == "" {
		t.Skip("unsupported platform")
	}
	port := stallingTCPServer(t)
	binBytes := buildRealBin(t)
	relBase := startReleaseMock(t, "redcontritio/cc-mysub", "v0.0.0-test", binBytes, true)
	confURL := startConfigMock(t, confJSON("127.0.0.1", "ABC"))
	repoRoot, _ := filepath.Abs("../..")
	home := t.TempDir()
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "bash", filepath.Join(repoRoot, "install.sh"), confURL, "installtest")
	cmd.Env = append(os.Environ(),
		"HOME="+home,
		"CC_MYSUB_RELEASE_BASE_URL="+relBase,
		"CC_MYSUB_PROBE_PORT="+strconv.Itoa(port),
		"CC_MYSUB_PROBE_TIMEOUT=2",
	) // 不设 CC_MYSUB_SKIP_POLL:真走轮询,探针打到停滞服务器
	start := time.Now()
	out, err := cmd.CombinedOutput()
	elapsed := time.Since(start)
	if ctx.Err() == context.DeadlineExceeded {
		t.Fatalf("install 未快退(被 90s ctx 杀)——看门狗没把停滞 host 判 unreachable\n%s", out)
	}
	if err == nil {
		t.Fatalf("expected non-zero exit on blackhole host, out=%s", out)
	}
	if elapsed > 60*time.Second {
		t.Errorf("watchdog fast-fail 太慢: %v (PROBE_TIMEOUT=2)", elapsed)
	}
	if !strings.Contains(string(out), "无法连接") {
		t.Errorf("缺少不可达提示: %s", out)
	}
	if _, e := os.Stat(filepath.Join(home, ".local/bin/myclaude")); e == nil {
		t.Errorf("myclaude must NOT be written when host never reachable")
	}
}

// TestInstall_ProbeUntrustedServerCert_NotApproved(id 29):探针用系统信任验真服务端证书。
// 不受信(自签)的 TLS 端点即便答 CONNECT 200 也不得被当成已批准 → install 非零退出、不写 myclaude。
// 回归(无 -verify_return_error)时该端点会被误判已批准并写 myclaude → 本测试随即失败。
func TestInstall_ProbeUntrustedServerCert_NotApproved(t *testing.T) {
	if plat() == "" {
		t.Skip("unsupported platform")
	}
	port := selfSignedTLSServer(t)
	binBytes := buildRealBin(t)
	relBase := startReleaseMock(t, "redcontritio/cc-mysub", "v0.0.0-test", binBytes, true)
	confURL := startConfigMock(t, confJSON("127.0.0.1", "ABC"))
	repoRoot, _ := filepath.Abs("../..")
	home := t.TempDir()
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "bash", filepath.Join(repoRoot, "install.sh"), confURL, "installtest")
	cmd.Env = append(os.Environ(),
		"HOME="+home,
		"CC_MYSUB_RELEASE_BASE_URL="+relBase,
		"CC_MYSUB_PROBE_PORT="+strconv.Itoa(port),
		"CC_MYSUB_PROBE_TIMEOUT=4",
	)
	out, err := cmd.CombinedOutput()
	if ctx.Err() == context.DeadlineExceeded {
		t.Fatalf("install hung against rogue TLS endpoint\n%s", out)
	}
	if err == nil {
		t.Fatalf("未验证的 TLS 端点被当成已批准(应拒): out=%s", out)
	}
	if _, e := os.Stat(filepath.Join(home, ".local/bin/myclaude")); e == nil {
		t.Errorf("myclaude must NOT be written for an unverified server endpoint")
	}
}
