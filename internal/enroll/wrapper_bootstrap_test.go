package enroll

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
)

// stubBinary 是 mock「cc-mysub 二进制」：被 wrapper 末行 exec 为 helper, 仅打印 marker 退出 0。
const stubBinary = "#!/bin/sh\necho CC_MYSUB_STUB_RAN\nexit 0\n"
const stubMarker = "CC_MYSUB_STUB_RAN"

// curPlatform 返回当前 Go 运行平台的 wrapper 平台键（与 uname case 映射一致）。
func curPlatform(t *testing.T) string {
	t.Helper()
	return runtime.GOOS + "-" + runtime.GOARCH
}

func sha256hex(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

// renderBootstrap 渲染一个 releaseBase 指向给定 URL、当前平台 sha 为 sha 的 wrapper。
func renderBootstrap(t *testing.T, releaseBase, sha string) string {
	t.Helper()
	tbl := map[string]string{
		"linux-amd64":  strings.Repeat("0", 64),
		"linux-arm64":  strings.Repeat("0", 64),
		"darwin-amd64": strings.Repeat("0", 64),
		"darwin-arm64": strings.Repeat("0", 64),
	}
	tbl[curPlatform(t)] = sha
	p := Params{PublicHost: "h", FrpsIP: "1.2.3.4", ProxyPort: 8788, SubType: "max"}
	out, err := RenderWrapper(p, "cco_dev_x", filepath.Join("${HOME}", ".config", "cc-mysub", "ca.crt"),
		"-----BEGIN CERTIFICATE-----\nabc\n-----END CERTIFICATE-----", tbl, "vtest", releaseBase)
	if err != nil {
		t.Fatalf("RenderWrapper: %v", err)
	}
	return out
}

// runWrapper 在隔离 HOME 下真 bash 跑 wrapper, 返回合并输出 + error。extraPATHDir 非空则前置到 PATH。
func runWrapper(t *testing.T, wrapper, home, extraPATHDir string) (string, error) {
	t.Helper()
	wf := filepath.Join(t.TempDir(), "myclaude")
	if err := os.WriteFile(wf, []byte(wrapper), 0o755); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("bash", wf)
	env := append(os.Environ(), "HOME="+home)
	if extraPATHDir != "" {
		env = append(env, "PATH="+extraPATHDir+":"+os.Getenv("PATH"))
	}
	cmd.Env = env
	b, err := cmd.CombinedOutput()
	return string(b), err
}

// mockBinaryServer 提供 /cc-mysub-<plat> = stub 字节, 记录命中次数。
func mockBinaryServer(t *testing.T) (*httptest.Server, *int) {
	t.Helper()
	var mu sync.Mutex
	hits := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/cc-mysub-") {
			mu.Lock()
			hits++
			mu.Unlock()
			_, _ = w.Write([]byte(stubBinary))
			return
		}
		http.NotFound(w, r)
	}))
	return srv, &hits
}

func TestWrapperBootstrapCorrectSha(t *testing.T) {
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash not available")
	}
	srv, hits := mockBinaryServer(t)
	defer srv.Close()
	home := t.TempDir()
	wrapper := renderBootstrap(t, srv.URL, sha256hex([]byte(stubBinary)))

	out, err := runWrapper(t, wrapper, home, "")
	if err != nil {
		t.Fatalf("wrapper failed: %v\n%s", err, out)
	}
	if !strings.Contains(out, stubMarker) {
		t.Errorf("stub not exec'd; output:\n%s", out)
	}
	if _, err := os.Stat(filepath.Join(home, ".local", "bin", "cc-mysub")); err != nil {
		t.Errorf("binary not cached: %v", err)
	}
	if *hits != 1 {
		t.Errorf("expected exactly 1 download, got %d", *hits)
	}
	// 内联 CA 写出
	if _, err := os.Stat(filepath.Join(home, ".config", "cc-mysub", "ca.crt")); err != nil {
		t.Errorf("inlined CA not written: %v", err)
	}
}

func TestWrapperBootstrapWrongShaFailsClosed(t *testing.T) {
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash not available")
	}
	srv, _ := mockBinaryServer(t)
	defer srv.Close()
	home := t.TempDir()
	// 烤入与 stub 不符的 sha → 校验失败 → fail-closed。
	wrapper := renderBootstrap(t, srv.URL, strings.Repeat("e", 64))

	out, err := runWrapper(t, wrapper, home, "")
	if err == nil {
		t.Fatalf("expected non-zero exit on sha mismatch; output:\n%s", out)
	}
	if strings.Contains(out, stubMarker) {
		t.Errorf("stub exec'd despite sha mismatch (NOT fail-closed):\n%s", out)
	}
	if _, err := os.Stat(filepath.Join(home, ".local", "bin", "cc-mysub")); err == nil {
		t.Errorf("corrupt binary left in cache after fail-closed")
	}
	// 把失败钉到供应链 sha 分支——否则任意非零退出(如 CA 写失败)也能让本测试绿过、掩盖回归。
	if !strings.Contains(out, "sha256 校验失败") {
		t.Errorf("fail-closed 退出原因未锚定到 sha 校验分支:\n%s", out)
	}
}

func TestWrapperBootstrapIdempotentSkipsDownload(t *testing.T) {
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash not available")
	}
	srv, hits := mockBinaryServer(t)
	defer srv.Close()
	home := t.TempDir()
	sha := sha256hex([]byte(stubBinary))
	// 预置已就位的 binary（= stub, sha 匹配）。
	bin := filepath.Join(home, ".local", "bin", "cc-mysub")
	if err := os.MkdirAll(filepath.Dir(bin), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(bin, []byte(stubBinary), 0o755); err != nil {
		t.Fatal(err)
	}
	wrapper := renderBootstrap(t, srv.URL, sha)

	out, err := runWrapper(t, wrapper, home, "")
	if err != nil {
		t.Fatalf("wrapper failed: %v\n%s", err, out)
	}
	if *hits != 0 {
		t.Errorf("expected 0 downloads (idempotent skip), got %d", *hits)
	}
	if !strings.Contains(out, stubMarker) {
		t.Errorf("pre-placed binary not exec'd:\n%s", out)
	}
}

func TestWrapperBootstrapUnsupportedPlatform(t *testing.T) {
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash not available")
	}
	srv, _ := mockBinaryServer(t)
	defer srv.Close()
	home := t.TempDir()
	// PATH 前置一个伪 uname, 返回不支持的平台 → case *) exit 1。
	shimDir := t.TempDir()
	shim := "#!/bin/sh\nif [ \"$1\" = \"-s\" ]; then echo Plan9; else echo sparc; fi\n"
	if err := os.WriteFile(filepath.Join(shimDir, "uname"), []byte(shim), 0o755); err != nil {
		t.Fatal(err)
	}
	wrapper := renderBootstrap(t, srv.URL, strings.Repeat("a", 64))

	out, err := runWrapper(t, wrapper, home, shimDir)
	if err == nil {
		t.Fatalf("expected non-zero exit on unsupported platform; output:\n%s", out)
	}
	if !strings.Contains(out, "不支持的平台") {
		t.Errorf("missing unsupported-platform message:\n%s", out)
	}
}

func TestWrapperBootstrapConcurrentFirstRun(t *testing.T) {
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash not available")
	}
	srv, hits := mockBinaryServer(t)
	defer srv.Close()
	home := t.TempDir()
	sha := sha256hex([]byte(stubBinary))
	wrapper := renderBootstrap(t, srv.URL, sha)
	// 主 goroutine 预写 wrapper 文件; goroutine 只跑 bash（t.Fatal 只能从测试主 goroutine 调用，
	// 故 goroutine 内不调用任何 t.* 失败方法，只回收 error）。
	wf := filepath.Join(t.TempDir(), "myclaude")
	if err := os.WriteFile(wf, []byte(wrapper), 0o755); err != nil {
		t.Fatal(err)
	}

	var wg sync.WaitGroup
	errs := make([]error, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			cmd := exec.Command("bash", wf)
			cmd.Env = append(os.Environ(), "HOME="+home)
			_, errs[idx] = cmd.CombinedOutput()
		}(i)
	}
	wg.Wait()
	for i, e := range errs {
		if e != nil {
			t.Errorf("concurrent run %d failed: %v", i, e)
		}
	}
	// 不论交错, 缓存的 binary 必须完整 (sha 匹配), 绝无损坏对象。
	bin := filepath.Join(home, ".local", "bin", "cc-mysub")
	b, err := os.ReadFile(bin)
	if err != nil {
		t.Fatalf("cached binary missing after concurrent runs: %v", err)
	}
	if sha256hex(b) != sha {
		t.Errorf("cached binary corrupt after concurrent first-run (sha mismatch)")
	}
	// 冷缓存并发首跑至少发生 1 次真下载(1 或 2 均可接受)——确认确走了下载路径而非全部误跳过。
	if *hits < 1 {
		t.Errorf("expected ≥1 real download on cold-cache concurrent run, got %d", *hits)
	}
}
