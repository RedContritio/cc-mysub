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
	p := Params{PublicHost: "h", SubType: "max"}
	out, err := RenderWrapper(p, filepath.Join("${HOME}", ".config", "cc-mysub", "ca.crt"),
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

// TestWrapperBootstrapInlineCANoInjection 验证内联 CA 的单引号 heredoc 中和 shell 注入(spec §8
// 点名契约):含 $(...)/反引号/; 的 CA PEM 必须逐字落盘、绝不被展开或执行。
func TestWrapperBootstrapInlineCANoInjection(t *testing.T) {
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash not available")
	}
	srv, _ := mockBinaryServer(t)
	defer srv.Close()
	home := t.TempDir()
	sha := sha256hex([]byte(stubBinary))
	sentinel := filepath.Join(home, "PWNED")
	evilPEM := "-----BEGIN CERTIFICATE-----\nLINE-$(touch " + sentinel + ")\n`touch " + sentinel + "`\n; rm -rf should-not-run\n-----END CERTIFICATE-----"
	tbl := map[string]string{"linux-amd64": sha, "linux-arm64": sha, "darwin-amd64": sha, "darwin-arm64": sha}
	p := Params{PublicHost: "h", SubType: "max"}
	wrapper, err := RenderWrapper(p, filepath.Join("${HOME}", ".config", "cc-mysub", "ca.crt"), evilPEM, tbl, "vtest", srv.URL)
	if err != nil {
		t.Fatalf("RenderWrapper: %v", err)
	}
	out, err := runWrapper(t, wrapper, home, "")
	if err != nil {
		t.Fatalf("wrapper failed: %v\n%s", err, out)
	}
	// $(...)/`...` 绝不能执行(单引号 heredoc 中和)。
	if _, statErr := os.Stat(sentinel); statErr == nil {
		t.Error("CA PEM 中的 $(...)/`...` 被执行了 — 单引号 heredoc 注入防护失效")
	}
	// CA 须逐字落盘(元字符原样保留)。
	caBytes, err := os.ReadFile(filepath.Join(home, ".config", "cc-mysub", "ca.crt"))
	if err != nil {
		t.Fatalf("CA not written: %v", err)
	}
	if !strings.Contains(string(caBytes), "$(touch") || !strings.Contains(string(caBytes), "`touch") {
		t.Errorf("CA 未逐字落盘(元字符应原样保留):\n%s", caBytes)
	}
}

// TestWrapperBootstrapStaleBinaryRedownloads 验证 D5 升级 linchpin:已存在但 sha 不符的旧二进制
// (换新 wrapper 场景)触发重下载 + 校验,绝不 exec 旧版本。
func TestWrapperBootstrapStaleBinaryRedownloads(t *testing.T) {
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash not available")
	}
	srv, hits := mockBinaryServer(t)
	defer srv.Close()
	home := t.TempDir()
	sha := sha256hex([]byte(stubBinary))
	bin := filepath.Join(home, ".local", "bin", "cc-mysub")
	if err := os.MkdirAll(filepath.Dir(bin), 0o755); err != nil {
		t.Fatal(err)
	}
	// 预置 sha 不符的旧二进制(模拟升级:新 wrapper 钉的 sha ≠ 旧缓存)。
	if err := os.WriteFile(bin, []byte("#!/bin/sh\necho STALE_OLD_BINARY\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	wrapper := renderBootstrap(t, srv.URL, sha) // 烤入 stub 真 sha
	out, err := runWrapper(t, wrapper, home, "")
	if err != nil {
		t.Fatalf("wrapper failed: %v\n%s", err, out)
	}
	if *hits != 1 {
		t.Errorf("stale binary must trigger exactly 1 re-download, got %d", *hits)
	}
	if !strings.Contains(out, stubMarker) {
		t.Errorf("re-downloaded stub not exec'd:\n%s", out)
	}
	if strings.Contains(out, "STALE_OLD_BINARY") {
		t.Errorf("stale binary exec'd instead of re-downloading (upgrade broken):\n%s", out)
	}
	b, err := os.ReadFile(bin)
	if err != nil {
		t.Fatalf("binary missing: %v", err)
	}
	if sha256hex(b) != sha {
		t.Errorf("cached binary not replaced with correct version after upgrade")
	}
}

// TestWrapperBootstrapDownloadFailureFailsClosed 验证 §6 fail-closed:二进制下载失败(404)→
// 非零退出 + 不 exec + 不留缓存。
func TestWrapperBootstrapDownloadFailureFailsClosed(t *testing.T) {
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash not available")
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r) // 所有路径 404 → 下载失败
	}))
	defer srv.Close()
	home := t.TempDir()
	wrapper := renderBootstrap(t, srv.URL, strings.Repeat("a", 64))
	out, err := runWrapper(t, wrapper, home, "")
	if err == nil {
		t.Fatalf("expected non-zero exit on download failure; output:\n%s", out)
	}
	if strings.Contains(out, stubMarker) {
		t.Errorf("stub exec'd despite download failure:\n%s", out)
	}
	if _, statErr := os.Stat(filepath.Join(home, ".local", "bin", "cc-mysub")); statErr == nil {
		t.Error("binary cached despite download failure (not fail-closed)")
	}
	if !strings.Contains(out, "下载失败") {
		t.Errorf("download failure not anchored to fetch branch:\n%s", out)
	}
}

// TestWrapperBootstrapMissingHashToolFailsClosed 验证 §4.4 点名的 no-bypass 契约:两个 sha
// 工具(sha256sum + shasum)皆缺时,verify_sha 走 else 分支 return 1(绝不落到 [ "" = "" ]
// 为真的旁路),fail-closed——守护 §7 供应链不变量#1。用受限 PATH(symlink 所需工具但排除两个
// hash 工具)模拟精简容器/CI 镜像。
func TestWrapperBootstrapMissingHashToolFailsClosed(t *testing.T) {
	bashPath, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("bash not available")
	}
	// 受限 PATH:含 bootstrap 所需工具,刻意排除 sha256sum + shasum。
	binDir := t.TempDir()
	const fetcherCurl, fetcherWget = "curl", "wget"
	needed := []string{"bash", "env", "awk", "mkdir", "mktemp", "cat", "cmp", "mv", "rm", "dirname", "uname", "chmod", fetcherCurl, fetcherWget}
	haveFetcher := false
	for _, tool := range needed {
		p, lookErr := exec.LookPath(tool)
		if lookErr != nil {
			continue // 本机无该工具(curl/wget 二选一即可)
		}
		if tool == fetcherCurl || tool == fetcherWget {
			haveFetcher = true
		}
		if err := os.Symlink(p, filepath.Join(binDir, tool)); err != nil {
			t.Fatal(err)
		}
	}
	for _, req := range []string{"bash", "mktemp", "cat", "mv", "uname", "awk", "cmp", "mkdir", "rm", "dirname", "chmod"} {
		if _, statErr := os.Stat(filepath.Join(binDir, req)); statErr != nil {
			t.Skipf("host 缺 %q,无法构造受限 PATH 测试", req)
		}
	}
	if !haveFetcher {
		t.Skip("host 既无 curl 也无 wget")
	}
	// 确认受限 PATH 里确实无 hash 工具(否则测试无意义)。
	for _, banned := range []string{"sha256sum", "shasum"} {
		if _, statErr := os.Stat(filepath.Join(binDir, banned)); statErr == nil {
			t.Fatalf("restricted PATH 意外含 %s", banned)
		}
	}

	srv, _ := mockBinaryServer(t)
	defer srv.Close()
	home := t.TempDir()
	sha := sha256hex([]byte(stubBinary))
	wrapper := renderBootstrap(t, srv.URL, sha)
	wf := filepath.Join(t.TempDir(), "myclaude")
	if err := os.WriteFile(wf, []byte(wrapper), 0o755); err != nil {
		t.Fatal(err)
	}
	// PATH 只含 binDir(无 hash 工具);用绝对 bash 路径启动,不依赖 PATH 找 bash。
	cmd := exec.Command(bashPath, wf)
	cmd.Env = append(os.Environ(), "HOME="+home, "PATH="+binDir)
	b, runErr := cmd.CombinedOutput()
	out := string(b)
	if runErr == nil {
		t.Fatalf("expected non-zero exit when hash tools absent; output:\n%s", out)
	}
	if strings.Contains(out, stubMarker) {
		t.Errorf("stub exec'd despite missing hash tools (NOT fail-closed):\n%s", out)
	}
	if _, statErr := os.Stat(filepath.Join(home, ".local", "bin", "cc-mysub")); statErr == nil {
		t.Error("binary cached despite missing hash tools (not fail-closed)")
	}
	if !strings.Contains(out, "需要 sha256sum 或 shasum") {
		t.Errorf("missing-hash-tool 失败未锚定到 verify_sha 工具缺失分支:\n%s", out)
	}
}

// TestRenderWrapperFleetGeneric 验证通用 wrapper 无 per-device 秘密：对两个不同 label（其余输入相同）
// 渲染, 输出必须字节相同——任何 per-device 值(旧 token/指纹)悄悄烤入都会破坏此不变量。RenderWrapper
// 不接 Label 入参, 此测试钉死「设备身份由 mTLS 客户端证书承载、绝不进 wrapper」的契约。
func TestRenderWrapperFleetGeneric(t *testing.T) {
	caPEM := "-----BEGIN CERTIFICATE-----\nabc\n-----END CERTIFICATE-----"
	tbl := map[string]string{
		"linux-amd64":  strings.Repeat("a", 64),
		"linux-arm64":  strings.Repeat("b", 64),
		"darwin-amd64": strings.Repeat("c", 64),
		"darwin-arm64": strings.Repeat("d", 64),
	}
	caPath := filepath.Join("${HOME}", ".config", "cc-mysub", "ca.crt")
	relBase := "https://x/releases/download/v1"
	w1, err := RenderWrapper(Params{Label: "alpha", PublicHost: "h", SubType: "max"}, caPath, caPEM, tbl, "v1", relBase)
	if err != nil {
		t.Fatalf("RenderWrapper(alpha): %v", err)
	}
	w2, err := RenderWrapper(Params{Label: "bravo", PublicHost: "h", SubType: "max"}, caPath, caPEM, tbl, "v1", relBase)
	if err != nil {
		t.Fatalf("RenderWrapper(bravo): %v", err)
	}
	if w1 != w2 {
		t.Error("wrapper not fleet-generic: differing labels produced differing bytes (per-device secret leaked)")
	}
}
