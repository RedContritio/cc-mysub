package enroll

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/redcontritio/cc-mysub/internal/auth"
	"github.com/redcontritio/cc-mysub/internal/config"
)

// fp 把单个 hex 字符重复 64 次，得一个合法的小写 hex 证书指纹（cert_sha256 规范形）。
// 迁移后 AppendDevice/ReplaceDevice 的第三参数语义 = 证书指纹，直接写入 CertSHA256、不再哈希；
// 不同字符 = 不同设备身份，使「换发/旁邻保留」类断言能区分。
func fp(c string) string { return strings.Repeat(c, 64) }

// ---- RenderWrapper ----

func TestRenderWrapperFillsValues(t *testing.T) {
	p := Params{PublicHost: "ccapi.example.com", SubType: "max"}
	const caPath = "${HOME}/.config/cc-mysub/ca.crt"
	const caPEM = "-----BEGIN CERTIFICATE-----\nMIIBfakeCAcontent==\n-----END CERTIFICATE-----"
	shaTable := map[string]string{
		"linux-amd64":  strings.Repeat("a", 64),
		"linux-arm64":  strings.Repeat("b", 64),
		"darwin-amd64": strings.Repeat("c", 64),
		"darwin-arm64": strings.Repeat("d", 64),
	}
	const relBase = "https://example.test/redcontritio/cc-mysub/releases/download/v1.2.3"
	out, err := RenderWrapper(p, caPath, caPEM, shaTable, "v1.2.3", relBase)
	if err != nil {
		t.Fatalf("RenderWrapper: %v", err)
	}
	for _, want := range []string{
		`PUBLIC_HOST="ccapi.example.com"`,
		`SUB_TYPE="max"`,
		`CA_CERT="` + caPath + `"`,
		`RELEASE_BASE="` + relBase + `"`,
		`CLAUDE_CODE_OAUTH_TOKEN="cco_dev_placeholder"`, // fleet-generic 固定占位, 非凭据
		`CLAUDE_CODE_SUBSCRIPTION_TYPE="$SUB_TYPE"`,
		`NODE_EXTRA_CA_CERTS="$CA_CERT"`,
		`DEV_CERT=`,             // 本设备客户端证书路径变量
		`DEV_KEY=`,              // 本设备私钥路径变量
		"device-init",           // 首次入网逻辑
		caPEM,                   // 内联 CA 逐字出现
		"钉定版本: v1.2.3",          // version 注释
		strings.Repeat("d", 64), // darwin-arm64 sha 烤入 case 分支
		"verify_sha",            // bootstrap 助手
		"trap '",                // 清理 trap
		"sha256 校验失败（供应链）",      // fail-closed 分支
		`exec "$CC_MYSUB_BIN" helper --host "$PUBLIC_HOST" --client-cert "$DEV_CERT" --client-key "$DEV_KEY" -- claude "$@"`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("rendered wrapper missing %q\n---\n%s", want, out)
		}
	}
	// 通用 wrapper(无 per-device 秘密) + v4 收口: 旧 token/v3 形态必须彻底删除。
	for _, banned := range []string{
		"DEVICE_TOKEN",                // 旧 per-device token 变量
		"PROXY_ENTRY",                 // 旧 frps 入口变量
		"PRIVATE KEY",                 // 私钥 PEM 绝不内联
		"ANTHROPIC_BASE_URL=https://", // v3 直连形态
		"unshare",
		"/etc/hosts",
		`exec cc-mysub helper`, // 旧的裸命令(无 $CC_MYSUB_BIN)形态
	} {
		if strings.Contains(out, banned) {
			t.Errorf("rendered wrapper still contains obsolete/leaky token %q\n---\n%s", banned, out)
		}
	}
	// 不得有任何 per-device 真 token 烤入: 只允许固定占位, 不得出现 cco_dev_<hex> 凭据形态。
	if realTok := regexp.MustCompile(`cco_dev_[0-9a-f]{16,}`).FindString(out); realTok != "" {
		t.Errorf("rendered wrapper embeds a real per-device token %q (must be fleet-generic)", realTok)
	}
}

// 核心契约: 工具绝不替用户预设小模型。
func TestRenderWrapperDoesNotDecideSmallModel(t *testing.T) {
	out, err := RenderWrapper(
		Params{PublicHost: "h", SubType: "max"},
		"/dev/null", "PEM", map[string]string{}, "v0", "https://x/releases/download/v0")
	if err != nil {
		t.Fatalf("RenderWrapper: %v", err)
	}
	if strings.Contains(out, "claude-haiku") {
		t.Errorf("wrapper bakes in a concrete small model (claude-haiku); must not decide for user\n%s", out)
	}
	// 不得有任何【未注释】的 ANTHROPIC_SMALL_FAST_MODEL 赋值/导出。
	active := regexp.MustCompile(`(?m)^\s*(export\s+)?ANTHROPIC_SMALL_FAST_MODEL=`)
	for _, line := range strings.Split(out, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "#") {
			continue // 注释里给个 <placeholder> 示例是允许的
		}
		if active.MatchString(line) {
			t.Errorf("wrapper actively sets ANTHROPIC_SMALL_FAST_MODEL (decides for user): %q", line)
		}
	}
}

func TestRenderWrapperIsValidBash(t *testing.T) {
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash not available")
	}
	out, err := RenderWrapper(
		Params{PublicHost: "h", SubType: "max"},
		"/dev/null", "-----BEGIN CERTIFICATE-----\nabc\n-----END CERTIFICATE-----",
		map[string]string{"linux-amd64": strings.Repeat("a", 64), "linux-arm64": strings.Repeat("b", 64),
			"darwin-amd64": strings.Repeat("c", 64), "darwin-arm64": strings.Repeat("d", 64)},
		"v1", "https://x/releases/download/v1")
	if err != nil {
		t.Fatalf("RenderWrapper: %v", err)
	}
	f := filepath.Join(t.TempDir(), "myclaude")
	if err := os.WriteFile(f, []byte(out), 0o755); err != nil {
		t.Fatal(err)
	}
	if b, err := exec.Command("bash", "-n", f).CombinedOutput(); err != nil {
		t.Errorf("rendered wrapper is not valid bash: %v\n%s", err, b)
	}
}

// ---- AppendDevice ----

func readDevices(t *testing.T, path string) []auth.Device {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read devices: %v", err)
	}
	var list []auth.Device
	if err := json.Unmarshal(b, &list); err != nil {
		t.Fatalf("parse devices: %v", err)
	}
	return list
}

func TestAppendDeviceCreatesFileWithFingerprint(t *testing.T) {
	path := filepath.Join(t.TempDir(), "devices.json")
	p := Params{Label: "laptop", PublicHost: "h", SubType: "max", RateLimit: 120}
	cert := fp("a")
	if err := AppendDevice(path, p, cert); err != nil {
		t.Fatalf("AppendDevice: %v", err)
	}
	list := readDevices(t, path)
	if len(list) != 1 {
		t.Fatalf("want 1 device, got %d", len(list))
	}
	d := list[0]
	if d.Label != "laptop" || d.RateLimit != 120 {
		t.Errorf("unexpected device %+v", d)
	}
	// 第三参数语义 = 证书指纹: 直接落盘到 cert_sha256, 不再哈希。
	if d.CertSHA256 != cert {
		t.Errorf("stored cert_sha256 %q != fingerprint %q", d.CertSHA256, cert)
	}
}

func TestAppendDevicePreservesExisting(t *testing.T) {
	path := filepath.Join(t.TempDir(), "devices.json")
	must(t, AppendDevice(path, Params{Label: "a", PublicHost: "h", SubType: "max"}, fp("a")))
	must(t, AppendDevice(path, Params{Label: "b", PublicHost: "h", SubType: "max"}, fp("b")))
	list := readDevices(t, path)
	if len(list) != 2 {
		t.Fatalf("want 2 devices, got %d", len(list))
	}
	if list[0].Label != "a" || list[1].Label != "b" {
		t.Errorf("order/content wrong: %+v", list)
	}
}

// TestAppendDeviceStoresUpstream 验证 Params.Upstream 写入设备记录（决定该设备抽哪个 setup-token）。
func TestAppendDeviceStoresUpstream(t *testing.T) {
	path := filepath.Join(t.TempDir(), "devices.json")
	p := Params{Label: "work", PublicHost: "h", SubType: "max", Upstream: "team-b"}
	must(t, AppendDevice(path, p, fp("a")))
	list := readDevices(t, path)
	if len(list) != 1 || list[0].Upstream != "team-b" {
		t.Fatalf("device upstream not persisted: %+v", list)
	}
}

func TestAppendDeviceRejectsDuplicateLabel(t *testing.T) {
	path := filepath.Join(t.TempDir(), "devices.json")
	must(t, AppendDevice(path, Params{Label: "dup", PublicHost: "h", SubType: "max"}, fp("1")))
	err := AppendDevice(path, Params{Label: "dup", PublicHost: "h", SubType: "max"}, fp("2"))
	if err == nil {
		t.Fatalf("expected error on duplicate label, got nil")
	}
	if !strings.Contains(err.Error(), "dup") {
		t.Errorf("error should mention the duplicate label: %v", err)
	}
}

func TestReplaceDeviceErrorsWhenLabelAbsent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "devices.json")
	must(t, AppendDevice(path, Params{Label: "a", PublicHost: "h", SubType: "max"}, fp("a")))
	err := ReplaceDevice(path, Params{Label: "ghost", PublicHost: "h", SubType: "max"}, fp("9"))
	if err == nil {
		t.Fatal("expected error rotating an absent label, got nil")
	}
	if !strings.Contains(err.Error(), "ghost") {
		t.Errorf("error should mention the absent label, got: %v", err)
	}
	// 失败的 rotate 须零副作用：原设备 a 完好、未半截写入。
	list := readDevices(t, path)
	if len(list) != 1 || list[0].Label != "a" || list[0].CertSHA256 != fp("a") {
		t.Errorf("failed rotate must be side-effect-free; devices.json mutated: %+v", list)
	}
}

func TestReplaceDeviceSwapsFingerprint(t *testing.T) {
	path := filepath.Join(t.TempDir(), "devices.json")
	must(t, AppendDevice(path, Params{Label: "a", PublicHost: "h", SubType: "max"}, fp("a")))
	must(t, ReplaceDevice(path, Params{Label: "a", PublicHost: "h", SubType: "max"}, fp("b")))
	list := readDevices(t, path)
	if len(list) != 1 {
		t.Fatalf("want 1 device after rotate, got %d", len(list))
	}
	if list[0].CertSHA256 != fp("b") {
		t.Errorf("fingerprint not swapped to new")
	}
}

// TestReplaceDevicePreservesSiblings 验证 rotate 只动目标 label：换发 target 后，同库其它设备行
// (keep) 的指纹必须原封不动、仍命中。守护「rotate 误伤旁邻设备 = 静默大规模 lockout / 凭据丢失」
// 这一灾难性回归——对抗 review 变异验证发现：核心契约外，sibling-preservation 此前无守护
// (把 ReplaceDevice 改成丢弃全部行 + 追加新行的回归能通过整包测试)。
func TestReplaceDevicePreservesSiblings(t *testing.T) {
	path := filepath.Join(t.TempDir(), "devices.json")
	must(t, AppendDevice(path, Params{Label: "keep", PublicHost: "h", SubType: "max"}, fp("c")))
	must(t, AppendDevice(path, Params{Label: "target", PublicHost: "h", SubType: "max"}, fp("d")))

	must(t, ReplaceDevice(path, Params{Label: "target", PublicHost: "h", SubType: "max"}, fp("e")))

	list := readDevices(t, path)
	if len(list) != 2 {
		t.Fatalf("rotate must preserve sibling; want 2 devices, got %d: %+v", len(list), list)
	}
	byLabel := map[string]auth.Device{}
	for _, d := range list {
		byLabel[d.Label] = d
	}
	if byLabel["keep"].CertSHA256 != fp("c") {
		t.Errorf("sibling 'keep' fingerprint altered by rotate of 'target' (mass-revocation regression)")
	}
	if byLabel["target"].CertSHA256 != fp("e") {
		t.Errorf("target fingerprint not swapped to new")
	}
	if byLabel["target"].CertSHA256 == fp("d") {
		t.Errorf("target still carries old fingerprint after rotate")
	}
}

// ---- Resolve ----

func TestResolveFlagOverridesConfig(t *testing.T) {
	def := &config.ClientConfig{PublicHost: "cfg.example.com", SubscriptionType: "max"}
	got, err := Resolve(def, Params{Label: "x", SubType: "pro"})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if got.PublicHost != "cfg.example.com" {
		t.Errorf("config defaults not applied: %+v", got)
	}
	if got.SubType != "pro" {
		t.Errorf("flag override not applied, want pro got %q", got.SubType)
	}
}

func TestResolveUsesConfigWhenNoFlags(t *testing.T) {
	def := &config.ClientConfig{PublicHost: "cfg.example.com", SubscriptionType: "max"}
	got, err := Resolve(def, Params{Label: "x"})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if got.PublicHost != "cfg.example.com" || got.SubType != "max" {
		t.Errorf("config not used as default: %+v", got)
	}
}

func TestResolveRequiresLabel(t *testing.T) {
	def := &config.ClientConfig{PublicHost: "h", SubscriptionType: "max"}
	if _, err := Resolve(def, Params{}); err == nil {
		t.Errorf("expected error when label missing")
	}
}

func TestResolveRequiresHostSub(t *testing.T) {
	cases := map[string]*config.ClientConfig{
		"no host": {SubscriptionType: "max"},
		"no sub":  {PublicHost: "h"},
		"nil cfg": nil,
	}
	for name, def := range cases {
		if _, err := Resolve(def, Params{Label: "x"}); err == nil {
			t.Errorf("%s: expected error for missing required field", name)
		}
	}
}

// TestResolveReleaseRepoDefault 验证 release_repo 缺省回退默认仓库，config/flag 给值则优先。
func TestResolveReleaseRepoDefault(t *testing.T) {
	def := &config.ClientConfig{PublicHost: "h", SubscriptionType: "max"}
	got, err := Resolve(def, Params{Label: "x"})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if got.ReleaseRepo != "redcontritio/cc-mysub" {
		t.Errorf("default ReleaseRepo = %q, want redcontritio/cc-mysub", got.ReleaseRepo)
	}
	def2 := &config.ClientConfig{PublicHost: "h", SubscriptionType: "max", ReleaseRepo: "acme/cc-mysub"}
	got2, err := Resolve(def2, Params{Label: "x"})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if got2.ReleaseRepo != "acme/cc-mysub" {
		t.Errorf("config ReleaseRepo = %q, want acme/cc-mysub", got2.ReleaseRepo)
	}
	// flag override 优先于 config
	got3, err := Resolve(def2, Params{Label: "x", ReleaseRepo: "flag/repo"})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if got3.ReleaseRepo != "flag/repo" {
		t.Errorf("flag override ReleaseRepo = %q, want flag/repo", got3.ReleaseRepo)
	}
}

// ---- Run (integration) ----

// sumsServer 返回一个仅对 /SHA256SUMS 回 validSums() 的 httptest server，复用现有 manifest mock 机制。
func sumsServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/SHA256SUMS") {
			io.WriteString(w, validSums())
			return
		}
		http.NotFound(w, r)
	}))
}

func TestRunEndToEnd(t *testing.T) {
	srv := sumsServer(t)
	defer srv.Close()
	t.Setenv("CC_MYSUB_RELEASE_BASE_URL", srv.URL)

	cfgDir := t.TempDir()
	must(t, os.WriteFile(filepath.Join(cfgDir, "config.json"),
		[]byte(`{"listen":"127.0.0.1:8788","client":{"public_host":"ccapi.example.com","subscription_type":"max"}}`), 0o644))

	outDir := t.TempDir()
	wrapperPath := filepath.Join(outDir, "myclaude-laptop")
	// 真实形态的混合 hex 指纹, 刻意区别于 validSums() 的 a/b/c/d*64 平台 sha, 以使
	// 「wrapper 不含 per-device 指纹」断言不被 sha 表巧合命中。
	const cert = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
	var sb strings.Builder
	err := Run([]string{"--label", "laptop", "--release", "v1.0.0", "--fingerprint", cert, "--out", wrapperPath}, cfgDir, &sb)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	// devices.json 落了一条, cert_sha256 = 传入的指纹（直接相等, 不哈希）。
	list := readDevices(t, filepath.Join(cfgDir, "devices.json"))
	if len(list) != 1 || list[0].Label != "laptop" {
		t.Fatalf("devices.json not written correctly: %+v", list)
	}
	if list[0].CertSHA256 != cert {
		t.Errorf("stored cert_sha256 %q != fingerprint %q", list[0].CertSHA256, cert)
	}

	// wrapper 文件写出。
	if _, err := os.Stat(wrapperPath); err != nil {
		t.Fatalf("wrapper not written: %v", err)
	}
	w := string(mustRead(t, wrapperPath))
	if !strings.Contains(w, `PUBLIC_HOST="ccapi.example.com"`) || !strings.Contains(w, `SUB_TYPE="max"`) {
		t.Errorf("wrapper not filled from config: \n%s", w)
	}
	// v4 mTLS helper 形态: exec 行 + fleet-generic 占位 token, 不得残留 v3 直连/隔离形态。
	if !strings.Contains(w, `exec "$CC_MYSUB_BIN" helper --host "$PUBLIC_HOST" --client-cert "$DEV_CERT" --client-key "$DEV_KEY" -- claude "$@"`) {
		t.Errorf("wrapper missing v4 mTLS helper exec line:\n%s", w)
	}
	if !strings.Contains(w, `CLAUDE_CODE_OAUTH_TOKEN="cco_dev_placeholder"`) {
		t.Errorf("wrapper missing fleet-generic placeholder token:\n%s", w)
	}
	if strings.Contains(w, "ANTHROPIC_BASE_URL=https://") || strings.Contains(w, "unshare") {
		t.Errorf("wrapper still contains obsolete v3 form:\n%s", w)
	}
	// fleet-generic: per-device 指纹是服务端身份, 绝不泄漏进通用 wrapper。
	if strings.Contains(w, cert) {
		t.Errorf("wrapper leaked the per-device fingerprint (must be fleet-generic):\n%s", w)
	}
	// §7 硬不变量: 私钥 ca.key 绝不内联(只内联公 ca.crt)。负向守护:误把 serverCACertPath 指向
	// key、或多读 ca.key 内联的回归须被抓到。
	if strings.Contains(w, "PRIVATE KEY") {
		t.Errorf("wrapper leaked a private-key PEM (ca.key must never be inlined):\n%s", w)
	}
	if keyPEM, err := os.ReadFile(filepath.Join(cfgDir, "ca.key")); err == nil && strings.Contains(w, strings.TrimSpace(string(keyPEM))) {
		t.Errorf("wrapper embeds ca.key content (private-key leak)")
	}

	// add-device 首次运行须落 cc-mysub CA（ca.crt + ca.key, key 0600）。
	if _, err := os.Stat(filepath.Join(cfgDir, "ca.crt")); err != nil {
		t.Errorf("ca.crt not generated: %v", err)
	}
	keyFI, err := os.Stat(filepath.Join(cfgDir, "ca.key"))
	if err != nil {
		t.Fatalf("ca.key not generated: %v", err)
	}
	if keyFI.Mode().Perm() != 0o600 {
		t.Errorf("ca.key mode = %v, want 0600", keyFI.Mode().Perm())
	}

	// 打印输出登记了该设备指纹。
	if !strings.Contains(sb.String(), cert) {
		t.Errorf("printed output does not mention the registered fingerprint:\n%s", sb.String())
	}
}

// TestRunAssignsUpstream 验证 --upstream 写入 devices.json 的 upstream 字段。
func TestRunAssignsUpstream(t *testing.T) {
	srv := sumsServer(t)
	defer srv.Close()
	t.Setenv("CC_MYSUB_RELEASE_BASE_URL", srv.URL)

	cfgDir := t.TempDir()
	must(t, os.WriteFile(filepath.Join(cfgDir, "config.json"),
		[]byte(`{"listen":"127.0.0.1:8788","client":{"public_host":"ccapi.example.com","subscription_type":"max"}}`), 0o644))

	wrapperPath := filepath.Join(t.TempDir(), "myclaude-work")
	cert := fp("b")
	var sb strings.Builder
	err := Run([]string{"--label", "work", "--upstream", "b", "--release", "v1.0.0", "--fingerprint", cert, "--out", wrapperPath}, cfgDir, &sb)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	list := readDevices(t, filepath.Join(cfgDir, "devices.json"))
	if len(list) != 1 || list[0].Upstream != "b" {
		t.Fatalf("--upstream b not written to devices.json: %+v", list)
	}
	if list[0].CertSHA256 != cert {
		t.Errorf("stored cert_sha256 %q != fingerprint %q", list[0].CertSHA256, cert)
	}
	raw := string(mustRead(t, filepath.Join(cfgDir, "devices.json")))
	if !strings.Contains(raw, `"upstream": "b"`) {
		t.Errorf("devices.json missing upstream field:\n%s", raw)
	}
	if !strings.Contains(raw, `"cert_sha256": "`+cert+`"`) {
		t.Errorf("devices.json missing cert_sha256 field:\n%s", raw)
	}
}

// TestRunNormalizesFingerprintToLower 验证 --fingerprint 传大写时, resolveFingerprint 归一为小写后落盘
// (devices.json 的 cert_sha256 只认小写规范形; CanonicalFingerprint 拒非小写)。
func TestRunNormalizesFingerprintToLower(t *testing.T) {
	srv := sumsServer(t)
	defer srv.Close()
	t.Setenv("CC_MYSUB_RELEASE_BASE_URL", srv.URL)

	cfgDir := t.TempDir()
	must(t, os.WriteFile(filepath.Join(cfgDir, "config.json"),
		[]byte(`{"listen":"127.0.0.1:8788","client":{"public_host":"h","subscription_type":"max"}}`), 0o644))

	upper := strings.Repeat("A", 64)
	var sb strings.Builder
	err := Run([]string{"--label", "up", "--release", "v1.0.0", "--fingerprint", upper, "--out", filepath.Join(t.TempDir(), "w")}, cfgDir, &sb)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	list := readDevices(t, filepath.Join(cfgDir, "devices.json"))
	if len(list) != 1 {
		t.Fatalf("want 1 device, got %d", len(list))
	}
	want := strings.Repeat("a", 64)
	if list[0].CertSHA256 != want {
		t.Errorf("fingerprint not normalized to lowercase: stored %q, want %q", list[0].CertSHA256, want)
	}
}

// TestRunRejectsMalformedRelease 验证含 shell 元字符的 --release tag 在落盘前被拒(错误可见)：
// 这类值会被逐字插入生成的 wrapper、产出损坏/可注入的 bash。校验须先于 fetchManifest/落盘，
// 故无需 httptest，且 devices.json 绝不应被创建(零 orphan 副作用)。
func TestRunRejectsMalformedRelease(t *testing.T) {
	cfgDir := t.TempDir()
	must(t, os.WriteFile(filepath.Join(cfgDir, "config.json"),
		[]byte(`{"listen":"127.0.0.1:8788","client":{"public_host":"h","subscription_type":"max"}}`), 0o644))

	var sb strings.Builder
	err := Run([]string{"--label", "x", "--release", `v1"; rm -rf ~; "`, "--fingerprint", fp("a"), "--out", filepath.Join(t.TempDir(), "w")}, cfgDir, &sb)
	if err == nil {
		t.Fatal("expected error for --release with shell metachars, got nil")
	}
	if _, statErr := os.Stat(filepath.Join(cfgDir, "devices.json")); statErr == nil {
		t.Error("devices.json written despite malformed --release (orphan side effect)")
	}
}

// TestRunRotateRevokesOldFingerprint 验证 --rotate 原地换发: 旧指纹不再 Lookup 命中, 新指纹命中, 单行。
func TestRunRotateRevokesOldFingerprint(t *testing.T) {
	srv := sumsServer(t)
	defer srv.Close()
	t.Setenv("CC_MYSUB_RELEASE_BASE_URL", srv.URL)

	cfgDir := t.TempDir()
	must(t, os.WriteFile(filepath.Join(cfgDir, "config.json"),
		[]byte(`{"listen":"127.0.0.1:8788","client":{"public_host":"h","subscription_type":"max"}}`), 0o644))

	oldFP := fp("a")
	newFP := fp("b")

	var sb1 strings.Builder
	must(t, Run([]string{"--label", "laptop", "--release", "v1.0.0", "--fingerprint", oldFP, "--out", filepath.Join(t.TempDir(), "w1")}, cfgDir, &sb1))

	var sb2 strings.Builder
	must(t, Run([]string{"--label", "laptop", "--rotate", "--release", "v1.0.0", "--fingerprint", newFP, "--out", filepath.Join(t.TempDir(), "w2")}, cfgDir, &sb2))

	store, err := auth.NewDeviceStore(filepath.Join(cfgDir, "devices.json"))
	must(t, err)
	defer store.StopWatch()
	if _, ok := store.Lookup(oldFP); ok {
		t.Error("old fingerprint still valid after rotate (NOT revoked)")
	}
	if _, ok := store.Lookup(newFP); !ok {
		t.Error("new fingerprint not valid after rotate")
	}
	list := readDevices(t, filepath.Join(cfgDir, "devices.json"))
	if len(list) != 1 {
		t.Errorf("want exactly 1 row for the label after rotate, got %d", len(list))
	}
}

// TestRunNoRotateRejectsDuplicate 验证不带 --rotate 时同 label 仍被 AppendDevice 硬拒。
func TestRunNoRotateRejectsDuplicate(t *testing.T) {
	srv := sumsServer(t)
	defer srv.Close()
	t.Setenv("CC_MYSUB_RELEASE_BASE_URL", srv.URL)

	cfgDir := t.TempDir()
	must(t, os.WriteFile(filepath.Join(cfgDir, "config.json"),
		[]byte(`{"listen":"127.0.0.1:8788","client":{"public_host":"h","subscription_type":"max"}}`), 0o644))

	var sb1 strings.Builder
	must(t, Run([]string{"--label", "dup", "--release", "v1.0.0", "--fingerprint", fp("a"), "--out", filepath.Join(t.TempDir(), "w1")}, cfgDir, &sb1))
	var sb2 strings.Builder
	err := Run([]string{"--label", "dup", "--release", "v1.0.0", "--fingerprint", fp("b"), "--out", filepath.Join(t.TempDir(), "w2")}, cfgDir, &sb2)
	if err == nil {
		t.Fatal("expected duplicate-label error without --rotate, got nil")
	}
	if !strings.Contains(err.Error(), "dup") {
		t.Errorf("error should be the duplicate-label rejection (AppendDevice), got: %v", err)
	}
}

// ---- helpers ----

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func mustRead(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
