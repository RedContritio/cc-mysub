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

// ---- GenerateToken ----

func TestGenerateTokenFormat(t *testing.T) {
	tok, err := GenerateToken()
	if err != nil {
		t.Fatalf("GenerateToken: %v", err)
	}
	if !strings.HasPrefix(tok, "cco_dev_") {
		t.Errorf("token %q lacks cco_dev_ prefix", tok)
	}
	body := strings.TrimPrefix(tok, "cco_dev_")
	// 24 random bytes -> 48 hex chars (matches README's `openssl rand -hex 24`).
	if !regexp.MustCompile(`^[0-9a-f]{48}$`).MatchString(body) {
		t.Errorf("token body %q is not 48 lowercase hex chars", body)
	}
}

func TestGenerateTokenUnique(t *testing.T) {
	a, _ := GenerateToken()
	b, _ := GenerateToken()
	if a == b {
		t.Errorf("two GenerateToken calls returned identical token %q", a)
	}
}

// ---- RenderWrapper ----

func TestRenderWrapperFillsValues(t *testing.T) {
	p := Params{PublicHost: "ccapi.example.com", FrpsIP: "203.0.113.10", ProxyPort: 8788, SubType: "max"}
	const caPath = "${HOME}/.config/cc-mysub/ca.crt"
	const caPEM = "-----BEGIN CERTIFICATE-----\nMIIBfakeCAcontent==\n-----END CERTIFICATE-----"
	shaTable := map[string]string{
		"linux-amd64":  strings.Repeat("a", 64),
		"linux-arm64":  strings.Repeat("b", 64),
		"darwin-amd64": strings.Repeat("c", 64),
		"darwin-arm64": strings.Repeat("d", 64),
	}
	const relBase = "https://example.test/redcontritio/cc-mysub/releases/download/v1.2.3"
	out, err := RenderWrapper(p, "cco_dev_deadbeef", caPath, caPEM, shaTable, "v1.2.3", relBase)
	if err != nil {
		t.Fatalf("RenderWrapper: %v", err)
	}
	for _, want := range []string{
		`PUBLIC_HOST="ccapi.example.com"`,
		`PROXY_ENTRY="203.0.113.10:8788"`,
		`DEVICE_TOKEN="cco_dev_deadbeef"`,
		`SUB_TYPE="max"`,
		`CA_CERT="` + caPath + `"`,
		`RELEASE_BASE="` + relBase + `"`,
		`CLAUDE_CODE_OAUTH_TOKEN="$DEVICE_TOKEN"`,
		`CLAUDE_CODE_SUBSCRIPTION_TYPE="$SUB_TYPE"`,
		`NODE_EXTRA_CA_CERTS="$CA_CERT"`,
		caPEM,                   // 内联 CA 逐字出现
		"钉定版本: v1.2.3",          // version 注释
		strings.Repeat("d", 64), // darwin-arm64 sha 烤入 case 分支
		"verify_sha",            // bootstrap 助手
		"trap '",                // 清理 trap
		"sha256 校验失败（供应链）",      // fail-closed 分支
		`exec "$CC_MYSUB_BIN" helper --upstream "$PROXY_ENTRY" --server-name "$PUBLIC_HOST" --ca "$CA_CERT" -- claude "$@"`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("rendered wrapper missing %q\n---\n%s", want, out)
		}
	}
	// v4 收口 + 不再依赖 PATH 上的裸 cc-mysub: OLD 形态必须彻底删除。
	for _, banned := range []string{
		"ANTHROPIC_BASE_URL=https://",
		"unshare",
		"/etc/hosts",
		`exec cc-mysub helper`, // 旧的裸命令(无 $CC_MYSUB_BIN)形态
	} {
		if strings.Contains(out, banned) {
			t.Errorf("rendered wrapper still contains obsolete token %q\n---\n%s", banned, out)
		}
	}
}

// 核心契约: 工具绝不替用户预设小模型。
func TestRenderWrapperDoesNotDecideSmallModel(t *testing.T) {
	out, err := RenderWrapper(
		Params{PublicHost: "h", FrpsIP: "1.2.3.4", ProxyPort: 8788, SubType: "max"},
		"cco_dev_x", "/dev/null", "PEM", map[string]string{}, "v0", "https://x/releases/download/v0")
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
		Params{PublicHost: "h", FrpsIP: "1.2.3.4", ProxyPort: 8788, SubType: "max"},
		"cco_dev_x", "/dev/null", "-----BEGIN CERTIFICATE-----\nabc\n-----END CERTIFICATE-----",
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

func TestAppendDeviceCreatesFileWithCorrectHash(t *testing.T) {
	path := filepath.Join(t.TempDir(), "devices.json")
	p := Params{Label: "laptop", PublicHost: "h", FrpsIP: "1.2.3.4", SubType: "max", RateLimit: 120}
	const tok = "cco_dev_abc123"
	if err := AppendDevice(path, p, tok); err != nil {
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
	if d.TokenSHA256 != auth.HashToken(tok) {
		t.Errorf("stored sha256 %q != HashToken(token) %q", d.TokenSHA256, auth.HashToken(tok))
	}
	// 明文 token 绝不入库。
	if strings.Contains(string(mustRead(t, path)), tok) {
		t.Errorf("plaintext token leaked into devices.json")
	}
}

func TestAppendDevicePreservesExisting(t *testing.T) {
	path := filepath.Join(t.TempDir(), "devices.json")
	must(t, AppendDevice(path, Params{Label: "a", PublicHost: "h", FrpsIP: "1.2.3.4", SubType: "max"}, "cco_dev_a"))
	must(t, AppendDevice(path, Params{Label: "b", PublicHost: "h", FrpsIP: "1.2.3.4", SubType: "max"}, "cco_dev_b"))
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
	p := Params{Label: "work", PublicHost: "h", FrpsIP: "1.2.3.4", SubType: "max", Upstream: "team-b"}
	must(t, AppendDevice(path, p, "cco_dev_work"))
	list := readDevices(t, path)
	if len(list) != 1 || list[0].Upstream != "team-b" {
		t.Fatalf("device upstream not persisted: %+v", list)
	}
}

func TestAppendDeviceRejectsDuplicateLabel(t *testing.T) {
	path := filepath.Join(t.TempDir(), "devices.json")
	must(t, AppendDevice(path, Params{Label: "dup", PublicHost: "h", FrpsIP: "1.2.3.4", SubType: "max"}, "cco_dev_1"))
	err := AppendDevice(path, Params{Label: "dup", PublicHost: "h", FrpsIP: "1.2.3.4", SubType: "max"}, "cco_dev_2")
	if err == nil {
		t.Fatalf("expected error on duplicate label, got nil")
	}
	if !strings.Contains(err.Error(), "dup") {
		t.Errorf("error should mention the duplicate label: %v", err)
	}
}

func TestReplaceDeviceErrorsWhenLabelAbsent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "devices.json")
	must(t, AppendDevice(path, Params{Label: "a", PublicHost: "h", FrpsIP: "1.2.3.4", SubType: "max"}, "cco_dev_a"))
	err := ReplaceDevice(path, Params{Label: "ghost", PublicHost: "h", FrpsIP: "1.2.3.4", SubType: "max"}, "cco_dev_x")
	if err == nil {
		t.Fatal("expected error rotating an absent label, got nil")
	}
	if !strings.Contains(err.Error(), "ghost") {
		t.Errorf("error should mention the absent label, got: %v", err)
	}
	// 失败的 rotate 须零副作用：原设备 a 完好、未半截写入。
	list := readDevices(t, path)
	if len(list) != 1 || list[0].Label != "a" || list[0].TokenSHA256 != auth.HashToken("cco_dev_a") {
		t.Errorf("failed rotate must be side-effect-free; devices.json mutated: %+v", list)
	}
}

func TestReplaceDeviceSwapsToken(t *testing.T) {
	path := filepath.Join(t.TempDir(), "devices.json")
	must(t, AppendDevice(path, Params{Label: "a", PublicHost: "h", FrpsIP: "1.2.3.4", SubType: "max"}, "cco_dev_old"))
	must(t, ReplaceDevice(path, Params{Label: "a", PublicHost: "h", FrpsIP: "1.2.3.4", SubType: "max"}, "cco_dev_new"))
	list := readDevices(t, path)
	if len(list) != 1 {
		t.Fatalf("want 1 device after rotate, got %d", len(list))
	}
	if list[0].TokenSHA256 != auth.HashToken("cco_dev_new") {
		t.Errorf("token not swapped to new")
	}
}

// TestReplaceDevicePreservesSiblings 验证 rotate 只动目标 label：换发 target 后，同库其它设备行
// (keep) 的 token 必须原封不动、仍命中。守护「rotate 误伤旁邻设备 = 静默大规模 lockout / 凭据丢失」
// 这一灾难性回归——对抗 review 变异验证发现：核心契约外，sibling-preservation 此前无守护
// (把 ReplaceDevice 改成丢弃全部行 + 追加新行的回归能通过整包测试)。
func TestReplaceDevicePreservesSiblings(t *testing.T) {
	path := filepath.Join(t.TempDir(), "devices.json")
	must(t, AppendDevice(path, Params{Label: "keep", PublicHost: "h", FrpsIP: "1.2.3.4", SubType: "max"}, "cco_dev_keep"))
	must(t, AppendDevice(path, Params{Label: "target", PublicHost: "h", FrpsIP: "1.2.3.4", SubType: "max"}, "cco_dev_oldtarget"))

	must(t, ReplaceDevice(path, Params{Label: "target", PublicHost: "h", FrpsIP: "1.2.3.4", SubType: "max"}, "cco_dev_newtarget"))

	list := readDevices(t, path)
	if len(list) != 2 {
		t.Fatalf("rotate must preserve sibling; want 2 devices, got %d: %+v", len(list), list)
	}
	byLabel := map[string]auth.Device{}
	for _, d := range list {
		byLabel[d.Label] = d
	}
	if byLabel["keep"].TokenSHA256 != auth.HashToken("cco_dev_keep") {
		t.Errorf("sibling 'keep' token altered by rotate of 'target' (mass-revocation regression)")
	}
	if byLabel["target"].TokenSHA256 != auth.HashToken("cco_dev_newtarget") {
		t.Errorf("target token not swapped to new")
	}
	if byLabel["target"].TokenSHA256 == auth.HashToken("cco_dev_oldtarget") {
		t.Errorf("target still carries old token after rotate")
	}
}

// ---- Resolve ----

func TestResolveFlagOverridesConfig(t *testing.T) {
	def := &config.ClientConfig{PublicHost: "cfg.example.com", FrpsIP: "1.1.1.1", SubscriptionType: "max"}
	got, err := Resolve(def, Params{Label: "x", SubType: "pro"})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if got.PublicHost != "cfg.example.com" || got.FrpsIP != "1.1.1.1" {
		t.Errorf("config defaults not applied: %+v", got)
	}
	if got.SubType != "pro" {
		t.Errorf("flag override not applied, want pro got %q", got.SubType)
	}
}

func TestResolveUsesConfigWhenNoFlags(t *testing.T) {
	def := &config.ClientConfig{PublicHost: "cfg.example.com", FrpsIP: "1.1.1.1", SubscriptionType: "max"}
	got, err := Resolve(def, Params{Label: "x"})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if got.PublicHost != "cfg.example.com" || got.FrpsIP != "1.1.1.1" || got.SubType != "max" {
		t.Errorf("config not used as default: %+v", got)
	}
}

// TestResolveProxyPortDefault 验证 ProxyPort 缺省回退 8788，配置/flag 给值则优先。
func TestResolveProxyPortDefault(t *testing.T) {
	// config/flag 都没给 → 默认 8788
	got, err := Resolve(&config.ClientConfig{PublicHost: "h", FrpsIP: "1.1.1.1", SubscriptionType: "max"}, Params{Label: "x"})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if got.ProxyPort != 8788 {
		t.Errorf("default ProxyPort = %d, want 8788", got.ProxyPort)
	}
	// config 显式给值 → 用配置值
	got2, err := Resolve(&config.ClientConfig{PublicHost: "h", FrpsIP: "1.1.1.1", SubscriptionType: "max", ProxyPort: 9999}, Params{Label: "x"})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if got2.ProxyPort != 9999 {
		t.Errorf("config ProxyPort = %d, want 9999", got2.ProxyPort)
	}
}

func TestResolveRequiresLabel(t *testing.T) {
	def := &config.ClientConfig{PublicHost: "h", FrpsIP: "1.1.1.1", SubscriptionType: "max"}
	if _, err := Resolve(def, Params{}); err == nil {
		t.Errorf("expected error when label missing")
	}
}

func TestResolveRequiresHostFrpsSub(t *testing.T) {
	cases := map[string]*config.ClientConfig{
		"no host": {FrpsIP: "1.1.1.1", SubscriptionType: "max"},
		"no frps": {PublicHost: "h", SubscriptionType: "max"},
		"no sub":  {PublicHost: "h", FrpsIP: "1.1.1.1"},
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
	def := &config.ClientConfig{PublicHost: "h", FrpsIP: "1.1.1.1", SubscriptionType: "max"}
	got, err := Resolve(def, Params{Label: "x"})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if got.ReleaseRepo != "redcontritio/cc-mysub" {
		t.Errorf("default ReleaseRepo = %q, want redcontritio/cc-mysub", got.ReleaseRepo)
	}
	def2 := &config.ClientConfig{PublicHost: "h", FrpsIP: "1.1.1.1", SubscriptionType: "max", ReleaseRepo: "acme/cc-mysub"}
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

func TestRunEndToEnd(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/SHA256SUMS") {
			io.WriteString(w, validSums())
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()
	t.Setenv("CC_MYSUB_RELEASE_BASE_URL", srv.URL)

	cfgDir := t.TempDir()
	must(t, os.WriteFile(filepath.Join(cfgDir, "config.json"),
		[]byte(`{"listen":"127.0.0.1:8788","client":{"public_host":"ccapi.example.com","frps_ip":"203.0.113.10","subscription_type":"max"}}`), 0o644))

	outDir := t.TempDir()
	wrapperPath := filepath.Join(outDir, "myclaude-laptop")
	var sb strings.Builder
	err := Run([]string{"--label", "laptop", "--release", "v1.0.0", "--out", wrapperPath}, cfgDir, &sb)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	// devices.json 落了一条
	list := readDevices(t, filepath.Join(cfgDir, "devices.json"))
	if len(list) != 1 || list[0].Label != "laptop" {
		t.Fatalf("devices.json not written correctly: %+v", list)
	}

	// wrapper 文件写出（mode 由 adddevice_test.go TestAddDeviceSubcommand 覆盖）
	if _, err := os.Stat(wrapperPath); err != nil {
		t.Fatalf("wrapper not written: %v", err)
	}
	w := string(mustRead(t, wrapperPath))
	if !strings.Contains(w, `PUBLIC_HOST="ccapi.example.com"`) || !strings.Contains(w, `SUB_TYPE="max"`) {
		t.Errorf("wrapper not filled from config: \n%s", w)
	}
	// v4 helper 形态: 必须有 helper exec 行, 不得残留 v3 直连/隔离形态。
	if !strings.Contains(w, `exec "$CC_MYSUB_BIN" helper --upstream "$PROXY_ENTRY" --server-name "$PUBLIC_HOST" --ca "$CA_CERT" -- claude "$@"`) {
		t.Errorf("wrapper missing v4 self-bootstrap helper exec line:\n%s", w)
	}
	if strings.Contains(w, "ANTHROPIC_BASE_URL=https://") || strings.Contains(w, "unshare") {
		t.Errorf("wrapper still contains obsolete v3 form:\n%s", w)
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

	// 打印的明文 token 与库内 sha256 对得上，且 wrapper 里也带着它
	printed := sb.String()
	tok := extractToken(t, printed)
	if list[0].TokenSHA256 != auth.HashToken(tok) {
		t.Errorf("printed token does not match stored hash")
	}
	if !strings.Contains(w, tok) {
		t.Errorf("wrapper does not embed the generated token")
	}
}

// TestRunAssignsUpstream 验证 --upstream 写入 devices.json 的 upstream 字段。
func TestRunAssignsUpstream(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/SHA256SUMS") {
			io.WriteString(w, validSums())
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()
	t.Setenv("CC_MYSUB_RELEASE_BASE_URL", srv.URL)

	cfgDir := t.TempDir()
	must(t, os.WriteFile(filepath.Join(cfgDir, "config.json"),
		[]byte(`{"listen":"127.0.0.1:8788","client":{"public_host":"ccapi.example.com","frps_ip":"203.0.113.10","proxy_port":8788,"subscription_type":"max"}}`), 0o644))

	wrapperPath := filepath.Join(t.TempDir(), "myclaude-work")
	var sb strings.Builder
	err := Run([]string{"--label", "work", "--upstream", "b", "--release", "v1.0.0", "--out", wrapperPath}, cfgDir, &sb)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	list := readDevices(t, filepath.Join(cfgDir, "devices.json"))
	if len(list) != 1 || list[0].Upstream != "b" {
		t.Fatalf("--upstream b not written to devices.json: %+v", list)
	}
	raw := string(mustRead(t, filepath.Join(cfgDir, "devices.json")))
	if !strings.Contains(raw, `"upstream": "b"`) {
		t.Errorf("devices.json missing upstream field:\n%s", raw)
	}
}

// TestRunRejectsMalformedRelease 验证含 shell 元字符的 --release tag 在落盘前被拒(错误可见)：
// 这类值会被逐字插入生成的 wrapper、产出损坏/可注入的 bash。校验须先于 fetchManifest/落盘，
// 故无需 httptest，且 devices.json 绝不应被创建(零 orphan 副作用)。
func TestRunRejectsMalformedRelease(t *testing.T) {
	cfgDir := t.TempDir()
	must(t, os.WriteFile(filepath.Join(cfgDir, "config.json"),
		[]byte(`{"listen":"127.0.0.1:8788","client":{"public_host":"h","frps_ip":"1.2.3.4","proxy_port":8788,"subscription_type":"max"}}`), 0o644))

	var sb strings.Builder
	err := Run([]string{"--label", "x", "--release", `v1"; rm -rf ~; "`, "--out", filepath.Join(t.TempDir(), "w")}, cfgDir, &sb)
	if err == nil {
		t.Fatal("expected error for --release with shell metachars, got nil")
	}
	if _, statErr := os.Stat(filepath.Join(cfgDir, "devices.json")); statErr == nil {
		t.Error("devices.json written despite malformed --release (orphan side effect)")
	}
}

// TestRunRotateRevokesOldToken 验证 --rotate 原地换发: 旧 token 不再 Lookup 命中, 新 token 命中, 单行。
func TestRunRotateRevokesOldToken(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/SHA256SUMS") {
			io.WriteString(w, validSums())
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()
	t.Setenv("CC_MYSUB_RELEASE_BASE_URL", srv.URL)

	cfgDir := t.TempDir()
	must(t, os.WriteFile(filepath.Join(cfgDir, "config.json"),
		[]byte(`{"listen":"127.0.0.1:8788","client":{"public_host":"h","frps_ip":"1.2.3.4","proxy_port":8788,"subscription_type":"max"}}`), 0o644))

	var sb1 strings.Builder
	must(t, Run([]string{"--label", "laptop", "--release", "v1.0.0", "--out", filepath.Join(t.TempDir(), "w1")}, cfgDir, &sb1))
	oldTok := extractToken(t, sb1.String())

	var sb2 strings.Builder
	must(t, Run([]string{"--label", "laptop", "--rotate", "--release", "v1.0.0", "--out", filepath.Join(t.TempDir(), "w2")}, cfgDir, &sb2))
	newTok := extractToken(t, sb2.String())

	if oldTok == newTok {
		t.Fatal("rotate did not issue a new token")
	}
	store, err := auth.NewDeviceStore(filepath.Join(cfgDir, "devices.json"))
	must(t, err)
	defer store.StopWatch()
	if _, ok := store.Lookup(oldTok); ok {
		t.Error("old token still valid after rotate (NOT revoked)")
	}
	if _, ok := store.Lookup(newTok); !ok {
		t.Error("new token not valid after rotate")
	}
	list := readDevices(t, filepath.Join(cfgDir, "devices.json"))
	if len(list) != 1 {
		t.Errorf("want exactly 1 row for the label after rotate, got %d", len(list))
	}
}

// TestRunNoRotateRejectsDuplicate 验证不带 --rotate 时同 label 仍被 AppendDevice 硬拒。
func TestRunNoRotateRejectsDuplicate(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/SHA256SUMS") {
			io.WriteString(w, validSums())
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()
	t.Setenv("CC_MYSUB_RELEASE_BASE_URL", srv.URL)

	cfgDir := t.TempDir()
	must(t, os.WriteFile(filepath.Join(cfgDir, "config.json"),
		[]byte(`{"listen":"127.0.0.1:8788","client":{"public_host":"h","frps_ip":"1.2.3.4","proxy_port":8788,"subscription_type":"max"}}`), 0o644))

	var sb1 strings.Builder
	must(t, Run([]string{"--label", "dup", "--release", "v1.0.0", "--out", filepath.Join(t.TempDir(), "w1")}, cfgDir, &sb1))
	var sb2 strings.Builder
	err := Run([]string{"--label", "dup", "--release", "v1.0.0", "--out", filepath.Join(t.TempDir(), "w2")}, cfgDir, &sb2)
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

var tokenRE = regexp.MustCompile(`cco_dev_[0-9a-f]{48}`)

func extractToken(t *testing.T, s string) string {
	t.Helper()
	m := tokenRE.FindString(s)
	if m == "" {
		t.Fatalf("no cco_dev_ token found in output:\n%s", s)
	}
	return m
}
