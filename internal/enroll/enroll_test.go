package enroll

import (
	"encoding/json"
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
	out, err := RenderWrapper(p, "cco_dev_deadbeef", caPath)
	if err != nil {
		t.Fatalf("RenderWrapper: %v", err)
	}
	for _, want := range []string{
		`PUBLIC_HOST="ccapi.example.com"`,
		`PROXY_ENTRY="203.0.113.10:8788"`,
		`DEVICE_TOKEN="cco_dev_deadbeef"`,
		`SUB_TYPE="max"`,
		`CA_CERT="` + caPath + `"`,
		`CLAUDE_CODE_OAUTH_TOKEN="$DEVICE_TOKEN"`,
		`CLAUDE_CODE_SUBSCRIPTION_TYPE="$SUB_TYPE"`,
		`NODE_EXTRA_CA_CERTS="$CA_CERT"`,
		`exec cc-mysub helper --upstream "$PROXY_ENTRY" --server-name "$PUBLIC_HOST" --ca "$CA_CERT" -- claude "$@"`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("rendered wrapper missing %q\n---\n%s", want, out)
		}
	}
	// v4 收口: OLD v3 形态(base_url 直连 / unshare / hosts)必须彻底删除。
	for _, banned := range []string{
		"ANTHROPIC_BASE_URL=https://",
		"unshare",
		"/etc/hosts",
	} {
		if strings.Contains(out, banned) {
			t.Errorf("rendered wrapper still contains obsolete v3 token %q\n---\n%s", banned, out)
		}
	}
}

// 核心契约: 工具绝不替用户预设小模型。
func TestRenderWrapperDoesNotDecideSmallModel(t *testing.T) {
	out, err := RenderWrapper(Params{PublicHost: "h", FrpsIP: "1.2.3.4", ProxyPort: 8788, SubType: "max"}, "cco_dev_x", "/dev/null")
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
	out, err := RenderWrapper(Params{PublicHost: "h", FrpsIP: "1.2.3.4", ProxyPort: 8788, SubType: "max"}, "cco_dev_x", "/dev/null")
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
	cfgDir := t.TempDir()
	must(t, os.WriteFile(filepath.Join(cfgDir, "config.json"),
		[]byte(`{"listen":"127.0.0.1:8788","client":{"public_host":"ccapi.example.com","frps_ip":"203.0.113.10","subscription_type":"max"}}`), 0o644))

	outDir := t.TempDir()
	wrapperPath := filepath.Join(outDir, "myclaude-laptop")
	var sb strings.Builder
	err := Run([]string{"--label", "laptop", "--out", wrapperPath}, cfgDir, &sb)
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
	if !strings.Contains(w, `exec cc-mysub helper --upstream "$PROXY_ENTRY" --server-name "$PUBLIC_HOST" --ca "$CA_CERT" -- claude "$@"`) {
		t.Errorf("wrapper missing v4 helper exec line:\n%s", w)
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
	cfgDir := t.TempDir()
	must(t, os.WriteFile(filepath.Join(cfgDir, "config.json"),
		[]byte(`{"listen":"127.0.0.1:8788","client":{"public_host":"ccapi.example.com","frps_ip":"203.0.113.10","proxy_port":8788,"subscription_type":"max"}}`), 0o644))

	wrapperPath := filepath.Join(t.TempDir(), "myclaude-work")
	var sb strings.Builder
	err := Run([]string{"--label", "work", "--upstream", "b", "--out", wrapperPath}, cfgDir, &sb)
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
