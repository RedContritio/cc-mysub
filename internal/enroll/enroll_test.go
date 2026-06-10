package enroll

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/redcontritio/cc-mysub/internal/auth"
	"github.com/redcontritio/cc-mysub/internal/config"
)

// fp 把单个 hex 字符重复 64 次，得一个合法的小写 hex 证书指纹（cert_sha256 规范形）。
// 迁移后 AppendDevice/ReplaceDevice 的第三参数语义 = 证书指纹，直接写入 CertSHA256、不再哈希；
// 不同字符 = 不同设备身份，使「换发/旁邻保留」类断言能区分。
func fp(c string) string { return strings.Repeat(c, 64) }

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

// ---- RemoveDevice / RunRemove (吊销走 cli) ----

// TestRemoveDevice 验证吊销: 按指纹/label 删除、写回合法 JSON、删后 store.Lookup 不命中(即时失效)、
// 旁邻保留、无匹配报错(错误可见)。
func TestRemoveDevice(t *testing.T) {
	path := filepath.Join(t.TempDir(), "devices.json")
	must(t, AppendDevice(path, Params{Label: "a", PublicHost: "h", SubType: "max"}, fp("a")))
	must(t, AppendDevice(path, Params{Label: "b", PublicHost: "h", SubType: "max"}, fp("b")))

	// 按指纹删 a；写回仍是合法 JSON(否则 readDevices Fatal),旁邻 b 保留。
	must(t, RemoveDevice(path, fp("a"), ""))
	if list := readDevices(t, path); len(list) != 1 || list[0].Label != "b" {
		t.Fatalf("after remove a by fp: %+v", list)
	}
	// 删后 store Lookup a 不命中、b 仍命中(吊销即时,经热重载读到新表)。
	store, err := auth.NewDeviceStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := store.Lookup(fp("a")); ok {
		t.Error("removed device a still resolves (NOT revoked)")
	}
	if _, ok := store.Lookup(fp("b")); !ok {
		t.Error("sibling b lost")
	}

	// 按 label 删 b → 空。
	must(t, RemoveDevice(path, "", "b"))
	if list := readDevices(t, path); len(list) != 0 {
		t.Fatalf("after remove b by label, want empty, got %+v", list)
	}

	// 无匹配 → 报错(不静默成功)。
	if err := RemoveDevice(path, fp("z"), ""); err == nil {
		t.Error("removing nonexistent fingerprint should error")
	}
}

// TestRunRemove 验证 remove-device cli 入口: --label 删除生效;缺 --fingerprint/--label 报错。
func TestRunRemove(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "devices.json")
	must(t, AppendDevice(path, Params{Label: "x", PublicHost: "h", SubType: "max"}, fp("a")))
	var out bytes.Buffer
	if err := RunRemove([]string{"--config-dir", dir, "--label", "x"}, dir, &out); err != nil {
		t.Fatalf("RunRemove: %v", err)
	}
	if list := readDevices(t, path); len(list) != 0 {
		t.Fatalf("device not removed: %+v", list)
	}
	if err := RunRemove([]string{"--config-dir", dir}, dir, &out); err == nil {
		t.Error("RunRemove without --fingerprint/--label should error")
	}
}

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

// TestResolveRequiresHost 验证 public host 仍是 Resolve 的硬必填（缺 host 无从定位部署身份/证书）。
// 收口后 SubType 不再必填（见 TestResolveAllowsMissingSub），故此处只覆盖 host 缺失。
func TestResolveRequiresHost(t *testing.T) {
	cases := map[string]*config.ClientConfig{
		"no host": {SubscriptionType: "max"},
		"nil cfg": nil,
	}
	for name, def := range cases {
		if _, err := Resolve(def, Params{Label: "x"}); err == nil {
			t.Errorf("%s: expected error for missing public host", name)
		}
	}
}

// TestResolveAllowsMissingSub 钉死收口契约变更：add-device 不再渲染 wrapper，sub 仅作部署元数据
// （由 gen-config 经部署配置下发），故缺 subscription_type 不再让 Resolve fail。
func TestResolveAllowsMissingSub(t *testing.T) {
	def := &config.ClientConfig{PublicHost: "h"} // 无 subscription_type
	got, err := Resolve(def, Params{Label: "x"})
	if err != nil {
		t.Fatalf("Resolve should not require sub after 收口: %v", err)
	}
	if got.SubType != "" {
		t.Errorf("SubType should stay empty when unset, got %q", got.SubType)
	}
}

// ---- Run (integration) ----

// TestRun_RegistersOnly_NoWrapper 钉死收口后的 add-device 形态：只 register 指纹 + 首建 CA，
// 绝不产出任何 myclaude wrapper 文件（wrapper/分发改由 install.sh 管）。
func TestRun_RegistersOnly_NoWrapper(t *testing.T) {
	d := t.TempDir()
	os.WriteFile(filepath.Join(d, "config.json"),
		[]byte(`{"listen":"127.0.0.1:8788","client":{"public_host":"ccapi.example.com","subscription_type":"max"}}`), 0o644)
	out := &bytes.Buffer{}
	fp := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	err := Run([]string{"-config-dir", d, "-label", "box", "-fingerprint", fp}, d, out)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	// devices.json 写入了该指纹
	b, _ := os.ReadFile(filepath.Join(d, "devices.json"))
	if !bytes.Contains(b, []byte(fp)) {
		t.Errorf("devices.json missing fingerprint: %s", b)
	}
	// CA 首次生成
	if _, err := os.Stat(filepath.Join(d, "ca.crt")); err != nil {
		t.Errorf("ca.crt not generated: %v", err)
	}
	// 不产生任何 myclaude-* wrapper 文件
	matches, _ := filepath.Glob(filepath.Join(d, "myclaude*"))
	matches2, _ := filepath.Glob("myclaude*")
	if len(matches)+len(matches2) > 0 {
		t.Errorf("add-device should not emit a wrapper file, found %v %v", matches, matches2)
	}
}

// TestRunAssignsUpstream 验证 --upstream 写入 devices.json 的 upstream 字段。
func TestRunAssignsUpstream(t *testing.T) {
	cfgDir := t.TempDir()
	must(t, os.WriteFile(filepath.Join(cfgDir, "config.json"),
		[]byte(`{"listen":"127.0.0.1:8788","client":{"public_host":"ccapi.example.com","subscription_type":"max"}}`), 0o644))

	cert := fp("b")
	var sb strings.Builder
	err := Run([]string{"--label", "work", "--upstream", "b", "--fingerprint", cert}, cfgDir, &sb)
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
	raw, err := os.ReadFile(filepath.Join(cfgDir, "devices.json"))
	if err != nil {
		t.Fatalf("read devices.json: %v", err)
	}
	if !strings.Contains(string(raw), `"upstream": "b"`) {
		t.Errorf("devices.json missing upstream field:\n%s", raw)
	}
	if !strings.Contains(string(raw), `"cert_sha256": "`+cert+`"`) {
		t.Errorf("devices.json missing cert_sha256 field:\n%s", raw)
	}
}

// TestRunNormalizesFingerprintToLower 验证 --fingerprint 传大写时, resolveFingerprint 归一为小写后落盘
// (devices.json 的 cert_sha256 只认小写规范形; CanonicalFingerprint 拒非小写)。
func TestRunNormalizesFingerprintToLower(t *testing.T) {
	cfgDir := t.TempDir()
	must(t, os.WriteFile(filepath.Join(cfgDir, "config.json"),
		[]byte(`{"listen":"127.0.0.1:8788","client":{"public_host":"h","subscription_type":"max"}}`), 0o644))

	upper := strings.Repeat("A", 64)
	var sb strings.Builder
	err := Run([]string{"--label", "up", "--fingerprint", upper}, cfgDir, &sb)
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

// TestRunRotateRevokesOldFingerprint 验证 --rotate 原地换发: 旧指纹不再 Lookup 命中, 新指纹命中, 单行。
func TestRunRotateRevokesOldFingerprint(t *testing.T) {
	cfgDir := t.TempDir()
	must(t, os.WriteFile(filepath.Join(cfgDir, "config.json"),
		[]byte(`{"listen":"127.0.0.1:8788","client":{"public_host":"h","subscription_type":"max"}}`), 0o644))

	oldFP := fp("a")
	newFP := fp("b")

	var sb1 strings.Builder
	must(t, Run([]string{"--label", "laptop", "--fingerprint", oldFP}, cfgDir, &sb1))

	var sb2 strings.Builder
	must(t, Run([]string{"--label", "laptop", "--rotate", "--fingerprint", newFP}, cfgDir, &sb2))

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
	cfgDir := t.TempDir()
	must(t, os.WriteFile(filepath.Join(cfgDir, "config.json"),
		[]byte(`{"listen":"127.0.0.1:8788","client":{"public_host":"h","subscription_type":"max"}}`), 0o644))

	var sb1 strings.Builder
	must(t, Run([]string{"--label", "dup", "--fingerprint", fp("a")}, cfgDir, &sb1))
	var sb2 strings.Builder
	err := Run([]string{"--label", "dup", "--fingerprint", fp("b")}, cfgDir, &sb2)
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
