package enroll

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
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

// TestResolveRejectsNegativeRateLimit 钉死 RateLimit>=0 登记契约（P3-23）：负值是登记期意外输入，
// Resolve fail-closed 报错而非静默回退默认——middleware.RateLimitByDevice 的「dev.RateLimit 恒 >=0」
// 注释据此成立。0 是合法值（= 用代理默认配额），不应被拒。
func TestResolveRejectsNegativeRateLimit(t *testing.T) {
	def := &config.ClientConfig{PublicHost: "h"}
	if _, err := Resolve(def, Params{Label: "x", RateLimit: -1}); err == nil {
		t.Errorf("expected error for negative rate-limit")
	}
	if _, err := Resolve(def, Params{Label: "x", RateLimit: 0}); err != nil {
		t.Errorf("rate-limit 0 should be allowed (proxy default), got %v", err)
	}
	if _, err := Resolve(def, Params{Label: "x", RateLimit: 120}); err != nil {
		t.Errorf("positive rate-limit should be allowed, got %v", err)
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

// TestAppendDeviceRejectsDuplicateFingerprint 契约(P1 吊销链):同一指纹不可多 label 登记。
// 否则 store last-wins + remove --label 假吊销,设备仍被授权。拒绝且零副作用(表不被污染)。
func TestAppendDeviceRejectsDuplicateFingerprint(t *testing.T) {
	path := filepath.Join(t.TempDir(), "devices.json")
	must(t, AppendDevice(path, Params{Label: "a", PublicHost: "h"}, fp("a")))
	err := AppendDevice(path, Params{Label: "b", PublicHost: "h"}, fp("a")) // 同指纹,不同 label
	if err == nil {
		t.Fatal("expected error on duplicate cert_sha256, got nil")
	}
	if !strings.Contains(err.Error(), "cert_sha256") {
		t.Errorf("error should mention the duplicate fingerprint: %v", err)
	}
	list := readDevices(t, path)
	if len(list) != 1 || list[0].Label != "a" {
		t.Fatalf("rejected dup-fingerprint append must not mutate devices.json: %+v", list)
	}
}

// TestReplaceDeviceRejectsForeignFingerprint 契约:rotate 不能把 label 换到另一台设备已用的指纹
// （会制造同指纹双别名）。拒绝且零副作用。
func TestReplaceDeviceRejectsForeignFingerprint(t *testing.T) {
	path := filepath.Join(t.TempDir(), "devices.json")
	must(t, AppendDevice(path, Params{Label: "a", PublicHost: "h"}, fp("a")))
	must(t, AppendDevice(path, Params{Label: "b", PublicHost: "h"}, fp("b")))
	err := ReplaceDevice(path, Params{Label: "b", PublicHost: "h"}, fp("a")) // 撞 a 的指纹
	if err == nil {
		t.Fatal("expected error rotating to another device's fingerprint, got nil")
	}
	if !strings.Contains(err.Error(), "cert_sha256") {
		t.Errorf("error should mention the conflicting fingerprint: %v", err)
	}
	list := readDevices(t, path)
	byLabel := map[string]auth.Device{}
	for _, d := range list {
		byLabel[d.Label] = d
	}
	if len(list) != 2 || byLabel["a"].CertSHA256 != fp("a") || byLabel["b"].CertSHA256 != fp("b") {
		t.Fatalf("rejected foreign-fingerprint rotate must not mutate devices.json: %+v", list)
	}
}

// TestReplaceDeviceToSameFingerprintAllowed 边界:rotate 到自身原指纹（label 行被先丢弃）不应被
// 误判为冲突——只有撞「别的 label」的指纹才拒。
func TestReplaceDeviceToSameFingerprintAllowed(t *testing.T) {
	path := filepath.Join(t.TempDir(), "devices.json")
	must(t, AppendDevice(path, Params{Label: "a", PublicHost: "h"}, fp("a")))
	if err := ReplaceDevice(path, Params{Label: "a", PublicHost: "h", RateLimit: 99}, fp("a")); err != nil {
		t.Fatalf("rotating a label to its own fingerprint must be allowed: %v", err)
	}
	list := readDevices(t, path)
	if len(list) != 1 || list[0].CertSHA256 != fp("a") || list[0].RateLimit != 99 {
		t.Fatalf("self-fingerprint rotate should update the row: %+v", list)
	}
}

// TestRemoveByLabelRevokesAllAliasesOfFingerprint 契约(P1 吊销链):同指纹双 label 的历史脏状态下,
// remove --label 必须连带删除同指纹的别名行,删后 store.Lookup 该指纹必 miss(吊销真正生效)。
func TestRemoveByLabelRevokesAllAliasesOfFingerprint(t *testing.T) {
	path := filepath.Join(t.TempDir(), "devices.json")
	dup := fp("a")
	// 直接写出「同指纹双 label」状态(AppendDevice 现已拒,绕过它构造该历史脏状态)。
	raw := `[{"label":"x","cert_sha256":"` + dup + `","rate_limit":0,"upstream":""},` +
		`{"label":"y","cert_sha256":"` + dup + `","rate_limit":0,"upstream":""}]`
	must(t, os.WriteFile(path, []byte(raw), 0o600))

	// 按 label x 吊销 → 必须连带删除同指纹的别名行 y。
	must(t, RemoveDevice(path, "", "x"))
	for _, d := range readDevices(t, path) {
		if d.CertSHA256 == dup {
			t.Fatalf("fingerprint still present after revoke-by-label (吊销 fail-open): %+v", d)
		}
	}
	// 经 store Lookup 也 miss(吊销即时生效)。
	store, err := auth.NewDeviceStore(path)
	must(t, err)
	defer store.StopWatch()
	if _, ok := store.Lookup(dup); ok {
		t.Error("revoked device's fingerprint must not resolve after remove --label")
	}
}

// TestConcurrentAppendNoLostUpdate 契约(P3,finding 13):flock 串行化读-改-写,N 个并发 add-device
// 全部落盘、无丢失更新。无锁时此断言会因 last-rename-wins 失败。
func TestConcurrentAppendNoLostUpdate(t *testing.T) {
	path := filepath.Join(t.TempDir(), "devices.json")
	const n = 24
	var wg sync.WaitGroup
	errs := make(chan error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			label := fmt.Sprintf("dev-%02d", i)
			cert := auth.CertFingerprint([]byte(label)) // 每个 label 唯一指纹,避免 dedup 拒绝
			errs <- AppendDevice(path, Params{Label: label, PublicHost: "h"}, cert)
		}(i)
	}
	wg.Wait()
	close(errs)
	for e := range errs {
		if e != nil {
			t.Fatalf("AppendDevice under contention: %v", e)
		}
	}
	if list := readDevices(t, path); len(list) != n {
		t.Fatalf("lost update under concurrency: want %d devices, got %d", n, len(list))
	}
}

// TestRunRemoveRejectsBothFingerprintAndLabel 契约(P3,finding 14):同时给 --fingerprint 与 --label
// 必须报错——否则 label 被静默忽略,成功消息却把两者都打印为已吊销,易误判。
func TestRunRemoveRejectsBothFingerprintAndLabel(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "devices.json")
	must(t, AppendDevice(path, Params{Label: "real", PublicHost: "h"}, fp("a")))
	var out bytes.Buffer
	err := RunRemove([]string{"--config-dir", dir, "--fingerprint", fp("a"), "--label", "real"}, dir, &out)
	if err == nil {
		t.Fatal("expected error when both --fingerprint and --label are given")
	}
	// 拒绝即报错,不得已删除任何设备。
	if list := readDevices(t, path); len(list) != 1 {
		t.Fatalf("ambiguous remove must not delete anything: %+v", list)
	}
}

// TestRunRemoveMessageOnlyEchoesUsedCriterion 契约(finding 14):成功消息只回显实际使用的判据,
// 不再把未用的另一参数打印为已吊销。
func TestRunRemoveMessageOnlyEchoesUsedCriterion(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "devices.json")
	must(t, AppendDevice(path, Params{Label: "lbl", PublicHost: "h"}, fp("a")))
	var out bytes.Buffer
	must(t, RunRemove([]string{"--config-dir", dir, "--label", "lbl"}, dir, &out))
	if !strings.Contains(out.String(), "label=") {
		t.Errorf("by-label removal should echo the label: %q", out.String())
	}
	if strings.Contains(out.String(), "fingerprint=") {
		t.Errorf("by-label removal must not echo an empty fingerprint criterion: %q", out.String())
	}
}

// TestRunRejectsUnknownUpstream 契约(P3,finding 15):--upstream id 不在 upstream.json 池中时,
// 登记期即报错,而非推迟到设备运行期 502;且不写 devices.json(fail before side effect)。
func TestRunRejectsUnknownUpstream(t *testing.T) {
	cfgDir := t.TempDir()
	must(t, os.WriteFile(filepath.Join(cfgDir, "config.json"),
		[]byte(`{"listen":"127.0.0.1:8788","client":{"public_host":"h","subscription_type":"max"}}`), 0o644))
	must(t, os.WriteFile(filepath.Join(cfgDir, "upstream.json"),
		[]byte(`{"oauthTokens":[{"id":"team-a","token":"t1"},{"id":"team-b","token":"t2"}]}`), 0o600))

	var out bytes.Buffer
	err := Run([]string{"--config-dir", cfgDir, "--label", "x", "--upstream", "team-z", "--fingerprint", fp("a")}, cfgDir, &out)
	if err == nil {
		t.Fatal("expected error for --upstream id not in pool, got nil")
	}
	if !strings.Contains(err.Error(), "team-z") {
		t.Errorf("error should name the bad upstream id: %v", err)
	}
	if _, statErr := os.Stat(filepath.Join(cfgDir, "devices.json")); statErr == nil {
		t.Error("unknown-upstream registration must fail before writing devices.json")
	}
}

// TestRunAcceptsKnownUpstream 契约(finding 15):池内已存在的 --upstream id 正常登记。
func TestRunAcceptsKnownUpstream(t *testing.T) {
	cfgDir := t.TempDir()
	must(t, os.WriteFile(filepath.Join(cfgDir, "config.json"),
		[]byte(`{"listen":"127.0.0.1:8788","client":{"public_host":"h","subscription_type":"max"}}`), 0o644))
	must(t, os.WriteFile(filepath.Join(cfgDir, "upstream.json"),
		[]byte(`{"oauthTokens":[{"id":"team-a","token":"t1"}]}`), 0o600))

	var out bytes.Buffer
	must(t, Run([]string{"--config-dir", cfgDir, "--label", "x", "--upstream", "team-a", "--fingerprint", fp("a")}, cfgDir, &out))
	list := readDevices(t, filepath.Join(cfgDir, "devices.json"))
	if len(list) != 1 || list[0].Upstream != "team-a" {
		t.Fatalf("known --upstream should register: %+v", list)
	}
}

// TestResolveFingerprintRejectsNonCertPEM 契约(P3,finding 37):--client-cert 误传私钥/CSR(首块
// 非 CERTIFICATE)时报错,不把私钥 DER 当证书算出一个语义错误的指纹静默登记。
func TestResolveFingerprintRejectsNonCertPEM(t *testing.T) {
	dir := t.TempDir()
	keyFile := filepath.Join(dir, "device.key")
	// 首块为 EC PRIVATE KEY 的合法 PEM(body 任意合法 base64,类型判定在 DER 解码之前)。
	must(t, os.WriteFile(keyFile, []byte("-----BEGIN EC PRIVATE KEY-----\naGVsbG8=\n-----END EC PRIVATE KEY-----\n"), 0o600))
	if _, err := resolveFingerprint("", keyFile); err == nil {
		t.Fatal("expected error for non-CERTIFICATE PEM block, got nil")
	} else if !strings.Contains(err.Error(), "CERTIFICATE") {
		t.Errorf("error should explain the PEM type mismatch: %v", err)
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
