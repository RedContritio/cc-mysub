package auth

import (
	"bytes"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func writeDevices(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestStoreLookup(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "devices.json")
	// cert_sha256 直接就是 Lookup 入参（指纹），不再二次哈希。
	fp := CertFingerprint([]byte("dev-a"))
	writeDevices(t, p, `[{"label":"laptop","cert_sha256":"`+fp+`","rate_limit":60}]`)

	s, err := NewDeviceStore(p)
	if err != nil {
		t.Fatal(err)
	}
	dev, ok := s.Lookup(fp)
	if !ok || dev.Label != "laptop" {
		t.Fatalf("Lookup failed: ok=%v dev=%+v", ok, dev)
	}
	// "wrong" 是非 64-hex 串 → CanonicalFingerprint 拒 → 天然 miss。
	if _, ok := s.Lookup("wrong"); ok {
		t.Error("non-canonical fingerprint should not match")
	}
	// 合法但不在表里的指纹也 miss。
	if _, ok := s.Lookup(CertFingerprint([]byte("dev-b"))); ok {
		t.Error("unknown fingerprint should not match")
	}
}

func TestDevice_UpstreamField(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "devices.json")
	fp := CertFingerprint([]byte("dev-x"))
	writeDevices(t, p, `[{"label":"l","cert_sha256":"`+fp+`","upstream":"b"}]`)
	s, err := NewDeviceStore(p)
	if err != nil {
		t.Fatal(err)
	}
	d, ok := s.Lookup(fp)
	if !ok || d.Upstream != "b" {
		t.Fatalf("upstream = %q ok=%v", d.Upstream, ok)
	}

	// 哨兵值 "" = 使用默认 token：字段缺失 与 显式 "upstream":"" 两种零值路径都须解析为 ""。
	fpMissing, fpExplicit := CertFingerprint([]byte("dev-missing")), CertFingerprint([]byte("dev-explicit"))
	writeDevices(t, p, `[`+
		`{"label":"m","cert_sha256":"`+fpMissing+`"},`+
		`{"label":"e","cert_sha256":"`+fpExplicit+`","upstream":""}`+
		`]`)
	s2, err := NewDeviceStore(p)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{fpMissing, fpExplicit} {
		d, ok := s2.Lookup(want)
		if !ok || d.Upstream != "" {
			t.Errorf("fp %q: upstream = %q ok=%v, want empty sentinel", want, d.Upstream, ok)
		}
	}
}

func TestStoreHotReload(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "devices.json")
	fp1 := CertFingerprint([]byte("t1"))
	fp2 := CertFingerprint([]byte("t2"))
	writeDevices(t, p, `[{"label":"a","cert_sha256":"`+fp1+`"}]`)
	s, err := NewDeviceStore(p)
	if err != nil {
		t.Fatal(err)
	}
	s.pollInterval = 20 * time.Millisecond
	s.StartWatch()
	defer s.StopWatch()

	// 改文件: 撤销 fp1, 新增 fp2
	time.Sleep(10 * time.Millisecond)
	writeDevices(t, p, `[{"label":"b","cert_sha256":"`+fp2+`"}]`)

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		_, had1 := s.Lookup(fp1)
		_, has2 := s.Lookup(fp2)
		if !had1 && has2 {
			return // reload 生效
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("hot reload did not take effect")
}

// TestLookupEmptyMisses 契约：空串非规范指纹，在查表前即被 CanonicalFingerprint 守卫拒，
// Lookup("") 永远 miss。防手改 devices.json 后用空指纹撞开。
func TestLookupEmptyMisses(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "devices.json")
	writeDevices(t, p, `[{"label":"real","cert_sha256":"`+CertFingerprint([]byte("good"))+`"}]`)
	s, err := NewDeviceStore(p)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := s.Lookup(""); ok {
		t.Error(`Lookup("") must always miss`)
	}
}

// TestReloadRejectsNonCanonicalRows 契约：load 期 reload 用 CanonicalFingerprint 闸门
// 拒任何 cert_sha256 非规范的行——空串、非 64-hex 短串、以及合法十六进制但含大写的串
// （大写虽是有效 hex 却非规范，必须被拒；否则同一指纹大小写两形可双开，破坏吊销）。
// 直接断言内部表 byHash（同包白盒）以给 load 闸门真牙：非规范行根本不进表，
// 而非仅被 Lookup 入参守卫遮蔽（后者无法区分"未入表"与"入表但不可查"）。
func TestReloadRejectsNonCanonicalRows(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "devices.json")
	good := CertFingerprint([]byte("good"))
	upper := strings.ToUpper(good) // 合法 hex 但大写 → 非规范，必须被拒
	writeDevices(t, p, `[`+
		`{"label":"empty","cert_sha256":""},`+
		`{"label":"short","cert_sha256":"abcd"},`+
		`{"label":"upper","cert_sha256":"`+upper+`"},`+
		`{"label":"real","cert_sha256":"`+good+`"}`+
		`]`)
	s, err := NewDeviceStore(p)
	if err != nil {
		t.Fatal(err)
	}
	// load 闸门：仅合法行进表。
	if len(s.byHash) != 1 {
		t.Fatalf("byHash size = %d want 1 (non-canonical rows must be dropped): %+v", len(s.byHash), s.byHash)
	}
	for _, bad := range []string{"", "abcd", upper} {
		if _, present := s.byHash[bad]; present {
			t.Errorf("non-canonical key %q must not enter table", bad)
		}
	}
	// 合法行不受牵连。
	if d, ok := s.byHash[good]; !ok || d.Label != "real" {
		t.Errorf("canonical row should load: ok=%v d=%+v", ok, d)
	}
}

// TestReloadParseFailureLogsLoud 契约：热重载遇坏 JSON 时保留旧表 BUT 大声 slog.Error。
func TestReloadParseFailureLogsLoud(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "devices.json")
	fp := CertFingerprint([]byte("t1"))
	writeDevices(t, p, `[{"label":"a","cert_sha256":"`+fp+`"}]`)
	s, err := NewDeviceStore(p)
	if err != nil {
		t.Fatal(err)
	}

	// 捕获默认 slog 输出。
	var logBuf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelError})))
	t.Cleanup(func() { slog.SetDefault(prev) })

	s.pollInterval = 20 * time.Millisecond
	s.StartWatch()

	time.Sleep(10 * time.Millisecond)
	// 写入坏 JSON 触发 reload 失败。
	if err := os.WriteFile(p, []byte(`{ this is not valid json `), 0o600); err != nil {
		t.Fatal(err)
	}

	// Allow several poll cycles to fire; StopWatch then blocks until the goroutine
	// exits so that the logBuf reads below happen with no concurrent writer alive.
	time.Sleep(300 * time.Millisecond)
	s.StopWatch()
	if !bytes.Contains(logBuf.Bytes(), []byte("reload failed")) {
		t.Fatalf("expected loud reload-failure log, got: %q", logBuf.String())
	}
	// 旧表保留：fp 仍命中。
	if _, ok := s.Lookup(fp); !ok {
		t.Error("prior table must be kept after parse failure")
	}
}
