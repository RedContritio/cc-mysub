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

// TestReloadCallsOnRevoke 验证 P1-2:reload 检测到 fingerprint 从 devices.json 删除时回调 onRevoke
// (供 forward-proxy 主动断开被吊销设备的既有连接);无变化的 reload 不重复回调。
func TestReloadCallsOnRevoke(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "devices.json")
	fpA := strings.Repeat("a", 64)
	fpB := strings.Repeat("b", 64)
	writeDevices(t, p, `[{"label":"a","cert_sha256":"`+fpA+`"},{"label":"b","cert_sha256":"`+fpB+`"}]`)
	s, err := NewDeviceStore(p)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	s.SetOnRevoke(func(removed []string) { got = append(got, removed...) })

	// 删 A 只留 B → reload 回调 onRevoke([fpA])
	writeDevices(t, p, `[{"label":"b","cert_sha256":"`+fpB+`"}]`)
	if err := s.reload(); err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0] != fpA {
		t.Fatalf("onRevoke got %v, want [%s]", got, fpA)
	}

	// 无变化 reload → 不重复回调
	got = nil
	if err := s.reload(); err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Errorf("onRevoke called on no-change reload: %v", got)
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
	// 丢弃非规范行时必须大声 slog.Warn(错误可见),不静默 continue——捕获默认 slog 断言可见性。
	var logBuf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelWarn})))
	t.Cleanup(func() { slog.SetDefault(prev) })

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
	// 三条非规范行(empty/short/upper)各产一条 surface 日志,「错误可见」契约不为空话。
	if n := bytes.Count(logBuf.Bytes(), []byte("non-canonical cert_sha256")); n != 3 {
		t.Errorf("expected 3 loud drop logs for non-canonical rows, got %d: %q", n, logBuf.String())
	}
}

// TestReloadCoercesNegativeRateLimit 契约(P3-23):负 rate_limit 只来自手编 devices.json
// (CLI 的 Resolve 在登记期已拒负值)。非安全不变量(middleware 只采信 >0),故大声告警并归零到
// 代理默认、行仍进表——避免一处 typo 拒载整个文件锁死整个 fleet。
func TestReloadCoercesNegativeRateLimit(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "devices.json")
	fp := CertFingerprint([]byte("dev"))
	writeDevices(t, p, `[{"label":"neg","cert_sha256":"`+fp+`","rate_limit":-5}]`)

	var logBuf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelWarn})))
	t.Cleanup(func() { slog.SetDefault(prev) })

	s, err := NewDeviceStore(p)
	if err != nil {
		t.Fatalf("negative rate_limit must not reject the file: %v", err)
	}
	d, ok := s.byHash[fp]
	if !ok {
		t.Fatal("row with negative rate_limit should still load")
	}
	if d.RateLimit != 0 {
		t.Errorf("negative rate_limit should be coerced to 0 (proxy default), got %d", d.RateLimit)
	}
	if !bytes.Contains(logBuf.Bytes(), []byte("negative rate_limit")) {
		t.Errorf("coercion must be loud (errors visible), log: %q", logBuf.String())
	}
}

// TestReloadRejectsDuplicateFingerprint 契约(P1 吊销链):同一 cert_sha256 多行 = 同一设备多别名,
// reload 拒载整个文件(不做 last-wins),否则按 label 吊销会假成功而指纹经另一行仍被授权。
func TestReloadRejectsDuplicateFingerprint(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "devices.json")
	dup := strings.Repeat("a", 64)
	writeDevices(t, p, `[{"label":"x","cert_sha256":"`+dup+`"},{"label":"y","cert_sha256":"`+dup+`"}]`)
	// 初次加载即拒(NewDeviceStore→reload 返回 error),fail-closed:整文件不进表。
	if _, err := NewDeviceStore(p); err == nil {
		t.Fatal("NewDeviceStore must reject devices.json with duplicate cert_sha256")
	}
}

// TestReloadDuplicateFingerprintKeepsPrevious 契约:运行中热重载遇重复指纹文件时,reload 返回 error
// 且保留旧表(与坏 JSON 同 fail-closed 语义),既不 last-wins 也不清空授权。
func TestReloadDuplicateFingerprintKeepsPrevious(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "devices.json")
	fp1 := CertFingerprint([]byte("one"))
	writeDevices(t, p, `[{"label":"a","cert_sha256":"`+fp1+`"}]`)
	s, err := NewDeviceStore(p)
	if err != nil {
		t.Fatal(err)
	}
	dup := strings.Repeat("b", 64)
	writeDevices(t, p, `[{"label":"x","cert_sha256":"`+dup+`"},{"label":"y","cert_sha256":"`+dup+`"}]`)
	if err := s.reload(); err == nil {
		t.Fatal("reload must reject duplicate cert_sha256")
	}
	if _, ok := s.Lookup(fp1); !ok {
		t.Error("previous table must be kept after dup-fingerprint reload")
	}
	if _, ok := s.Lookup(dup); ok {
		t.Error("rejected duplicate fingerprint must not be authenticated")
	}
}

// TestStatFailureLogsLoudAndKeepsTable 契约(P2):watcher 的 os.Stat 失败(devices.json 被删)与
// reload 失败同等大声 slog.Error 并保留旧表;状态翻转去重使持续失败只记一条,不每秒刷屏。
func TestStatFailureLogsLoudAndKeepsTable(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "devices.json")
	fp := CertFingerprint([]byte("keep"))
	writeDevices(t, p, `[{"label":"a","cert_sha256":"`+fp+`"}]`)
	s, err := NewDeviceStore(p)
	if err != nil {
		t.Fatal(err)
	}

	var logBuf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelError})))
	t.Cleanup(func() { slog.SetDefault(prev) })

	s.pollInterval = 20 * time.Millisecond
	s.StartWatch()

	// 删除 devices.json → 后续每次 stat 都失败。
	if err := os.Remove(p); err != nil {
		t.Fatal(err)
	}
	time.Sleep(200 * time.Millisecond)
	s.StopWatch()

	if !bytes.Contains(logBuf.Bytes(), []byte("stat failed")) {
		t.Fatalf("expected loud stat-failure log, got: %q", logBuf.String())
	}
	// 状态翻转去重:多次轮询失败只记一条。
	if n := bytes.Count(logBuf.Bytes(), []byte("stat failed")); n != 1 {
		t.Errorf("stat failure should log once (state-flip dedup), logged %d times: %q", n, logBuf.String())
	}
	// 旧表保留:删文件不静默撤销,fp 仍命中。
	if _, ok := s.Lookup(fp); !ok {
		t.Error("prior table must be kept after stat failure")
	}
}

// TestHotReloadDetectsMtimeRollback 契约(P3,finding 11):判据改 !Equal 后,mtime 回退(cp -p/
// rsync -a 从备份恢复)的 devices.json 也会被重载;旧 After() 判据会永久漏掉(旧 mtime 永不 > lastMod)。
func TestHotReloadDetectsMtimeRollback(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "devices.json")
	fp1 := CertFingerprint([]byte("v1"))
	fp2 := CertFingerprint([]byte("v2"))
	writeDevices(t, p, `[{"label":"a","cert_sha256":"`+fp1+`"}]`)
	s, err := NewDeviceStore(p)
	if err != nil {
		t.Fatal(err)
	}

	// 模拟备份恢复:换内容并把 mtime 回退到一小时前(保留时间戳的恢复方式)。
	writeDevices(t, p, `[{"label":"b","cert_sha256":"`+fp2+`"}]`)
	old := time.Now().Add(-time.Hour)
	if err := os.Chtimes(p, old, old); err != nil {
		t.Fatal(err)
	}

	s.pollInterval = 20 * time.Millisecond
	s.StartWatch()
	defer s.StopWatch()

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		_, has2 := s.Lookup(fp2)
		_, had1 := s.Lookup(fp1)
		if has2 && !had1 {
			return // 回退被检测并加载
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("mtime rollback not detected (After() bug: rolled-back devices.json never reloaded)")
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
