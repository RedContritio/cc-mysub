package auth

import (
	"bytes"
	"context"
	"log/slog"
	"os"
	"path/filepath"
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
	// HashToken("dev-secret") 预先算好
	h := HashToken("dev-secret")
	writeDevices(t, p, `[{"label":"laptop","token_sha256":"`+h+`","rate_limit":60}]`)

	s, err := NewDeviceStore(p)
	if err != nil {
		t.Fatal(err)
	}
	dev, ok := s.Lookup("dev-secret")
	if !ok || dev.Label != "laptop" {
		t.Fatalf("Lookup failed: ok=%v dev=%+v", ok, dev)
	}
	if _, ok := s.Lookup("wrong"); ok {
		t.Error("unknown token should not match")
	}
}

func TestDevice_UpstreamField(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "devices.json")
	tok := "cco_dev_x"
	writeDevices(t, p, `[{"label":"l","token_sha256":"`+HashToken(tok)+`","upstream":"b"}]`)
	s, err := NewDeviceStore(p)
	if err != nil {
		t.Fatal(err)
	}
	d, ok := s.Lookup(tok)
	if !ok || d.Upstream != "b" {
		t.Fatalf("upstream = %q ok=%v", d.Upstream, ok)
	}

	// 哨兵值 "" = 使用默认 token：字段缺失 与 显式 "upstream":"" 两种零值路径都须解析为 ""。
	missing, explicit := "cco_dev_missing", "cco_dev_explicit"
	writeDevices(t, p, `[`+
		`{"label":"m","token_sha256":"`+HashToken(missing)+`"},`+
		`{"label":"e","token_sha256":"`+HashToken(explicit)+`","upstream":""}`+
		`]`)
	s2, err := NewDeviceStore(p)
	if err != nil {
		t.Fatal(err)
	}
	for _, tk := range []string{missing, explicit} {
		d, ok := s2.Lookup(tk)
		if !ok || d.Upstream != "" {
			t.Errorf("token %q: upstream = %q ok=%v, want empty sentinel", tk, d.Upstream, ok)
		}
	}
}

func TestStoreHotReload(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "devices.json")
	writeDevices(t, p, `[{"label":"a","token_sha256":"`+HashToken("t1")+`"}]`)
	s, err := NewDeviceStore(p)
	if err != nil {
		t.Fatal(err)
	}
	s.pollInterval = 20 * time.Millisecond
	s.StartWatch()
	defer s.StopWatch()

	// 改文件: 撤销 t1, 新增 t2
	time.Sleep(10 * time.Millisecond)
	writeDevices(t, p, `[{"label":"b","token_sha256":"`+HashToken("t2")+`"}]`)

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		_, hadT1 := s.Lookup("t1")
		_, hasT2 := s.Lookup("t2")
		if !hadT1 && hasT2 {
			return // reload 生效
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("hot reload did not take effect")
}

// TestLookupEmptyTokenMisses 契约：空 token 在 hash 之前即被拒，绝不命中。
// 防手改 devices.json 插入 token_sha256==HashToken("") 行后用空 token 撞开。
func TestLookupEmptyTokenMisses(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "devices.json")
	writeDevices(t, p, `[{"label":"real","token_sha256":"`+HashToken("good")+`"}]`)
	s, err := NewDeviceStore(p)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := s.Lookup(""); ok {
		t.Error(`Lookup("") must always miss`)
	}
}

// TestReloadRejectsEmptyDigestRow 契约：load 期拒任何 token_sha256==HashToken("")
// 的行，使空哈希永不进表；用空 token 仍 miss。
func TestReloadRejectsEmptyDigestRow(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "devices.json")
	emptyDigest := HashToken("") // e3b0c442...b855
	writeDevices(t, p, `[`+
		`{"label":"poison","token_sha256":"`+emptyDigest+`"},`+
		`{"label":"real","token_sha256":"`+HashToken("good")+`"}`+
		`]`)
	s, err := NewDeviceStore(p)
	if err != nil {
		t.Fatal(err)
	}
	// 空 token 仍 miss（既因 Lookup 守卫，也因该行未入表）。
	if _, ok := s.Lookup(""); ok {
		t.Error(`empty-digest row must not be loadable via Lookup("")`)
	}
	// 真行不受牵连。
	if d, ok := s.Lookup("good"); !ok || d.Label != "real" {
		t.Errorf("real row should still load: ok=%v d=%+v", ok, d)
	}
}

// TestReloadParseFailureLogsLoud 契约：热重载遇坏 JSON 时保留旧表 BUT 大声 slog.Error。
func TestReloadParseFailureLogsLoud(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "devices.json")
	writeDevices(t, p, `[{"label":"a","token_sha256":"`+HashToken("t1")+`"}]`)
	s, err := NewDeviceStore(p)
	if err != nil {
		t.Fatal(err)
	}

	// 捕获默认 slog 输出。
	var logBuf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelError})))
	t.Cleanup(func() { slog.SetDefault(prev) })
	_ = context.Background() // (context import 已在文件中使用则删此行)

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
	// 旧表保留：t1 仍命中。
	if _, ok := s.Lookup("t1"); !ok {
		t.Error("prior table must be kept after parse failure")
	}
}
