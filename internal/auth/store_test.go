package auth

import (
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
