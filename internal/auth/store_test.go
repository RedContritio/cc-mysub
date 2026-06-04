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
