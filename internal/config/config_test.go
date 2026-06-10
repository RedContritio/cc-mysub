package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadConfigDefaults(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.json")
	os.WriteFile(cfgPath, []byte(`{"listen":"127.0.0.1:9000"}`), 0o600)

	cfg, err := LoadConfig(cfgPath)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if cfg.Listen != "127.0.0.1:9000" {
		t.Errorf("Listen = %q", cfg.Listen)
	}
}

func TestLoadUpstream(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "upstream.json")
	os.WriteFile(p, []byte(`{"oauthToken":"sk-ant-oat01-XYZ"}`), 0o600)

	up, err := LoadUpstream(p)
	if err != nil {
		t.Fatalf("LoadUpstream: %v", err)
	}
	if up.OAuthToken != "sk-ant-oat01-XYZ" {
		t.Errorf("OAuthToken = %q", up.OAuthToken)
	}
}

func TestLoadUpstreamRejectsEmpty(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "upstream.json")
	os.WriteFile(p, []byte(`{"oauthToken":""}`), 0o600)
	if _, err := LoadUpstream(p); err == nil {
		t.Fatal("expected error on empty oauthToken")
	}
}

func TestUpstream_PoolAndLegacy(t *testing.T) {
	// 旧单 token 兼容
	u1, err := parseUpstream([]byte(`{"oauthToken":"sk-ant-oat01-A"}`))
	if err != nil || u1.PickToken("") != "sk-ant-oat01-A" {
		t.Fatalf("legacy single: %v %q", err, u1.PickToken(""))
	}
	// legacy 模式 + 非空 id：无池可命中 → 未命中 → 空串（不静默回退单 token）
	if u1.PickToken("some-id") != "" {
		t.Errorf("legacy with non-empty id should be empty, got %q", u1.PickToken("some-id"))
	}
	// 池 + 按 id 取
	u2, err := parseUpstream([]byte(`{"oauthTokens":[{"id":"a","token":"sk-ant-oat01-A"},{"id":"b","token":"sk-ant-oat01-B"}]}`))
	if err != nil {
		t.Fatalf("pool parse: %v", err)
	}
	if u2.PickToken("b") != "sk-ant-oat01-B" {
		t.Errorf("pool pick b = %q", u2.PickToken("b"))
	}
	if u2.PickToken("") != "sk-ant-oat01-A" { // 空 id 取第一个(默认)
		t.Errorf("pool default = %q", u2.PickToken(""))
	}
	if u2.PickToken("zzz") != "" { // 未知 id → 空(调用方 fail)
		t.Errorf("unknown id should be empty")
	}
}

// TestRequireOwnerOnly 校验敏感凭据文件的 fail-closed 权限门：仅 0600(或更严)放行，
// 任何 group/other 可访问位被拒(codex 全仓审查 P1-3)。
func TestRequireOwnerOnly(t *testing.T) {
	dir := t.TempDir()
	priv := filepath.Join(dir, "priv")
	if err := os.WriteFile(priv, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := RequireOwnerOnly(priv); err != nil {
		t.Errorf("0600 应通过: %v", err)
	}
	for _, mode := range []os.FileMode{0o640, 0o644, 0o604, 0o660, 0o666} {
		p := filepath.Join(dir, "open")
		if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(p, mode); err != nil { // 绕开 umask,确保实际 mode
			t.Fatal(err)
		}
		if err := RequireOwnerOnly(p); err == nil {
			t.Errorf("mode %#o 应被拒(group/other-accessible)", mode)
		}
	}
	if err := RequireOwnerOnly(filepath.Join(dir, "nonexist")); err == nil {
		t.Error("缺失文件应报错")
	}
}

// TestParseUpstream_StrictContract 覆盖严格契约：两种 token 全空、空池、池条目空 id/token、重复 id 均须报错。
func TestParseUpstream_StrictContract(t *testing.T) {
	cases := map[string]string{
		"both empty":          `{}`,
		"explicit empty pool": `{"oauthTokens":[]}`,
		"empty token in pool": `{"oauthTokens":[{"id":"a","token":""}]}`,
		"empty id in pool":    `{"oauthTokens":[{"id":"","token":"sk-ant-oat01-A"}]}`,
		"duplicate pool id":   `{"oauthTokens":[{"id":"a","token":"X"},{"id":"a","token":"Y"}]}`,
	}
	for name, body := range cases {
		if _, err := parseUpstream([]byte(body)); err == nil {
			t.Errorf("%s: expected error, got nil", name)
		}
	}
}
