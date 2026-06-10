package main

import (
	"path/filepath"
	"testing"
)

// TestResolveConfigDir 守 id 56：HOME/用户主目录不可解析时 resolveConfigDir 返回 error，
// 绝不静默回退到文件系统根下的 /.config/cc-mysub（LaunchDaemon 最小环境无 HOME 时的 crash-loop 根因）。
func TestResolveConfigDir(t *testing.T) {
	t.Run("XDG_CONFIG_HOME wins", func(t *testing.T) {
		t.Setenv("XDG_CONFIG_HOME", "/xdg")
		t.Setenv("HOME", "/home/ignored")
		got, err := resolveConfigDir()
		if err != nil {
			t.Fatalf("unexpected err: %v", err)
		}
		if want := filepath.Join("/xdg", "cc-mysub"); got != want {
			t.Errorf("got %q want %q", got, want)
		}
	})

	t.Run("HOME fallback", func(t *testing.T) {
		t.Setenv("XDG_CONFIG_HOME", "")
		t.Setenv("HOME", "/home/alice")
		got, err := resolveConfigDir()
		if err != nil {
			t.Fatalf("unexpected err: %v", err)
		}
		if want := filepath.Join("/home/alice", ".config", "cc-mysub"); got != want {
			t.Errorf("got %q want %q", got, want)
		}
	})

	t.Run("no HOME, no XDG → error (no root fallback)", func(t *testing.T) {
		t.Setenv("XDG_CONFIG_HOME", "")
		t.Setenv("HOME", "")
		got, err := resolveConfigDir()
		if err == nil {
			t.Fatalf("expected error when HOME unresolvable, got %q (must not silently fall back to /.config)", got)
		}
		if got != "" {
			t.Errorf("on error the path must be empty, got %q", got)
		}
	})
}
