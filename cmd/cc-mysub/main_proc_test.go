package main

import (
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// buildCLI 构建当前平台 cc-mysub 二进制并返回路径（构建方式同 buildRealBin，要路径不要字节）。
func buildCLI(t *testing.T) string {
	t.Helper()
	repoRoot, _ := filepath.Abs("../..")
	bin := filepath.Join(t.TempDir(), "cc-mysub")
	cmd := exec.Command("go", "build", "-o", bin, "./cmd/cc-mysub")
	cmd.Dir = repoRoot
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build cc-mysub: %v\n%s", err, b)
	}
	return bin
}

// TestNoHome_ExplicitConfigDir 守 Backlog P1：launchd 最小环境（空 env，无 HOME/XDG_CONFIG_HOME）
// 下，显式 --config-dir 必须在任何默认目录解析之前生效——失败点必须是 load config（目录里
// 没有 config.json），绝不能是「无法确定配置目录」的 fail-fast。
func TestNoHome_ExplicitConfigDir(t *testing.T) {
	bin := buildCLI(t)
	bareEnv := []string{} // launchd 最小环境近似：不含 HOME/XDG_CONFIG_HOME

	t.Run("serve path honors explicit flag", func(t *testing.T) {
		cmd := exec.Command(bin, "--config-dir", t.TempDir())
		cmd.Env = bareEnv
		out, err := cmd.CombinedOutput()
		if err == nil {
			t.Fatalf("expected exit 1 (missing config.json), got success: %s", out)
		}
		if strings.Contains(string(out), "无法确定配置目录") {
			t.Fatalf("explicit --config-dir 被默认目录解析抢跑(Backlog P1 回归): %s", out)
		}
		if !strings.Contains(string(out), "load config") {
			t.Fatalf("失败点应是 load config: %s", out)
		}
	})

	t.Run("serve path without flag fails loud", func(t *testing.T) {
		cmd := exec.Command(bin)
		cmd.Env = bareEnv
		out, err := cmd.CombinedOutput()
		if err == nil {
			t.Fatalf("expected exit 1, got success: %s", out)
		}
		if !strings.Contains(string(out), "无法确定配置目录") {
			t.Fatalf("缺省目录不可解析必须 loud-fail(不静默回退根路径): %s", out)
		}
	})

	// 四个子命令分发处曾同样急切求值(main.go 旧 :24/:34/:47/:50)——逐个守住:
	// 显式 -config-dir 下输出绝不能出现默认目录解析错误(退出码/具体失败点各异,不在此断言)。
	for _, sub := range []string{"add-device", "remove-device", "gen-config", "device-init"} {
		t.Run(sub+" honors explicit flag", func(t *testing.T) {
			cmd := exec.Command(bin, sub, "-config-dir", t.TempDir())
			cmd.Env = bareEnv
			out, _ := cmd.CombinedOutput()
			if strings.Contains(string(out), "无法确定配置目录") {
				t.Fatalf("%s 的显式 -config-dir 被默认目录解析抢跑: %s", sub, out)
			}
		})
	}
}
