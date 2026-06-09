package hosts

import (
	"slices"
	"sort"
	"testing"
)

// TestDisjoint 守护两类互斥的契约:一个 host 不能既 MITM 又透传(否则 forward-proxy 分类歧义,
// 会把本应换 token 的 host 降级成盲隧道)。NewForwardProxy 也在运行期 panic 强制此契约,这里在
// 清单层面再钉一道,使误把 host 写进两表在测试期即暴露。
func TestDisjoint(t *testing.T) {
	for _, h := range MITMHosts {
		if slices.Contains(PassthroughHosts, h) {
			t.Errorf("host %q 同时在 MITMHosts 与 PassthroughHosts(两类必须互斥)", h)
		}
	}
}

// TestAll 验证 All() = MITMHosts ∪ PassthroughHosts(无重复、覆盖两类全部 host),
// 供设备 splitter 默认 allow 与 cc-mysub 合并准入门用。
func TestAll(t *testing.T) {
	all := All()
	want := []string{
		"api.anthropic.com",
		"console.anthropic.com",
		"downloads.claude.ai",
		"http-intake.logs.us5.datadoghq.com",
	}
	got := append([]string(nil), all...)
	sort.Strings(got)
	sort.Strings(want)
	if len(got) != len(want) {
		t.Fatalf("All() = %v, want %v (len mismatch)", all, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("All() sorted = %v, want %v", got, want)
		}
	}
	// All() 是两类的并集——逐一核对每个 host 确属其一(防止 All 漏项或混入第三类)。
	for _, h := range all {
		if !slices.Contains(MITMHosts, h) && !slices.Contains(PassthroughHosts, h) {
			t.Errorf("All() 含 %q 但既不在 MITMHosts 也不在 PassthroughHosts", h)
		}
	}
}
