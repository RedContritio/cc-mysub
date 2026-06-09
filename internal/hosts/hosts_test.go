package hosts

import (
	"sort"
	"testing"
)

func TestClassify(t *testing.T) {
	cases := []struct {
		host string
		want Mode
	}{
		// MITM 类:Anthropic 控制面/数据面(换 token)
		{"api.anthropic.com", ModeMITM},
		{"console.anthropic.com", ModeMITM},
		// Passthrough 类:遥测/更新(经出口、不解密、不碰 token)
		{"http-intake.logs.us5.datadoghq.com", ModePassthrough},
		{"downloads.claude.ai", ModePassthrough},
		// 未知 host → Deny(精确匹配;不做后缀/通配放宽)
		{"evil.example.com", ModeDeny},
		{"", ModeDeny},
		// 精确匹配:子域/父域均不命中
		{"sub.api.anthropic.com", ModeDeny},
		{"anthropic.com", ModeDeny},
		{"datadoghq.com", ModeDeny},
		{"http-intake.logs.us3.datadoghq.com", ModeDeny}, // 其它 DD site 不放行
	}
	for _, c := range cases {
		if got := Classify(c.host); got != c.want {
			t.Errorf("Classify(%q) = %v, want %v", c.host, got, c.want)
		}
	}
}

// All 返回 MITM∪Passthrough,供设备 splitter 默认 allow 与 cc-mysub 合并准入门用。
// 必须无重复、覆盖两类全部 host。
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
	// All 与 Classify 自洽:All 里每个 host 都非 Deny
	for _, h := range all {
		if Classify(h) == ModeDeny {
			t.Errorf("All() 含 %q 但 Classify 归为 Deny", h)
		}
	}
}
