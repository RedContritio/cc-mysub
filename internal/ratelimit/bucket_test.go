package ratelimit

import (
	"testing"
	"time"
)

func TestLimiterAllowsUpToBurst(t *testing.T) {
	now := time.Unix(0, 0)
	clock := func() time.Time { return now }
	l := NewLimiter(clock)
	// 每分钟 2 个 => burst 2
	for i := 0; i < 2; i++ {
		if !l.Allow("dev", 2) {
			t.Fatalf("request %d should be allowed", i)
		}
	}
	if l.Allow("dev", 2) {
		t.Error("3rd request should be denied")
	}
}

func TestLimiterRefills(t *testing.T) {
	now := time.Unix(0, 0)
	clock := func() time.Time { return now }
	l := NewLimiter(clock)
	l.Allow("dev", 60) // 每分钟 60 => 每秒补 1
	l.Allow("dev", 60)
	// 耗尽
	for l.Allow("dev", 60) {
	}
	now = now.Add(2 * time.Second) // 补 ~2 个
	if !l.Allow("dev", 60) {
		t.Error("should refill after 2s")
	}
}

func TestLimiterPerDeviceIsolation(t *testing.T) {
	now := time.Unix(0, 0)
	l := NewLimiter(func() time.Time { return now })
	l.Allow("a", 1)
	if !l.Allow("b", 1) {
		t.Error("device b should have its own bucket")
	}
}
