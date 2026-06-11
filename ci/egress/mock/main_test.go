package main

import (
	"fmt"
	"strings"
	"sync"
	"testing"
)

// TestSNIInventory_ConcurrentReadWriteSafe 复现 finding id 67: dumpAndExit 渲染 SNI inventory 时
// 若锁外读 sni map,与并发的 getCert 写(sni[name]++,由 TLS 握手 goroutine 触发)构成 data race,
// -race 下触发 Go runtime fatal、截断 mock.out。sniInventory 全程持锁快照,故并发写下安全。
// 本测试在 writer goroutine 持续写入的同时反复渲染 inventory,以 -race 钉住该契约,并校验渲染格式。
func TestSNIInventory_ConcurrentReadWriteSafe(t *testing.T) {
	var mu sync.Mutex
	sni := map[string]int{}
	hosts := []string{"api.anthropic.com", "http-intake.logs.us5.datadoghq.com", "downloads.claude.ai"}

	stop := make(chan struct{})
	var wg sync.WaitGroup
	// writers: 模拟 getCert 回调在握手 goroutine 里并发自增计数。
	for _, h := range hosts {
		wg.Add(1)
		go func(host string) {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
					mu.Lock()
					sni[host]++
					mu.Unlock()
				}
			}
		}(h)
	}
	// reader: 与写并发反复渲染 inventory(若 sniInventory 锁外读 map,-race 在此抓到)。
	for i := 0; i < 2000; i++ {
		_ = sniInventory(&mu, sni)
	}
	close(stop)
	wg.Wait()

	// 终态快照: 每个 host 必有一行、count>0,格式为 "host ... count=N"。
	lines := sniInventory(&mu, sni)
	seen := map[string]bool{}
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			t.Fatalf("inventory line malformed: %q", line)
		}
		host := fields[0]
		var n int
		if _, err := fmt.Sscanf(fields[len(fields)-1], "count=%d", &n); err != nil {
			t.Fatalf("inventory line %q: cannot parse count: %v", line, err)
		}
		if n <= 0 {
			t.Errorf("host %q count = %d; want > 0", host, n)
		}
		seen[host] = true
	}
	for _, h := range hosts {
		if !seen[h] {
			t.Errorf("inventory missing host %q", h)
		}
	}
}

// TestSNIInventory_EmptyAndSorted 边界: 空表渲染零行(扫描产出为空不 panic);多 host 输出按字典序。
func TestSNIInventory_EmptyAndSorted(t *testing.T) {
	var mu sync.Mutex
	if got := sniInventory(&mu, map[string]int{}); len(got) != 0 {
		t.Fatalf("empty map → %d lines; want 0", len(got))
	}
	lines := sniInventory(&mu, map[string]int{"b.example": 2, "a.example": 1, "c.example": 3})
	if len(lines) != 3 {
		t.Fatalf("got %d lines; want 3", len(lines))
	}
	var hosts []string
	for _, line := range lines {
		hosts = append(hosts, strings.Fields(line)[0])
	}
	for i := 1; i < len(hosts); i++ {
		if hosts[i-1] > hosts[i] {
			t.Errorf("inventory not sorted: %v", hosts)
		}
	}
}
