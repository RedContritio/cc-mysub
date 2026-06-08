package main

import (
	"fmt"
	"net"
	"os"
	"os/signal"
	"sort"
	"sync"
	"syscall"
	"time"
)

type rec struct {
	count int
	first time.Time
}

func main() {
	addr := "127.0.0.2:443"
	if a := os.Getenv("COLLECTOR_ADDR"); a != "" {
		addr = a
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		fmt.Fprintln(os.Stderr, "collector listen:", err)
		os.Exit(1)
	}
	fmt.Fprintln(os.Stderr, "collector listening on", addr)

	var mu sync.Mutex
	seen := map[string]*rec{}

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sig
		mu.Lock()
		defer mu.Unlock()
		hosts := make([]string, 0, len(seen))
		for h := range seen {
			hosts = append(hosts, h)
		}
		sort.Strings(hosts)
		fmt.Println("=== EGRESS INVENTORY (collector) ===")
		for _, h := range hosts {
			fmt.Printf("%-40s count=%d\n", h, seen[h].count)
		}
		os.Exit(0)
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			continue
		}
		go func(c net.Conn) {
			defer c.Close()
			_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
			buf := make([]byte, 4096)
			n, _ := c.Read(buf)
			host, ok := ParseSNI(buf[:n])
			if !ok || host == "" {
				host = "unknown-sni"
			}
			mu.Lock()
			r := seen[host]
			if r == nil {
				r = &rec{first: time.Now()}
				seen[host] = r
			}
			r.count++
			mu.Unlock()
		}(conn)
	}
}
