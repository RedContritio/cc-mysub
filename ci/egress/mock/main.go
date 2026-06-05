package main

import (
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"sort"
	"syscall"
)

func main() {
	addr := "127.0.0.1:9443"
	if a := os.Getenv("MOCK_ADDR"); a != "" {
		addr = a
	}
	rec := &Recorder{}
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sig
		auths := rec.Auths()
		sort.Strings(auths)
		fmt.Println("=== MOCK AUTHORIZATIONS (deduped) ===")
		last := ""
		for _, a := range auths {
			if a != last {
				fmt.Println(a)
				last = a
			}
		}
		os.Exit(0)
	}()
	fmt.Fprintln(os.Stderr, "mock listening on", addr)
	if err := http.ListenAndServe(addr, newMux(rec)); err != nil {
		fmt.Fprintln(os.Stderr, "mock:", err)
		os.Exit(1)
	}
}
