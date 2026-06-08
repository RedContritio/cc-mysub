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
	// v4 audit wrinkle: cc-mysub dials the real CONNECT host (api.anthropic.com:443)
	// over HTTPS via http.DefaultTransport, which verifies the server cert against
	// system roots. In the sealed netns the mock stands in for that host, so it must
	// present a TLS cert for that name signed by an audit CA installed in the
	// container trust store. When MOCK_TLS_CERT/MOCK_TLS_KEY are both set, serve
	// HTTPS; otherwise keep plain HTTP (back-compat with the v3 stages).
	cert, key := os.Getenv("MOCK_TLS_CERT"), os.Getenv("MOCK_TLS_KEY")
	if cert != "" && key != "" {
		fmt.Fprintln(os.Stderr, "mock listening on", addr, "(TLS)")
		if err := http.ListenAndServeTLS(addr, cert, key, newMux(rec)); err != nil {
			fmt.Fprintln(os.Stderr, "mock:", err)
			os.Exit(1)
		}
		return
	}
	fmt.Fprintln(os.Stderr, "mock listening on", addr)
	if err := http.ListenAndServe(addr, newMux(rec)); err != nil {
		fmt.Fprintln(os.Stderr, "mock:", err)
		os.Exit(1)
	}
}
