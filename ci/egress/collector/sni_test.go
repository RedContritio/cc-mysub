package main

import (
	"crypto/tls"
	"net"
	"testing"
	"time"
)

// 用真 crypto/tls 客户端在 net.Pipe 上产出一个真实 ClientHello，喂给 ParseSNI。
func clientHelloBytes(t *testing.T, serverName string) []byte {
	t.Helper()
	c, s := net.Pipe()
	defer c.Close()
	defer s.Close()
	got := make(chan []byte, 1)
	go func() {
		buf := make([]byte, 4096)
		_ = s.SetReadDeadline(time.Now().Add(2 * time.Second))
		n, _ := s.Read(buf)
		got <- buf[:n]
	}()
	_ = c.SetDeadline(time.Now().Add(2 * time.Second))
	// Handshake 会因对端不回应而失败，但 ClientHello 已写出，足够测试。
	_ = tls.Client(c, &tls.Config{ServerName: serverName, InsecureSkipVerify: true}).Handshake()
	select {
	case b := <-got:
		return b
	case <-time.After(2 * time.Second):
		t.Fatal("no ClientHello captured")
		return nil
	}
}

func TestParseSNI_RealClientHello(t *testing.T) {
	host, ok := ParseSNI(clientHelloBytes(t, "api.anthropic.com"))
	if !ok || host != "api.anthropic.com" {
		t.Fatalf("ParseSNI = %q,%v; want api.anthropic.com,true", host, ok)
	}
}

func TestParseSNI_NonTLS(t *testing.T) {
	if host, ok := ParseSNI([]byte("GET / HTTP/1.1\r\n")); ok {
		t.Errorf("ParseSNI on non-TLS = %q,true; want _,false", host)
	}
}

func TestParseSNI_Truncated(t *testing.T) {
	if _, ok := ParseSNI([]byte{0x16, 0x03, 0x01, 0x00}); ok {
		t.Errorf("ParseSNI on truncated record returned ok=true")
	}
}
