package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestHandler_StreamingMessages(t *testing.T) {
	rec := &Recorder{}
	srv := httptest.NewServer(newMux(rec))
	defer srv.Close()
	req, _ := http.NewRequest("POST", srv.URL+"/v1/messages", strings.NewReader(`{"stream":true,"max_tokens":1024,"messages":[{"role":"user","content":"probe"}]}`))
	req.Header.Set("Authorization", "Bearer sk-ant-oat01-MOCKTEST")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/event-stream") {
		t.Errorf("Content-Type = %q; want text/event-stream", ct)
	}
	if len(rec.Auths()) != 1 || rec.Auths()[0] != "Bearer sk-ant-oat01-MOCKTEST" {
		t.Errorf("recorded auths = %v", rec.Auths())
	}
}

func TestHandler_NonStreamAndCountTokens(t *testing.T) {
	rec := &Recorder{}
	srv := httptest.NewServer(newMux(rec))
	defer srv.Close()
	// 非 stream → JSON
	r1, _ := http.Post(srv.URL+"/v1/messages", "application/json", strings.NewReader(`{"max_tokens":1,"messages":[{"role":"user","content":"."}]}`))
	r1.Body.Close()
	if ct := r1.Header.Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		t.Errorf("non-stream Content-Type = %q; want application/json", ct)
	}
	// count_tokens
	r2, _ := http.Post(srv.URL+"/v1/messages/count_tokens", "application/json", strings.NewReader(`{}`))
	r2.Body.Close()
	if r2.StatusCode != 200 {
		t.Errorf("count_tokens status = %d", r2.StatusCode)
	}
}
