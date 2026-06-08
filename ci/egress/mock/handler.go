package main

import (
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
)

// Recorder 记录所有到达 mock 的请求的 Authorization 值（用于断言 1）。
type Recorder struct {
	mu    sync.Mutex
	auths []string
}

func (r *Recorder) add(a string) { r.mu.Lock(); r.auths = append(r.auths, a); r.mu.Unlock() }
func (r *Recorder) Auths() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]string, len(r.auths))
	copy(out, r.auths)
	return out
}

func newMux(rec *Recorder) http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("/v1/messages/count_tokens", func(w http.ResponseWriter, r *http.Request) {
		rec.add(r.Header.Get("Authorization"))
		_, _ = io.Copy(io.Discard, r.Body)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"input_tokens":12}`))
	})

	// 任意 /v1/messages（含 max_tokens:1 的 '.'/'test'/'quota' 探针）一律 200。
	mux.HandleFunc("/v1/messages", func(w http.ResponseWriter, r *http.Request) {
		rec.add(r.Header.Get("Authorization"))
		body, _ := io.ReadAll(r.Body)
		if !strings.Contains(string(body), `"stream":true`) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"id":"msg_mock","type":"message","role":"assistant","model":"claude-opus-4-8","content":[{"type":"text","text":"ok"}],"stop_reason":"end_turn","usage":{"input_tokens":12,"output_tokens":1}}`))
			return
		}
		w.Header().Set("Content-Type", "text/event-stream")
		fl, _ := w.(http.Flusher)
		send := func(ev, data string) {
			fmt.Fprintf(w, "event: %s\ndata: %s\n\n", ev, data)
			if fl != nil {
				fl.Flush()
			}
		}
		send("message_start", `{"type":"message_start","message":{"id":"msg_mock","type":"message","role":"assistant","model":"claude-opus-4-8","content":[],"stop_reason":null,"usage":{"input_tokens":12,"output_tokens":1}}}`)
		send("content_block_start", `{"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}`)
		send("content_block_delta", `{"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"ok"}}`)
		send("content_block_stop", `{"type":"content_block_stop","index":0}`)
		send("message_delta", `{"type":"message_delta","delta":{"stop_reason":"end_turn"},"usage":{"output_tokens":1}}`)
		send("message_stop", `{"type":"message_stop"}`)
	})

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		rec.add(r.Header.Get("Authorization"))
		_, _ = io.Copy(io.Discard, r.Body)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{}`))
	})
	return mux
}
