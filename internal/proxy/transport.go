package proxy

import (
	"net/http"
	"time"
)

// retryTransport 对网络层错误(非 HTTP 状态码错误)按 delays 重试.
type retryTransport struct {
	base   http.RoundTripper
	delays []time.Duration
}

func (t *retryTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	var resp *http.Response
	var err error
	for i, d := range t.delays {
		if i > 0 {
			// 重试前必须能重放 body，否则会向上游发出被截断的请求体（违治理总纲「body 逐字节不动」）。
			// 与 stdlib Transport.isReplayable 对齐：仅当无 body 或可经 GetBody 重置时才重试。
			if req.Body != nil && req.Body != http.NoBody {
				if req.GetBody == nil {
					return resp, err // 不可重放 → 不重试，返回上次错误
				}
				body, gerr := req.GetBody()
				if gerr != nil {
					return resp, err
				}
				req.Body = body
			}
			time.Sleep(d)
		}
		resp, err = t.base.RoundTrip(req)
		if err == nil {
			return resp, nil
		}
	}
	return resp, err
}
