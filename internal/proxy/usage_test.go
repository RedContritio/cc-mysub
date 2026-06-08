package proxy

import "testing"

func TestSniffUsageJSON(t *testing.T) {
	body := `{"model":"claude-opus","usage":{"input_tokens":10,"output_tokens":5}}`
	u := SniffUsageJSON([]byte(body))
	if u.Model != "claude-opus" || u.InputTokens != 10 || u.OutputTokens != 5 {
		t.Errorf("got %+v", u)
	}
}

func TestSniffUsageSSE(t *testing.T) {
	sse := "event: message_start\ndata: {\"message\":{\"model\":\"claude-haiku\",\"usage\":{\"input_tokens\":7,\"output_tokens\":0}}}\n\n" +
		"event: message_delta\ndata: {\"usage\":{\"output_tokens\":42}}\n\n"
	u := SniffUsageSSE([]byte(sse))
	if u.Model != "claude-haiku" || u.InputTokens != 7 || u.OutputTokens != 42 {
		t.Errorf("got %+v", u)
	}
}

func TestSniffUsageGarbageNoCrash(t *testing.T) {
	u := SniffUsageJSON([]byte("not json"))
	if u.Model != "" { // 降级: 返回零值不 panic
		t.Errorf("got %+v", u)
	}
}
