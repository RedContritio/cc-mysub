package proxy

import (
	"bytes"
	"encoding/json"
)

type Usage struct {
	Model        string
	InputTokens  int
	OutputTokens int
}

type usageWire struct {
	Model   string `json:"model"`
	Message struct {
		Model string `json:"model"`
		Usage struct {
			In  int `json:"input_tokens"`
			Out int `json:"output_tokens"`
		} `json:"usage"`
	} `json:"message"`
	Usage struct {
		In  int `json:"input_tokens"`
		Out int `json:"output_tokens"`
	} `json:"usage"`
}

func SniffUsageJSON(b []byte) Usage {
	var w usageWire
	if err := json.Unmarshal(b, &w); err != nil {
		return Usage{}
	}
	return Usage{Model: w.Model, InputTokens: w.Usage.In, OutputTokens: w.Usage.Out}
}

// SniffUsageSSE 扫描 SSE 帧, 合并 message_start(model+input) 与 message_delta(output).
func SniffUsageSSE(b []byte) Usage {
	var u Usage
	for _, line := range bytes.Split(b, []byte("\n")) {
		if !bytes.HasPrefix(line, []byte("data:")) {
			continue
		}
		payload := bytes.TrimSpace(line[len("data:"):])
		var w usageWire
		if json.Unmarshal(payload, &w) != nil {
			continue
		}
		if w.Message.Model != "" {
			u.Model = w.Message.Model
		}
		if w.Message.Usage.In > 0 {
			u.InputTokens = w.Message.Usage.In
		}
		if w.Usage.Out > 0 {
			u.OutputTokens = w.Usage.Out
		}
		if w.Usage.In > 0 {
			u.InputTokens = w.Usage.In
		}
	}
	return u
}
