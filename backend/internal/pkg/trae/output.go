package trae

// 下游出口：把标准 OpenAI SSE 透传给客户端，或聚合成单个 chat.completion。
//
// 与 pkg/qoder 的同名函数职责相同。**刻意各写一份而不是抽公共包**：
// 两边的上游协议完全不同（qoder 是信封、trae 是事件流），共用一个包会把
// 两套协议的演化绑在一起 —— 改 trae 的聚合策略不该动到 qoder 的行为。
// 如果将来出现第三家用 OpenAI SSE 的上游，那时再抽也不迟。

import (
	"bufio"
	"encoding/json"
	"io"
	"net/http"
	"strings"
)

// StreamAll 把标准 OpenAI SSE 原样写给客户端，同时把内容镜像进 sink。
//
// sink 用于提取 usage（上游只在末帧给，调用方通常传尾部缓冲）。
func StreamAll(w io.Writer, rc io.Reader, sink io.Writer) error {
	buf := make([]byte, 32<<10)
	for {
		n, err := rc.Read(buf)
		if n > 0 {
			chunk := buf[:n]
			if _, werr := w.Write(chunk); werr != nil {
				return werr
			}
			if f, ok := w.(http.Flusher); ok {
				f.Flush()
			}
			if sink != nil {
				_, _ = sink.Write(chunk)
			}
		}
		if err != nil {
			if err == io.EOF {
				return nil
			}
			return err
		}
	}
}

// Aggregate 把一个标准 OpenAI SSE 流聚合成单个 chat.completion 对象。
//
// 上游没有非流式端点，所以非流式客户端只能靠这里聚合 —— 这是协议约束。
func Aggregate(rc io.Reader) (map[string]any, error) {
	scanner := bufio.NewScanner(rc)
	scanner.Buffer(make([]byte, 0, 1<<20), 8<<20)

	var content, reasoning strings.Builder
	var toolCalls []any
	finishReason := ""
	var usage map[string]any
	id, model := "", ""
	var created any

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if !strings.HasPrefix(line, "data:") {
			continue
		}
		payload := strings.TrimSpace(strings.TrimPrefix(line, "data:"))
		if payload == "" || payload == "[DONE]" {
			continue
		}
		var frame struct {
			ID      string `json:"id"`
			Model   string `json:"model"`
			Created any    `json:"created"`
			Choices []struct {
				Delta struct {
					Content          string `json:"content"`
					ReasoningContent string `json:"reasoning_content"`
					ToolCalls        []any  `json:"tool_calls"`
				} `json:"delta"`
				Message struct {
					Content          string `json:"content"`
					ReasoningContent string `json:"reasoning_content"`
					ToolCalls        []any  `json:"tool_calls"`
				} `json:"message"`
				FinishReason *string `json:"finish_reason"`
			} `json:"choices"`
			Usage map[string]any `json:"usage"`
		}
		if err := json.Unmarshal([]byte(payload), &frame); err != nil {
			continue
		}
		if frame.ID != "" {
			id = frame.ID
		}
		if frame.Model != "" {
			model = frame.Model
		}
		if frame.Created != nil {
			created = frame.Created
		}
		if frame.Usage != nil {
			usage = frame.Usage
		}
		for _, ch := range frame.Choices {
			content.WriteString(ch.Delta.Content)
			content.WriteString(ch.Message.Content)
			reasoning.WriteString(ch.Delta.ReasoningContent)
			reasoning.WriteString(ch.Message.ReasoningContent)
			toolCalls = append(toolCalls, ch.Delta.ToolCalls...)
			toolCalls = append(toolCalls, ch.Message.ToolCalls...)
			if ch.FinishReason != nil && *ch.FinishReason != "" {
				finishReason = *ch.FinishReason
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}

	message := map[string]any{"role": "assistant", "content": content.String()}
	if r := reasoning.String(); r != "" {
		message["reasoning_content"] = r
	}
	if len(toolCalls) > 0 {
		message["tool_calls"] = toolCalls
	}
	if finishReason == "" {
		finishReason = "stop"
	}

	out := map[string]any{
		"id":     id,
		"object": "chat.completion",
		"model":  model,
		"choices": []any{map[string]any{
			"index":         0,
			"message":       message,
			"finish_reason": finishReason,
		}},
	}
	if created != nil {
		out["created"] = created
	}
	if usage != nil {
		out["usage"] = usage
	}
	return out, nil
}
