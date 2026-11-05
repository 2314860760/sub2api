package trae

// Trae 的自定义 SSE 事件流 → 标准 OpenAI chat.completion.chunk。
//
// # 上游帧形状
//
//	event:output
//	data:{"response":"…","reasoning_content":"…","tool_calls":[…]}
//
// 事件类型：metadata / timing_cost / output / token_usage / done / error。
// `data:` 可能跨多行，拼接后再解析（上游在长文本时会断行）。
//
// # 为什么必须自己转
//
// 客户端（以及 sub2api 的网关）认的是 OpenAI chunk。直接把上游帧透传，
// 客户端会看到 `event:output` 而解析失败 —— 表现为「有响应但没内容」。
//
// # 错误是 HTTP 200 + event:error
//
// 所以错误处理不能挂在状态码上，必须在流内识别。错误码语义：
//   1005 / 4008 / 4011 → 额度 / 套餐 / 限流，需要冷却或换号
//   4001               → 模型不可调用（function 渠道填错）
//   4027               → 消息顺序错（tool 结果没紧跟 assistant）

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"strings"
)

// openAIChunk 是最小化的 OpenAI chunk 结构，用于输出。
type openAIChunk struct {
	ID      string        `json:"id"`
	Object  string        `json:"object"`
	Created int64         `json:"created"`
	Model   string        `json:"model"`
	Choices []chunkChoice `json:"choices"`
	Usage   any           `json:"usage,omitempty"`
}

type chunkChoice struct {
	Index        int         `json:"index"`
	Delta        chunkDelta  `json:"delta"`
	FinishReason *string     `json:"finish_reason"`
}

type chunkDelta struct {
	Role             string           `json:"role,omitempty"`
	Content          string           `json:"content,omitempty"`
	ReasoningContent string           `json:"reasoning_content,omitempty"`
	ToolCalls        []chunkToolCall  `json:"tool_calls,omitempty"`
}

type chunkToolCall struct {
	Index    int             `json:"index"`
	ID       string          `json:"id,omitempty"`
	Type     string          `json:"type,omitempty"`
	Function chunkToolFunc   `json:"function"`
}

type chunkToolFunc struct {
	Name      string `json:"name,omitempty"`
	Arguments string `json:"arguments,omitempty"`
}

// convertSSE 逐帧转换。整体流式，不缓冲完整响应。
func convertSSE(src io.Reader, dst io.Writer) {
	scanner := bufio.NewScanner(src)
	scanner.Buffer(make([]byte, 0, 1<<20), 8<<20)

	const chunkID = "chatcmpl-trae"
	var created int64 = 0
	sentRole := false
	toolIndex := 0

	// dataBuf 累积多行 data:（上游会把长 JSON 断行）。
	var dataBuf strings.Builder
	eventName := ""

	emit := func(payload any) {
		raw, err := json.Marshal(payload)
		if err != nil {
			return
		}
		fmt.Fprintf(dst, "data: %s\n\n", raw)
	}

	flushFrame := func() {
		defer func() { dataBuf.Reset(); eventName = "" }()
		body := strings.TrimSpace(dataBuf.String())
		if body == "" {
			return
		}

		switch eventName {
		case "error":
			// 上游错误：转成 OpenAI error 形状，保留原始 code/msg 供上层分类。
			var e struct {
				Code    any    `json:"code"`
				Message string `json:"message"`
				Msg     string `json:"msg"`
			}
			_ = json.Unmarshal([]byte(body), &e)
			msg := firstNonEmpty(e.Msg, e.Message, body)
			code := ""
			if e.Code != nil {
				code = fmt.Sprintf("%v", e.Code)
			}
			if code != "" {
				msg = "code=" + code + " msg=" + msg
			}
			emit(map[string]any{
				"error": map[string]any{"message": msg, "type": "upstream_error"},
			})

		case "done":
			var d struct {
				FinishReason string `json:"finish_reason"`
			}
			_ = json.Unmarshal([]byte(body), &d)
			fr := firstNonEmpty(d.FinishReason, "stop")
			emit(openAIChunk{
				ID: chunkID, Object: "chat.completion.chunk", Created: created,
				Choices: []chunkChoice{{Index: 0, Delta: chunkDelta{}, FinishReason: &fr}},
			})
			fmt.Fprint(dst, "data: [DONE]\n\n")

		case "token_usage":
			// usage 单独一帧；原样透出，让上层按 OpenAI 口径解析。
			var usage any
			if err := json.Unmarshal([]byte(body), &usage); err == nil {
				emit(map[string]any{
					"id": chunkID, "object": "chat.completion.chunk", "created": created,
					"choices": []any{}, "usage": usage,
				})
			}

		case "output":
			var o struct {
				Response         string `json:"response"`
				ReasoningContent string `json:"reasoning_content"`
				ToolCalls        []struct {
					ID       string `json:"id"`
					Function struct {
						Name      string `json:"name"`
						Arguments string `json:"arguments"`
					} `json:"function"`
				} `json:"tool_calls"`
			}
			if err := json.Unmarshal([]byte(body), &o); err != nil {
				// 解析失败不能静默丢弃：客户端会看到内容凭空缺失，
				// 而没有任何错误信号。这里透出一个 error 帧，让上层能发现。
				emit(map[string]any{
					"error": map[string]any{
						"message": fmt.Sprintf("trae: 无法解析上游 output 帧: %v (片段: %s)", err, truncate(body, 200)),
						"type":    "upstream_error",
					},
				})
				return
			}

			delta := chunkDelta{}
			if !sentRole {
				delta.Role = "assistant"
				sentRole = true
			}
			delta.Content = o.Response
			delta.ReasoningContent = o.ReasoningContent

			for _, tc := range o.ToolCalls {
				delta.ToolCalls = append(delta.ToolCalls, chunkToolCall{
					Index: toolIndex,
					ID:    firstNonEmpty(tc.ID, fmt.Sprintf("call_%d", toolIndex)),
					Type:  "function",
					Function: chunkToolFunc{
						Name:      tc.Function.Name,
						Arguments: tc.Function.Arguments,
					},
				})
				toolIndex++
			}

			// 空 delta 不产生帧：上游会发大量只带 timing 的 output 帧，
			// 全部透传会让客户端收到一堆空 chunk。
			if delta.Content == "" && delta.ReasoningContent == "" && len(delta.ToolCalls) == 0 && delta.Role == "" {
				return
			}
			emit(openAIChunk{
				ID: chunkID, Object: "chat.completion.chunk", Created: created,
				Choices: []chunkChoice{{Index: 0, Delta: delta}},
			})

		default:
			// metadata / timing_cost 等：丢弃。它们不含客户端需要的内容，
			// 透传只会让下游解析器困惑。
		}
	}

	for scanner.Scan() {
		line := scanner.Text()

		switch {
		case strings.HasPrefix(line, "event:"):
			// 新事件开始：先把上一帧刷掉（上游某些帧没有空行分隔）。
			if dataBuf.Len() > 0 {
				flushFrame()
			}
			eventName = strings.TrimSpace(strings.TrimPrefix(line, "event:"))

		case strings.HasPrefix(line, "data:"):
			// 多行 data 直接拼接，**不插换行**。
			// SSE 规范允许 data: 跨行，但语义上是「原样续写」；上游在长 JSON
			// 中间断行时，插换行会把 JSON 字面量切断（字符串里的换行非法），
			// 解析必然失败 —— 表现是「有响应但没内容」。
			dataBuf.WriteString(strings.TrimSpace(strings.TrimPrefix(line, "data:")))

		case strings.TrimSpace(line) == "":
			if dataBuf.Len() > 0 {
				flushFrame()
			}

		default:
			// 兼容上游偶尔发裸 JSON（无 event/data 前缀）的情况。
			if strings.HasPrefix(strings.TrimSpace(line), "{") {
				if dataBuf.Len() > 0 {
					flushFrame()
				}
				dataBuf.WriteString(strings.TrimSpace(line))
			}
		}
	}
	// 流结束：刷掉最后一帧。
	//
	// 这里**不补发 [DONE]**：只有收到上游 done 事件时才发（见 flushFrame）。
	// 上游异常断流时补 [DONE] 会让客户端以为回答完整，从而静默截断内容 ——
	// 宁可让客户端看到流意外结束，也不要伪装成正常完成。
	if dataBuf.Len() > 0 {
		flushFrame()
	}
}

// IsRetryableError 报告错误码是否需要冷却/换号。
func IsRetryableError(msg string) bool {
	for _, code := range []string{"1005", "4008", "4011"} {
		if strings.Contains(msg, code) {
			return true
		}
	}
	return false
}

// IsModelNotCallable 报告是否为「模型不可调用」（渠道填错）。
func IsModelNotCallable(msg string) bool {
	return strings.Contains(msg, "4001")
}

// IsMessageOrderError 报告是否为消息顺序错（tool 结果未紧跟 assistant）。
func IsMessageOrderError(msg string) bool {
	return strings.Contains(msg, "4027")
}
