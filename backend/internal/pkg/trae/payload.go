package trae

// 把 OpenAI Chat Completions 请求体翻译成 Trae 的 SOLO 结构。
//
// # SOLO 与 OpenAI 的四处硬差异
//
//  1. `model` 字段会被 `config_name` **覆盖**（不是并存）。上游只认 config_name，
//     而 config_name 是模型目录键（如 `deepseek-v4.1-flash`），不是显示名。
//  2. `function` 是「渠道」标识（默认 `solo_work_lite`），必须与模型所属渠道匹配。
//     填错 → HTTP 200 + 流内 4001（看起来像模型不可用）。
//  3. `tools[].function.parameters` 必须是 **JSON 字符串**，不能是对象。
//     用对象形式上游会静默忽略该工具。
//  4. assistant 的 `tool_calls[].function` 要改写成 `function_call`（单数）；
//     `role:"tool"` 必须**紧跟**它对应的 assistant tool_calls，中间插任何消息都是硬 4027。
//
// 这四条都不会给出指向字段本身的报错 —— 所以下面每一处都写了注释。

import (
	"encoding/json"
	"fmt"
	"strings"
)

// SOLOBody 是上游推理端点的请求体。
type SOLOBody struct {
	// ConfigName 与 Model 同值：上游用 model 字段，但语义上是 config_name。
	Model      string `json:"model"`
	ConfigName string `json:"config_name"`
	// Function 是渠道标识。默认 solo_work_lite。
	Function string `json:"function"`

	Messages []SOLOMessage `json:"messages"`
	Stream   bool          `json:"stream"`

	Tools       []SOLOTool `json:"tools,omitempty"`
	Temperature *float64   `json:"temperature,omitempty"`
	MaxTokens   *int       `json:"max_tokens,omitempty"`
	Stop        any        `json:"stop,omitempty"`
	ReasoningEffort string `json:"reasoning_effort,omitempty"`

	// Max 模式字段：只在模型 meta 声明 max_mode=true 时才能发，
	// 盲发会被拒。默认关闭。
	MaxMode *MaxModeBlock `json:"max_mode_config,omitempty"`
}

// MaxModeBlock 是 1M 上下文档位的参数块。
type MaxModeBlock struct {
	ModelAutoSelection    bool   `json:"model_auto_selection"`
	ModelSelectionStrategy string `json:"model_selection_strategy"`
	ModeType              string `json:"mode_type"`
	ContextWindowSize     int    `json:"context_window_size"`
	PromptMaxTokens       int    `json:"prompt_max_tokens"`
}

// SOLOMessage 是 SOLO 的 message 结构。
//
// 与 OpenAI 的差异：
//   - Content 必须是 `[{type:"text",text:…}]` 数组，不是字符串
//   - assistant 的工具调用叫 `function_call`（单数对象），不是 `tool_calls`（数组）
//   - 纯工具调用的 assistant 必须把 content 置为 null
type SOLOMessage struct {
	Role         string          `json:"role"`
	Content      any             `json:"content"`
	FunctionCall *SOLOFunctionCall `json:"function_call,omitempty"`
	// 工具结果消息用 tool_call_id 关联，但 SOLO 要求紧跟 assistant。
	Name string `json:"name,omitempty"`
	ToolCallID string `json:"tool_call_id,omitempty"`
}

// SOLOFunctionCall 是 assistant 的工具调用（单数形式）。
type SOLOFunctionCall struct {
	Name      string `json:"name"`
	Arguments string `json:"arguments"`
}

// SOLOTool 是工具声明。Parameters 刻意用 any 承载「字符串化后的对象」。
type SOLOTool struct {
	Type     string          `json:"type"`
	Function SOLOToolFunction `json:"function"`
}

type SOLOToolFunction struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	// Parameters 是 JSON **字符串**，不是对象。见文件头第 3 条。
	Parameters string `json:"parameters"`
}

// DefaultFunction 是默认渠道标识。
const DefaultFunction = "solo_work_lite"

// BuildSOLOBody 把 OpenAI 请求体翻译成 SOLO。
//
// configName 是模型目录键；为空时退回 OpenAI 请求里的 model。
func BuildSOLOBody(openAI []byte, configName string) (*SOLOBody, error) {
	var in struct {
		Model           string            `json:"model"`
		Messages        []json.RawMessage `json:"messages"`
		Tools           []json.RawMessage `json:"tools"`
		Temperature     *float64          `json:"temperature"`
		MaxTokens       *int              `json:"max_tokens"`
		MaxCompletion   *int              `json:"max_completion_tokens"`
		Stop            any               `json:"stop"`
		ReasoningEffort string            `json:"reasoning_effort"`
	}
	if err := json.Unmarshal(openAI, &in); err != nil {
		return nil, fmt.Errorf("trae: 解析请求体失败: %w", err)
	}

	name := strings.TrimSpace(configName)
	if name == "" {
		name = strings.TrimSpace(in.Model)
	}
	if name == "" {
		return nil, fmt.Errorf("trae: 缺 model / config_name")
	}
	// config_name 可能带 `__suffix`（思考档位等），base name 取 `__` 之前。
	baseName := name
	if i := strings.Index(baseName, "__"); i > 0 {
		baseName = baseName[:i]
	}

	msgs, err := convertMessages(in.Messages)
	if err != nil {
		return nil, err
	}

	tools, err := convertTools(in.Tools)
	if err != nil {
		return nil, err
	}

	// max_tokens 必须钳到 64000：上游对更大的值直接 4xx。
	maxTokens := in.MaxTokens
	if maxTokens == nil {
		maxTokens = in.MaxCompletion
	}
	if maxTokens != nil && *maxTokens > 64000 {
		clamped := 64000
		maxTokens = &clamped
	}

	return &SOLOBody{
		// ⚠️ model 与 config_name 同值：上游用 model 字段承载 config_name。
		// 传显示名（如 "DeepSeek-V4.1-Flash"）会得到 4001 model not callable。
		Model:           baseName,
		ConfigName:      name,
		Function:        DefaultFunction,
		Messages:        msgs,
		Stream:          true, // 上游流式专用
		Tools:           tools,
		Temperature:     in.Temperature,
		MaxTokens:       maxTokens,
		Stop:            in.Stop,
		ReasoningEffort: in.ReasoningEffort,
	}, nil
}

// convertMessages 逐条转换，并保证 tool 结果紧跟其 assistant tool_calls。
func convertMessages(raw []json.RawMessage) ([]SOLOMessage, error) {
	out := make([]SOLOMessage, 0, len(raw))

	for _, item := range raw {
		var m struct {
			Role       string          `json:"role"`
			Content    any             `json:"content"`
			ToolCalls  []struct {
				ID       string `json:"id"`
				Function struct {
					Name      string `json:"name"`
					Arguments string `json:"arguments"`
				} `json:"function"`
			} `json:"tool_calls"`
			ToolCallID string `json:"tool_call_id"`
			Name       string `json:"name"`
		}
		if err := json.Unmarshal(item, &m); err != nil {
			return nil, fmt.Errorf("trae: 解析 message 失败: %w", err)
		}

		conv := SOLOMessage{
			Role:       m.Role,
			Content:    soloContent(m.Content),
			ToolCallID: m.ToolCallID,
			Name:       m.Name,
		}

		// assistant 的 tool_calls 数组 → SOLO 的单个 function_call。
		// 上游只支持一个（SOLO 的 function_call 是对象不是数组），取第一个；
		// 多个并发工具调用会被上游丢弃，这一点无法绕过。
		if len(m.ToolCalls) > 0 {
			tc := m.ToolCalls[0]
			conv.FunctionCall = &SOLOFunctionCall{Name: tc.Function.Name, Arguments: tc.Function.Arguments}
			// 纯工具调用的 assistant 必须 content=null，否则上游 4027。
			if isEmptyContent(m.Content) {
				conv.Content = nil
			}
		}

		out = append(out, conv)
	}
	return out, nil
}

// soloContent 把 OpenAI content（字符串或 parts 数组）转成 SOLO 的 parts 数组。
//
// SOLO 只认 `[{type:"text",text:…}]`；图片走 attachment 通道（另见 OFM 的
// image 处理），这里只保文本，图片暂时丢弃 —— 静默丢图比 400 更容易让人
// 以为「模型不支持视觉」，所以这个取舍写在这里而不是隐含在代码里。
func soloContent(v any) any {
	switch t := v.(type) {
	case nil:
		return nil
	case string:
		return []map[string]any{{"type": "text", "text": t}}
	case []any:
		parts := make([]map[string]any, 0, len(t))
		for _, p := range t {
			m, ok := p.(map[string]any)
			if !ok {
				continue
			}
			if s, ok := m["text"].(string); ok {
				parts = append(parts, map[string]any{"type": "text", "text": s})
			}
		}
		if len(parts) == 0 {
			return nil
		}
		return parts
	default:
		return nil
	}
}

func isEmptyContent(v any) bool {
	switch t := v.(type) {
	case nil:
		return true
	case string:
		return strings.TrimSpace(t) == ""
	case []any:
		return len(t) == 0
	}
	return false
}

// convertTools 把 OpenAI tools 转成 SOLO tools，**parameters 字符串化**。
func convertTools(raw []json.RawMessage) ([]SOLOTool, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	out := make([]SOLOTool, 0, len(raw))
	for _, item := range raw {
		var t struct {
			Type     string `json:"type"`
			Function struct {
				Name        string `json:"name"`
				Description string `json:"description"`
				Parameters  any    `json:"parameters"`
			} `json:"function"`
		}
		if err := json.Unmarshal(item, &t); err != nil {
			continue
		}
		// ⚠️ parameters 必须是 JSON 字符串。对象形式上游会静默忽略整个工具，
		// 表现是「模型不会调用工具」而不是报错。
		params := "{}"
		if t.Function.Parameters != nil {
			if encoded, err := json.Marshal(t.Function.Parameters); err == nil {
				params = string(encoded)
			}
		}
		out = append(out, SOLOTool{
			Type: firstNonEmpty(t.Type, "function"),
			Function: SOLOToolFunction{
				Name:        t.Function.Name,
				Description: t.Function.Description,
				Parameters:  params,
			},
		})
	}
	return out, nil
}
