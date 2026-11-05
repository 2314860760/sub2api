package qoder

// 把 OpenAI Chat Completions 请求体翻译成 Qoder 的私有推理结构。
//
// # 为什么不能直接转发
//
// 上游要的是 agent 形态的 payload：chat_context（当前输入）、messages（历史）、
// system（独立数组）、model_config（模型元数据）、business（路由标识），
// 而不是 OpenAI 的单一 messages 数组。缺字段的表现很隐蔽：
//
//   - 缺 business.type=agent → 路由到坏节点，回 `[FAIL]node:… Execution failed`
//   - 缺顶层 tools → 模型把工具调用当 XML 写进正文
//   - 缺 chat_context → 上游认为无输入
//
// # 结构来源
//
// 字段清单来自 OFM 的 buildQoderInferPayload 实测（其注释明确记了
// 「序列化丢结构」导致的三次线上故障），并与社区 qoder2api 的实现交叉核对。

import (
	"encoding/json"
	"fmt"
	"strings"
)

// InferPayload 是上游推理端点的请求体。
//
// 字段名必须与上游一致（snake_case + 部分 camelCase 混用），这是上游的定义，
// 不是我们的风格选择 —— 改名会得到 400，且错误信息指不到具体字段。
type InferPayload struct {
	RequestID    string `json:"request_id"`
	RequestSetID string `json:"request_set_id"`
	ChatRecordID string `json:"chat_record_id"`
	SessionID    string `json:"session_id"`

	Stream   bool   `json:"stream"`
	ChatTask string `json:"chat_task"`

	ChatContext ChatContext `json:"chat_context"`

	IsReply  bool   `json:"is_reply"`
	IsRetry  bool   `json:"is_retry"`
	Source   int    `json:"source"`
	Version  string `json:"version"`

	AgentID string `json:"agent_id"`
	TaskID  string `json:"task_id"`

	SessionType    string `json:"session_type"`
	AliyunUserType string `json:"aliyun_user_type"`

	ModelConfig ModelConfig `json:"model_config"`
	CustomModel any         `json:"custom_model"`

	System  []ContentPart `json:"system"`
	Messages []Message    `json:"messages"`
	Tools   []any         `json:"tools"`

	Parameters map[string]any `json:"parameters"`

	// Business 必须非 nil：{type:"agent"}。
	// 缺了会被路由到坏节点，症状是 `Execution failed` 而不是参数错误。
	Business *Business `json:"business,omitempty"`
}

// ChatContext 是"当前这一轮输入"。
type ChatContext struct {
	Text             string         `json:"text"`
	Features         []any          `json:"features"`
	Extra            ChatExtra      `json:"extra"`
	ChatPrompt       string         `json:"chatPrompt"`
	ImageURLs        any            `json:"imageUrls"`
}

type ChatExtra struct {
	Context         []any       `json:"context"`
	ModelConfig     ModelKeyRef `json:"modelConfig"`
	OriginalContent string      `json:"originalContent"`
}

type ModelKeyRef struct {
	Key         string `json:"key"`
	IsReasoning bool   `json:"is_reasoning"`
}

// ModelConfig 是模型元数据。多数字段上游并不强校验，但 key/format 必须对。
type ModelConfig struct {
	Key            string `json:"key"`
	DisplayName    string `json:"display_name"`
	Model          string `json:"model"`
	Format         string `json:"format"`
	IsVL           bool   `json:"is_vl"`
	IsReasoning    bool   `json:"is_reasoning"`
	APIKey         string `json:"api_key"`
	URL            string `json:"url"`
	Source         string `json:"source"`
	MaxInputTokens int    `json:"max_input_tokens"`
}

// ContentPart 是 system 数组的元素。
type ContentPart struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

// Message 是历史消息。role 与 content 为最小集合；
// tool_calls / tool_call_id 在有工具时透传。
type Message struct {
	Role       string `json:"role"`
	Content    any    `json:"content"`
	ToolCalls  any    `json:"tool_calls,omitempty"`
	ToolCallID string `json:"tool_call_id,omitempty"`
	Name       string `json:"name,omitempty"`
}

type Business struct {
	Type string `json:"type"`
}

// BuildInferPayload 把 OpenAI 请求体翻译成上游 payload。
//
// modelKey 是上游目录键（如 qfmodel），由调用方做模型映射后传入 ——
// 上游只认目录键，不认对外显示名。
func BuildInferPayload(openAI []byte, modelKey string) (*InferPayload, error) {
	var in struct {
		Model       string           `json:"model"`
		Messages    []Message        `json:"messages"`
		Tools       []any            `json:"tools"`
		Temperature *float64         `json:"temperature"`
		TopP        *float64         `json:"top_p"`
		MaxTokens   *int             `json:"max_tokens"`
		Stop        any              `json:"stop"`
	}
	if err := json.Unmarshal(openAI, &in); err != nil {
		return nil, fmt.Errorf("qoder: 解析请求体失败: %w", err)
	}
	if strings.TrimSpace(modelKey) == "" {
		modelKey = in.Model
	}
	if strings.TrimSpace(modelKey) == "" {
		return nil, fmt.Errorf("qoder: 缺 model")
	}

	// system 单独抽取：上游把 system 放在顶层数组，不从 messages 里认。
	var system []ContentPart
	rest := make([]Message, 0, len(in.Messages))
	for _, m := range in.Messages {
		if m.Role == "system" || m.Role == "developer" {
			if text := flattenContent(m.Content); text != "" {
				system = append(system, ContentPart{Type: "text", Text: text})
			}
			continue
		}
		rest = append(rest, m)
	}
	if system == nil {
		system = []ContentPart{}
	}
	if in.Tools == nil {
		in.Tools = []any{}
	}

	requestID, err := newUUID()
	if err != nil {
		return nil, err
	}
	sessionID, err := newUUID()
	if err != nil {
		return nil, err
	}

	// chat_context.text 取最后一条 user 消息 —— 上游用它作为"本轮输入"，
	// 历史走 messages。取错（例如拼接全部）会让模型重复理解上下文。
	current := ""
	for i := len(rest) - 1; i >= 0; i-- {
		if rest[i].Role == "user" {
			current = flattenContent(rest[i].Content)
			break
		}
	}

	params := map[string]any{}
	if in.Temperature != nil {
		params["temperature"] = *in.Temperature
	}
	if in.TopP != nil {
		params["top_p"] = *in.TopP
	}
	if in.MaxTokens != nil {
		params["max_tokens"] = *in.MaxTokens
	}
	if in.Stop != nil {
		params["stop"] = in.Stop
	}

	return &InferPayload{
		RequestID:    requestID,
		RequestSetID: requestID,
		ChatRecordID: requestID,
		SessionID:    sessionID,

		Stream:   true, // 上游流式专用
		ChatTask: "FREE_INPUT",

		ChatContext: ChatContext{
			Text:     current,
			Features: []any{},
			Extra: ChatExtra{
				Context:         []any{},
				ModelConfig:     ModelKeyRef{Key: modelKey},
				OriginalContent: current,
			},
			ChatPrompt: "",
			ImageURLs:  nil,
		},

		IsReply: true,
		IsRetry: false,
		Source:  1,
		Version: "3",

		AgentID: "agent_common",
		TaskID:  "common",

		SessionType:    "qodercli",
		AliyunUserType: "",

		ModelConfig: ModelConfig{
			Key:     modelKey,
			Model:   "",
			Format:  "openai",
			APIKey:  "",
			URL:     "",
			Source:  "system",
		},
		CustomModel: nil,

		System:   system,
		Messages: rest,
		Tools:    in.Tools,

		Parameters: params,

		// 必须带，见结构体注释。
		Business: &Business{Type: "agent"},
	}, nil
}

// flattenContent 把 OpenAI 的 content（字符串或 parts 数组）压成纯文本。
//
// 只在 system 与 chat_context.text 上用。上游这两处要纯字符串，
// 传 parts 数组会被当成空输入。
func flattenContent(v any) string {
	switch t := v.(type) {
	case nil:
		return ""
	case string:
		return t
	case []any:
		var b strings.Builder
		for _, part := range t {
			m, ok := part.(map[string]any)
			if !ok {
				continue
			}
			// {type:"text", text:"…"}
			if s, ok := m["text"].(string); ok {
				b.WriteString(s)
				continue
			}
			// {type:"image_url", …}：文本压平里忽略图片，上游另有 imageUrls 字段承载。
		}
		return b.String()
	default:
		return ""
	}
}
