package trae

import (
	"encoding/json"
	"strings"
	"testing"
)

// ─────────────────────────────────────────────────────────────
// SOLO body 转换：四个「做错了不报错」的点
// ─────────────────────────────────────────────────────────────

// TestConfigNameOverridesModel 钉住 model 被 config_name 覆盖。
//
// 上游用 `model` 字段承载 config_name 语义。传显示名会得到 4001 model not callable，
// 而错误信息不会告诉你「应该传 config_name」。
func TestConfigNameOverridesModel(t *testing.T) {
	body := []byte(`{"model":"DeepSeek-V4.1-Flash","messages":[{"role":"user","content":"hi"}]}`)
	payload, err := BuildSOLOBody(body, "deepseek-v4.1-flash")
	if err != nil {
		t.Fatal(err)
	}
	if payload.Model != "deepseek-v4.1-flash" {
		t.Errorf("Model 应被 configName 覆盖，得到 %q", payload.Model)
	}
	if payload.ConfigName != "deepseek-v4.1-flash" {
		t.Errorf("ConfigName = %q", payload.ConfigName)
	}
}

func TestConfigNameSuffixStrippedForModel(t *testing.T) {
	// config_name 可能带 __suffix（思考档位），base name 取 __ 之前。
	body := []byte(`{"model":"x","messages":[{"role":"user","content":"hi"}]}`)
	payload, err := BuildSOLOBody(body, "deepseek-v4.1-flash__thinking")
	if err != nil {
		t.Fatal(err)
	}
	if payload.Model != "deepseek-v4.1-flash" {
		t.Errorf("Model 应去掉 __ 后缀，得到 %q", payload.Model)
	}
	if payload.ConfigName != "deepseek-v4.1-flash__thinking" {
		t.Errorf("ConfigName 应保留完整值，得到 %q", payload.ConfigName)
	}
}

// TestToolParametersAreJSONString 钉住 parameters 必须是字符串而非对象。
//
// 用对象形式上游**静默忽略**该工具，表现是「模型不会调用工具」。
func TestToolParametersAreJSONString(t *testing.T) {
	body := []byte(`{
		"model":"deepseek-v4.1-flash",
		"messages":[{"role":"user","content":"hi"}],
		"tools":[{"type":"function","function":{
			"name":"get_weather",
			"description":"get weather",
			"parameters":{"type":"object","properties":{"city":{"type":"string"}}}
		}}]
	}`)
	payload, err := BuildSOLOBody(body, "deepseek-v4.1-flash")
	if err != nil {
		t.Fatal(err)
	}
	if len(payload.Tools) != 1 {
		t.Fatalf("tools 数应为 1，得到 %d", len(payload.Tools))
	}
	params := payload.Tools[0].Function.Parameters
	if params == "" {
		t.Fatal("parameters 为空")
	}
	// 必须是能解析成 JSON 的**字符串**，而不是被序列化成对象。
	if !strings.HasPrefix(params, "{") {
		t.Errorf("parameters 应以 { 开头，得到 %q", params)
	}
	var decoded map[string]any
	if err := json.Unmarshal([]byte(params), &decoded); err != nil {
		t.Errorf("parameters 不是合法 JSON 字符串: %v (%q)", err, params)
	}
	if decoded["type"] != "object" {
		t.Errorf("parameters 内容丢失: %v", decoded)
	}
}

// TestAssistantToolCallsBecomeFunctionCall 钉住 tool_calls → function_call。
func TestAssistantToolCallsBecomeFunctionCall(t *testing.T) {
	body := []byte(`{
		"model":"m",
		"messages":[
			{"role":"user","content":"weather?"},
			{"role":"assistant","content":null,"tool_calls":[
				{"id":"call_1","function":{"name":"get_weather","arguments":"{\"city\":\"SH\"}"}}
			]},
			{"role":"tool","tool_call_id":"call_1","content":"sunny"}
		]
	}`)
	payload, err := BuildSOLOBody(body, "m")
	if err != nil {
		t.Fatal(err)
	}
	if len(payload.Messages) != 3 {
		t.Fatalf("消息数应为 3，得到 %d", len(payload.Messages))
	}
	asst := payload.Messages[1]
	if asst.FunctionCall == nil {
		t.Fatal("assistant 应有 function_call")
	}
	if asst.FunctionCall.Name != "get_weather" {
		t.Errorf("function_call.name = %q", asst.FunctionCall.Name)
	}
	// 纯工具调用的 content 必须是 nil。
	if asst.Content != nil {
		t.Errorf("纯工具调用的 content 应为 nil，得到 %#v", asst.Content)
	}
	// tool 结果紧跟其后。
	if payload.Messages[2].Role != "tool" || payload.Messages[2].ToolCallID != "call_1" {
		t.Errorf("tool 结果消息错误: %#v", payload.Messages[2])
	}
}

// TestContentBecomesTextParts 钉住 content 转成 [{type:text}] 数组。
func TestContentBecomesTextParts(t *testing.T) {
	body := []byte(`{"model":"m","messages":[{"role":"user","content":"hello"}]}`)
	payload, err := BuildSOLOBody(body, "m")
	if err != nil {
		t.Fatal(err)
	}
	parts, ok := payload.Messages[0].Content.([]map[string]any)
	if !ok {
		t.Fatalf("content 应为 parts 数组，得到 %#v", payload.Messages[0].Content)
	}
	if len(parts) != 1 || parts[0]["type"] != "text" || parts[0]["text"] != "hello" {
		t.Errorf("parts 内容错误: %#v", parts)
	}
}

// TestMaxTokensClamped 钉住 max_tokens 钳到 64000。
func TestMaxTokensClamped(t *testing.T) {
	body := []byte(`{"model":"m","messages":[{"role":"user","content":"hi"}],"max_tokens":200000}`)
	payload, err := BuildSOLOBody(body, "m")
	if err != nil {
		t.Fatal(err)
	}
	if payload.MaxTokens == nil || *payload.MaxTokens != 64000 {
		t.Errorf("max_tokens 应钳到 64000，得到 %v", payload.MaxTokens)
	}
}

func TestMaxCompletionTokensFallback(t *testing.T) {
	body := []byte(`{"model":"m","messages":[{"role":"user","content":"hi"}],"max_completion_tokens":128}`)
	payload, err := BuildSOLOBody(body, "m")
	if err != nil {
		t.Fatal(err)
	}
	if payload.MaxTokens == nil || *payload.MaxTokens != 128 {
		t.Errorf("max_completion_tokens 应回落到 max_tokens，得到 %v", payload.MaxTokens)
	}
}

func TestStreamAlwaysTrue(t *testing.T) {
	body := []byte(`{"model":"m","messages":[{"role":"user","content":"hi"}],"stream":false}`)
	payload, err := BuildSOLOBody(body, "m")
	if err != nil {
		t.Fatal(err)
	}
	if !payload.Stream {
		t.Error("stream 必须强制为 true（上游流式专用）")
	}
}

func TestMissingModelErrors(t *testing.T) {
	body := []byte(`{"messages":[{"role":"user","content":"hi"}]}`)
	if _, err := BuildSOLOBody(body, ""); err == nil {
		t.Error("缺 model 应报错")
	}
}

// ─────────────────────────────────────────────────────────────
// SSE 转换
// ─────────────────────────────────────────────────────────────

func TestConvertSSEEmitsOpenAIChunks(t *testing.T) {
	src := strings.Join([]string{
		`event:metadata`,
		`data:{"foo":"bar"}`,
		``,
		`event:output`,
		`data:{"response":"PO"}`,
		``,
		`event:output`,
		`data:{"response":"NG"}`,
		``,
		`event:done`,
		`data:{"finish_reason":"stop"}`,
		``,
	}, "\n")

	var out strings.Builder
	convertSSE(strings.NewReader(src), &out)
	got := out.String()

	if !strings.Contains(got, `"content":"PO"`) {
		t.Errorf("缺 PO chunk: %s", got)
	}
	if !strings.Contains(got, `"content":"NG"`) {
		t.Errorf("缺 NG chunk: %s", got)
	}
	if !strings.Contains(got, `"finish_reason":"stop"`) {
		t.Errorf("缺 finish_reason: %s", got)
	}
	if !strings.Contains(got, "data: [DONE]") {
		t.Errorf("缺 [DONE]: %s", got)
	}
	// metadata 帧不应透传。
	if strings.Contains(got, `"foo":"bar"`) {
		t.Errorf("metadata 帧被透传: %s", got)
	}
}

// TestConvertSSEHandlesMultilineData 钉住多行 data 拼接。
//
// 上游在长文本时会断行；不拼接会解析失败 → 客户端看到「有响应但没内容」。
func TestConvertSSEHandlesMultilineData(t *testing.T) {
	// 上游断行发生在 JSON 结构边界（不在字符串字面量内部），
	// 所以这里把一帧拆成「前半截 + 后半截」两行 data。
	src := strings.Join([]string{
		`event:output`,
		`data:{"response":"hello",`,
		`data:"reasoning_content":""}`,
		``,
	}, "\n")
	var out strings.Builder
	convertSSE(strings.NewReader(src), &out)
	if !strings.Contains(out.String(), `"content":"hello"`) {
		t.Errorf("多行 data 未正确拼接: %s", out.String())
	}
}

// TestConvertSSEErrorFrame 钉住 event:error 转成 OpenAI error。
func TestConvertSSEErrorFrame(t *testing.T) {
	src := strings.Join([]string{
		`event:error`,
		`data:{"code":4001,"message":"model not callable"}`,
		``,
	}, "\n")
	var out strings.Builder
	convertSSE(strings.NewReader(src), &out)
	got := out.String()
	if !strings.Contains(got, `"error"`) {
		t.Errorf("错误帧未转成 error: %s", got)
	}
	if !strings.Contains(got, "4001") {
		t.Errorf("错误帧丢了 code: %s", got)
	}
}

// TestConvertSSEDropsEmptyOutput 钉住空 output 帧不产生空 chunk。
func TestConvertSSEDropsEmptyOutput(t *testing.T) {
	src := strings.Join([]string{
		`event:output`,
		`data:{"response":"","reasoning_content":""}`,
		``,
	}, "\n")
	var out strings.Builder
	convertSSE(strings.NewReader(src), &out)
	// 只允许出现带 role 的首帧，不应出现纯空 delta 的帧。
	if strings.Count(out.String(), "data:") > 1 {
		t.Errorf("空 output 产生了多余帧: %s", out.String())
	}
}

// TestConvertSSEReasoningContent 钉住 reasoning_content 透出。
func TestConvertSSEReasoningContent(t *testing.T) {
	src := strings.Join([]string{
		`event:output`,
		`data:{"reasoning_content":"thinking"}`,
		``,
	}, "\n")
	var out strings.Builder
	convertSSE(strings.NewReader(src), &out)
	if !strings.Contains(out.String(), `"reasoning_content":"thinking"`) {
		t.Errorf("reasoning_content 未透出: %s", out.String())
	}
}

// TestConvertSSENoDoneOnTruncatedStream 钉住异常断流不补 [DONE]。
//
// 补 [DONE] 会让客户端以为回答完整，从而静默截断内容。
func TestConvertSSENoDoneOnTruncatedStream(t *testing.T) {
	src := strings.Join([]string{
		`event:output`,
		`data:{"response":"partial"}`,
		``,
	}, "\n")
	var out strings.Builder
	convertSSE(strings.NewReader(src), &out)
	if strings.Contains(out.String(), "[DONE]") {
		t.Errorf("截断的流不应补 [DONE]: %s", out.String())
	}
}

// TestConvertSSEToolCalls 钉住 tool_calls 累积。
func TestConvertSSEToolCalls(t *testing.T) {
	src := strings.Join([]string{
		`event:output`,
		`data:{"tool_calls":[{"id":"call_1","function":{"name":"f","arguments":"{}"}}]}`,
		``,
	}, "\n")
	var out strings.Builder
	convertSSE(strings.NewReader(src), &out)
	got := out.String()
	if !strings.Contains(got, `"tool_calls"`) {
		t.Errorf("tool_calls 未透出: %s", got)
	}
	if !strings.Contains(got, `"call_1"`) {
		t.Errorf("tool call id 丢失: %s", got)
	}
}

// ─────────────────────────────────────────────────────────────
// 错误分类
// ─────────────────────────────────────────────────────────────

func TestErrorClassifiers(t *testing.T) {
	cases := []struct {
		msg       string
		retryable bool
		notCall   bool
		order     bool
	}{
		{"code=1005 quota exceeded", true, false, false},
		{"code=4008 plan required", true, false, false},
		{"code=4011 rate limited", true, false, false},
		{"code=4001 model not callable", false, true, false},
		{"code=4027 message order invalid", false, false, true},
		{"something else", false, false, false},
	}
	for _, c := range cases {
		if got := IsRetryableError(c.msg); got != c.retryable {
			t.Errorf("IsRetryableError(%q) = %v", c.msg, got)
		}
		if got := IsModelNotCallable(c.msg); got != c.notCall {
			t.Errorf("IsModelNotCallable(%q) = %v", c.msg, got)
		}
		if got := IsMessageOrderError(c.msg); got != c.order {
			t.Errorf("IsMessageOrderError(%q) = %v", c.msg, got)
		}
	}
}

// ─────────────────────────────────────────────────────────────
// 指纹
// ─────────────────────────────────────────────────────────────

func TestFingerprintShape(t *testing.T) {
	fp := DeriveFingerprint("uid-1", "")
	if len(fp.MachineID) != 32 || len(fp.DeviceID) != 32 {
		t.Errorf("指纹应 hex32: machine=%q device=%q", fp.MachineID, fp.DeviceID)
	}
	if fp.MachineID == fp.DeviceID {
		t.Error("MachineID 与 DeviceID 不应相同（会触发关联检查）")
	}
}

func TestFingerprintStableAndIsolated(t *testing.T) {
	a := DeriveFingerprint("uid-a", "")
	if a != DeriveFingerprint("uid-a", "") {
		t.Error("同 uid 应稳定")
	}
	if a.MachineID == DeriveFingerprint("uid-b", "").MachineID {
		t.Error("不同 uid 不应相同")
	}
	if a.MachineID == DeriveFingerprint("uid-a", "salt").MachineID {
		t.Error("加盐后应变化")
	}
}

func TestNormalizeHex32(t *testing.T) {
	// 带连字符的 UUID → hex32
	got := NormalizeHex32("6932b9c9-0c03-41d6-9a05-d91f13225f8d")
	if len(got) != 32 {
		t.Errorf("长度应为 32，得到 %d: %q", len(got), got)
	}
	for _, r := range got {
		if !strings.ContainsRune("0123456789abcdef", r) {
			t.Fatalf("非十六进制字符 %q in %q", r, got)
		}
	}
	// 已经是 hex32 时原样返回
	already := "0123456789abcdef0123456789abcdef"
	if NormalizeHex32(already) != already {
		t.Error("合法 hex32 应原样返回")
	}
	// 太短则补齐
	if len(NormalizeHex32("abc")) != 32 {
		t.Error("短输入应补齐到 32")
	}
}
