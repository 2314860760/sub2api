package lobsterai

// 推理客户端。
//
// # 协议
//
//	POST {server}/api/proxy/v1/chat/completions
//	Authorization: Bearer <accessToken>
//	X-LobsterAI-Client-Capabilities: kimi-k3-agentic-v1
//	X-LobsterAI-Client-Version: <version>
//
// 请求体是**标准 OpenAI**，响应也是标准 OpenAI SSE。这是五个渠道里协议最干净的。
//
// # 两个必须处理的坑（都会伪装成"正常"）
//
//  1. **上游只支持流式**：`stream:false` 会返回 500。必须强制 `stream:true`，
//     非流式需求由调用方聚合。
//  2. **错误藏在 HTTP 200 的 SSE 流首**：上游把「额度不足 code=40201」这类业务
//     错误作为 `event:error` 帧塞进 200 流里。不窥探首块的话，错误会被当成
//     正常流透传，客户端看到空内容而不是错误 —— 排障时极难定位。

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// peekSize 是首块窥探窗口。上游的错误帧总在流首且很短（实测 < 200 字节）。
const peekSize = 4 << 10

// ChatClient 是推理客户端。
type ChatClient struct {
	HTTP *http.Client
	// ClientVersion 参与 User-Agent 与能力声明。
	ClientVersion string
}

// NewChatClient 构造推理客户端。
func NewChatClient() *ChatClient {
	return &ChatClient{
		HTTP: &http.Client{
			Transport: &http.Transport{
				MaxIdleConns:        100,
				MaxIdleConnsPerHost: 20,
				IdleConnTimeout:     90 * time.Second,
			},
			// 流式响应不设总超时，生命周期交给 ctx。
			Timeout: 0,
		},
	}
}

func (c *ChatClient) version() string {
	if v := strings.TrimSpace(c.ClientVersion); v != "" {
		return v
	}
	return FallbackClientVersion
}

// chatHeaders 是对照第三方实现与 OFM 得到的稳定头集合。
func (c *ChatClient) chatHeaders(accessToken string) map[string]string {
	return map[string]string{
		"accept":        "text/event-stream, application/json",
		"authorization": "Bearer " + accessToken,
		"content-type":  "application/json",
		"user-agent":    "LobsterAI/" + c.version(),
		// 能力声明头：缺失时上游可能降级模型能力（不报错，只是行为不同）。
		"x-lobsterai-client-capabilities": ClientCapabilities,
		"x-lobsterai-client-version":      c.version(),
	}
}

// ChatStream 发一次流式推理，返回标准 OpenAI SSE。
//
// 成功后返回的 reader 已经跳过首块窥探，内容是完整的（含被 Peek 的字节）。
func (c *ChatClient) ChatStream(ctx context.Context, accessToken string, openAIBody []byte) (io.ReadCloser, int, error) {
	return c.chatStreamAt(ctx, ServerBase+ChatPath, accessToken, openAIBody)
}

// chatStreamAt 是 ChatStream 的可注入 URL 版本（测试用）。
func (c *ChatClient) chatStreamAt(ctx context.Context, url, accessToken string, openAIBody []byte) (io.ReadCloser, int, error) {
	if strings.TrimSpace(accessToken) == "" {
		return nil, 0, fmt.Errorf("lobsterai: 缺 accessToken")
	}

	body, err := prepareChatBody(openAIBody)
	if err != nil {
		return nil, 0, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, 0, err
	}
	for k, v := range c.chatHeaders(accessToken) {
		req.Header.Set(k, v)
	}

	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, 0, err
	}
	if resp.StatusCode != http.StatusOK {
		defer resp.Body.Close()
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		return nil, resp.StatusCode, fmt.Errorf("lobsterai: 上游 %d: %s", resp.StatusCode, truncate(string(raw), 300))
	}

	// 首块窥探：识别 200 流内的错误帧。
	br := bufio.NewReaderSize(resp.Body, peekSize)
	head, peekErr := br.Peek(peekSize)
	if len(head) > 0 {
		if msg := detectStreamError(head); msg != "" {
			resp.Body.Close()
			return nil, http.StatusOK, &StreamError{Message: msg}
		}
	}
	_ = peekErr // EOF 时按正常流放行，让下游处理截断

	return &peekCloser{r: br, c: resp.Body}, resp.StatusCode, nil
}

// StreamError 表示「HTTP 200 但流首是错误帧」。
//
// 单独立类型是因为它的处置与普通错误不同：额度要冷却、鉴权要刷新。
// 混成字符串会让上层只能做子串匹配。
type StreamError struct {
	Message string
}

func (e *StreamError) Error() string { return e.Message }

// detectStreamError 在首块里找错误帧，返回其消息（空 = 正常）。
func detectStreamError(head []byte) string {
	s := string(head)
	// 上游两种形态都出现过：event:error 行，或 data 里带 error 对象。
	if !strings.Contains(s, "event:error") &&
		!strings.Contains(s, `"error":{`) && !strings.Contains(s, `"error": {`) {
		return ""
	}

	// 抽出 data 行里的 message/code。
	scanner := bufio.NewScanner(bytes.NewReader(head))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if !strings.HasPrefix(line, "data:") {
			continue
		}
		payload := strings.TrimSpace(strings.TrimPrefix(line, "data:"))
		var e struct {
			Code    any    `json:"code"`
			Message string `json:"message"`
			Msg     string `json:"msg"`
			Error   any    `json:"error"`
		}
		if err := json.Unmarshal([]byte(payload), &e); err != nil {
			continue
		}
		msg := firstNonEmpty(e.Msg, e.Message)
		if m, ok := e.Error.(map[string]any); ok {
			msg = firstNonEmpty(msg, str(m, "message"))
		}
		if msg == "" {
			msg = truncate(payload, 200)
		}
		if e.Code != nil {
			return fmt.Sprintf("code=%v msg=%s", e.Code, msg)
		}
		return msg
	}
	// 有 event:error 但 data 解不出来：原样带出首块。
	return truncate(s, 200)
}

// peekCloser 把 bufio.Reader 和原始 body 的关闭句柄绑在一起。
//
// Peek 只填充缓冲、不消费字节，所以从 br 读即从流首开始 —— 不会丢数据。
type peekCloser struct {
	r io.Reader
	c io.Closer
}

func (p *peekCloser) Read(b []byte) (int, error) { return p.r.Read(b) }
func (p *peekCloser) Close() error               { return p.c.Close() }

// prepareChatBody 强制 stream:true 并归整 tool_choice。
//
// 强制流式不是可选优化：上游对 stream:false 直接 500。
func prepareChatBody(raw []byte) ([]byte, error) {
	var body map[string]any
	if err := json.Unmarshal(raw, &body); err != nil {
		return nil, fmt.Errorf("lobsterai: 解析请求体失败: %w", err)
	}
	body["stream"] = true

	// tool_choice 的空字符串 / none 会让上游 4xx，直接删掉。
	if tc, ok := body["tool_choice"]; ok {
		if s, isStr := tc.(string); isStr && (s == "" || strings.EqualFold(s, "none")) {
			delete(body, "tool_choice")
			delete(body, "tools")
		}
		if tc == nil {
			delete(body, "tool_choice")
		}
	}
	return json.Marshal(body)
}

// FetchModels 取模型目录。
func (c *ChatClient) FetchModels(ctx context.Context, accessToken string) ([]ModelEntry, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, ServerBase+ModelsPath, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("accept", "application/json")
	req.Header.Set("authorization", "Bearer "+accessToken)
	req.Header.Set("user-agent", "LobsterAI/"+c.version())

	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("lobsterai: models %d: %s", resp.StatusCode, truncate(string(raw), 200))
	}

	var env struct {
		Code int          `json:"code"`
		Data []ModelEntry `json:"data"`
	}
	if err := json.Unmarshal(raw, &env); err != nil {
		return nil, fmt.Errorf("lobsterai: 解析模型目录失败: %w", err)
	}
	return env.Data, nil
}

// ModelEntry 是目录里的一条模型。
type ModelEntry struct {
	ModelID   string `json:"modelId"`
	ModelName string `json:"modelName"`
	Provider  string `json:"provider"`
	APIFormat string `json:"apiFormat"`
}

// Credits 查积分（含活动积分，不是只算 freeCredits）。
//
// 官方用 profile-summary 的 totalCreditsRemaining；
// /api/user/quota 只显示 freeCreditsTotal，不含活动积分，会少算。
func (c *ChatClient) Credits(ctx context.Context, accessToken string) (int64, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, ServerBase+ProfilePath, nil)
	if err != nil {
		return 0, err
	}
	req.Header.Set("accept", "application/json")
	req.Header.Set("authorization", "Bearer "+accessToken)
	req.Header.Set("user-agent", "LobsterAI/"+c.version())

	resp, err := c.HTTP.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("lobsterai: profile %d: %s", resp.StatusCode, truncate(string(raw), 200))
	}

	var env struct {
		Code int `json:"code"`
		Data struct {
			TotalCreditsRemaining float64 `json:"totalCreditsRemaining"`
		} `json:"data"`
	}
	if err := json.Unmarshal(raw, &env); err != nil {
		return 0, err
	}
	if env.Code != 0 {
		return 0, fmt.Errorf("lobsterai: profile code=%d", env.Code)
	}
	v := int64(env.Data.TotalCreditsRemaining)
	if v < 0 {
		v = 0
	}
	return v, nil
}
