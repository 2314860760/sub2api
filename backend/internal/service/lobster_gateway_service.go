package service

// LobsterAI 网关服务：把 pkg/lobsterai 接进 sub2api 的 provider 契约。
//
// # 三类错误的处置差异
//
// 官方把业务错误放 HTTP 200 的响应体/流里（code != 0）：
//
//	40201 等额度类   → 402，冷却换号
//	40100 / 40101    → 401，refreshToken 已废，需重新登录
//	流内 event:error → 按消息判断
//
// 三者混在一起会让调度器做出错误决定（比如对"需重新登录"反复换号重试）。

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/tidwall/gjson"

	cbLobster "github.com/Wei-Shaw/sub2api/internal/pkg/lobsterai"
)

// ErrLobsterNoCredential 表示账号缺少可用凭据。
var ErrLobsterNoCredential = errors.New("lobsterai account has no usable credential")

// lobsterTerminalCodes 是官方定义的"refreshToken 已废"错误码。
// 官方 authSessionManager.ts 的 TERMINAL_REFRESH_ERROR_CODES = {40100, 40101}。
var lobsterTerminalCodes = []string{"40100", "40101"}

// LobsterGatewayService 处理 lobsterai 平台的转发。
type LobsterGatewayService struct {
	accountRepo   AccountRepository
	tokenProvider *LobsterTokenProvider
	chat          *cbLobster.ChatClient
	auth          *cbLobster.Client
	clientVersion string
}

func NewLobsterGatewayService(
	accountRepo AccountRepository,
	tokenProvider *LobsterTokenProvider,
	chat *cbLobster.ChatClient,
	auth *cbLobster.Client,
	clientVersion string,
) *LobsterGatewayService {
	return &LobsterGatewayService{
		accountRepo:   accountRepo,
		tokenProvider: tokenProvider,
		chat:          chat,
		auth:          auth,
		clientVersion: clientVersion,
	}
}

func (s *LobsterGatewayService) GetTokenProvider() *LobsterTokenProvider { return s.tokenProvider }

// ForwardAsChatCompletions 处理 /v1/chat/completions。
func (s *LobsterGatewayService) ForwardAsChatCompletions(
	ctx context.Context,
	c *gin.Context,
	account *Account,
	body []byte,
) (*ForwardResult, error) {
	if s.chat == nil {
		return nil, s.writeError(c, http.StatusBadGateway, "api_error", "LobsterAI client not configured")
	}
	if account == nil || !account.IsLobsterAI() {
		return nil, s.writeError(c, http.StatusBadRequest, "invalid_request_error", "account is not a LobsterAI account")
	}

	var probe struct {
		Model  string `json:"model"`
		Stream bool   `json:"stream"`
	}
	if err := json.Unmarshal(body, &probe); err != nil {
		return nil, s.writeError(c, http.StatusBadRequest, "invalid_request_error", "Failed to parse request body")
	}
	if strings.TrimSpace(probe.Model) == "" {
		return nil, s.writeError(c, http.StatusBadRequest, "invalid_request_error", "Missing model")
	}

	clientModel := probe.Model
	upstreamModel := clientModel
	if mapped, matched := account.ResolveMappedModel(clientModel); matched {
		upstreamModel = mapped
	}

	token, err := s.tokenProvider.AccessToken(ctx, account)
	if err != nil {
		status, code, msg := http.StatusBadGateway, "api_error", err.Error()
		if errors.Is(err, ErrLobsterNoCredential) {
			status, code = http.StatusUnauthorized, "authentication_error"
			msg = "LobsterAI 账号未登录：缺少 access_token，请先完成登录"
		}
		return nil, s.writeError(c, status, code, msg)
	}

	// 模型映射：只在必要时改写 body 的 model 字段。
	if upstreamModel != clientModel {
		body = replaceJSONModelField(body, upstreamModel)
	}

	started := time.Now()
	rc, status, err := s.chat.ChatStream(ctx, token, body)
	if err != nil {
		return nil, s.writeLobsterError(c, status, err)
	}
	defer rc.Close()

	result := &ForwardResult{
		RequestID:     fmt.Sprintf("lb-%d", time.Now().UnixNano()),
		Model:         clientModel,
		UpstreamModel: upstreamModel,
		Stream:        probe.Stream,
		Duration:      time.Since(started),
	}

	if probe.Stream {
		tail := newCodeBuddyTailBuffer(32 << 10)
		if err := cbLobster.StreamAll(c.Writer, rc, tail); err != nil {
			return result, err
		}
		result.Usage = parseOpenAIStreamUsage(tail.Bytes())
		return result, nil
	}

	aggregated, aggErr := cbLobster.Aggregate(rc)
	if aggErr != nil {
		return nil, s.writeError(c, http.StatusBadGateway, "api_error",
			fmt.Sprintf("聚合上游响应失败: %v", aggErr))
	}
	if echo, ok := aggregated["model"].(string); ok && echo != clientModel {
		aggregated["model"] = clientModel
	}
	payload, _ := json.Marshal(aggregated)
	result.Usage = parseOpenAIUsage(payload)
	c.Data(http.StatusOK, "application/json", payload)
	return result, nil
}

// parseOpenAIUsage 映射 usage，并做重复计费防护。
//
// 上游 prompt_tokens 含缓存命中量，必须扣掉，否则同一批 token 既按 input
// 又按 cache read 计费。
func parseOpenAIUsage(payload []byte) ClaudeUsage {
	usage := gjson.GetBytes(payload, "usage")
	if !usage.Exists() || !usage.IsObject() {
		return ClaudeUsage{}
	}
	parsed, ok := openAIUsageFromGJSON(usage)
	if !ok {
		return ClaudeUsage{}
	}
	fresh := parsed.InputTokens - parsed.CacheReadInputTokens
	if fresh < 0 {
		fresh = 0
	}
	return ClaudeUsage{
		InputTokens:              fresh,
		OutputTokens:             parsed.OutputTokens,
		CacheCreationInputTokens: parsed.CacheCreationInputTokens,
		CacheReadInputTokens:     parsed.CacheReadInputTokens,
	}
}

func parseOpenAIStreamUsage(tail []byte) ClaudeUsage {
	lines := strings.Split(string(tail), "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		line := strings.TrimSpace(lines[i])
		if !strings.HasPrefix(line, "data:") {
			continue
		}
		payload := strings.TrimSpace(strings.TrimPrefix(line, "data:"))
		if payload == "" || payload == "[DONE]" {
			continue
		}
		if !gjson.Get(payload, "usage").Exists() {
			continue
		}
		if usage := parseOpenAIUsage([]byte(payload)); usage != (ClaudeUsage{}) {
			return usage
		}
	}
	return ClaudeUsage{}
}

func (s *LobsterGatewayService) writeError(c *gin.Context, status int, code, message string) error {
	c.JSON(status, gin.H{"error": gin.H{
		"message": message,
		"type":    code,
		"code":    code,
	}})
	return fmt.Errorf("lobsterai: %s: %s", code, message)
}

// writeLobsterError 按官方错误码语义分流。
func (s *LobsterGatewayService) writeLobsterError(c *gin.Context, status int, err error) error {
	msg := err.Error()

	for _, code := range lobsterTerminalCodes {
		if strings.Contains(msg, code) {
			// 这两个码意味着 refreshToken 已废 —— 换号或重试都无用，必须重新登录。
			c.JSON(http.StatusUnauthorized, gin.H{"error": gin.H{
				"message": "LobsterAI 凭据已失效，需要重新登录",
				"type":    "authentication_error",
				"code":    "lobster_reauth_required",
			}})
			return err
		}
	}

	// 额度类（40201 等）：需要冷却换号。
	lower := strings.ToLower(msg)
	if strings.Contains(lower, "credit") || strings.Contains(lower, "insufficient") ||
		strings.Contains(msg, "积分") || strings.Contains(msg, "40201") {
		c.JSON(http.StatusPaymentRequired, gin.H{"error": gin.H{
			"message": "LobsterAI 积分不足",
			"type":    "insufficient_quota",
			"code":    "insufficient_quota",
		}})
		return err
	}

	outStatus := status
	if outStatus < 400 {
		outStatus = http.StatusBadGateway
	}
	c.JSON(outStatus, gin.H{"error": gin.H{
		"message": msg,
		"type":    "upstream_error",
		"code":    "upstream_error",
	}})
	return err
}

// replaceJSONModelField 只改顶层 model，其余字节语义不变。
func replaceJSONModelField(body []byte, model string) []byte {
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(body, &obj); err != nil {
		return body
	}
	encoded, err := json.Marshal(model)
	if err != nil {
		return body
	}
	obj["model"] = encoded
	out, err := json.Marshal(obj)
	if err != nil {
		return body
	}
	return out
}
