package service

// Trae 网关服务：把 pkg/trae 接进 sub2api 的 provider 契约。
//
// # 与 qoder/codebuddy 的差异
//
// Trae 的错误是 **HTTP 200 + event:error**，所以错误不能挂在状态码上判断。
// pkg/trae 的 convertSSE 会把 error 帧转成 OpenAI error 形状，这里再按 code 分流：
//
//	1005 / 4008 / 4011 → 额度/套餐/限流 → 冷却换号
//	4001               → 渠道填错（function 与模型不匹配）
//	4027               → 消息顺序错（tool 结果未紧跟 assistant）
//
// 后两者是**请求构造错误**，换号重试毫无意义，必须让客户端看到原因。

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

	cbTrae "github.com/Wei-Shaw/sub2api/internal/pkg/trae"
)

// ErrTraeNoCredential 表示账号缺少可用凭据。
var ErrTraeNoCredential = errors.New("trae account has no usable credential")

// TraeGatewayService 处理 trae 平台的转发。
type TraeGatewayService struct {
	accountRepo   AccountRepository
	tokenProvider *TraeTokenProvider
	client        *cbTrae.Client
	deploySalt    string
}

func NewTraeGatewayService(
	accountRepo AccountRepository,
	tokenProvider *TraeTokenProvider,
	client *cbTrae.Client,
	deploySalt string,
) *TraeGatewayService {
	return &TraeGatewayService{
		accountRepo:   accountRepo,
		tokenProvider: tokenProvider,
		client:        client,
		deploySalt:    deploySalt,
	}
}

func (s *TraeGatewayService) GetTokenProvider() *TraeTokenProvider { return s.tokenProvider }

// ForwardAsChatCompletions 处理 /v1/chat/completions。
func (s *TraeGatewayService) ForwardAsChatCompletions(
	ctx context.Context,
	c *gin.Context,
	account *Account,
	body []byte,
) (*ForwardResult, error) {
	if s.client == nil {
		return nil, s.writeError(c, http.StatusBadGateway, "api_error", "Trae client not configured")
	}
	if account == nil || !account.IsTrae() {
		return nil, s.writeError(c, http.StatusBadRequest, "invalid_request_error", "account is not a Trae account")
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
	configName := clientModel
	if mapped, matched := account.ResolveMappedModel(clientModel); matched {
		configName = mapped
	}

	cred, err := s.tokenProvider.GetCredential(ctx, account, s.deploySalt)
	if err != nil {
		status, code, msg := http.StatusBadGateway, "api_error", err.Error()
		if errors.Is(err, ErrTraeNoCredential) {
			status, code = http.StatusUnauthorized, "authentication_error"
			msg = "Trae 账号缺少 access_token，请重新导入凭据"
		}
		return nil, s.writeError(c, status, code, msg)
	}

	started := time.Now()
	rc, status, err := s.client.ChatStream(ctx, cred, body, configName)
	if err != nil {
		return nil, s.writeTraeError(c, status, err)
	}
	defer rc.Close()

	result := &ForwardResult{
		RequestID:     fmt.Sprintf("tr-%d", time.Now().UnixNano()),
		Model:         clientModel,
		UpstreamModel: configName,
		Stream:        probe.Stream,
		Duration:      time.Since(started),
	}

	if probe.Stream {
		tail := newCodeBuddyTailBuffer(32 << 10)
		// 流式透传。注意上游的错误帧已经在 convertSSE 里转成 OpenAI error 形状，
		// 会随流一起发给客户端 —— 这是与 qoder 的差别：qoder 的错误在建流前就能
		// 探测到，trae 的部分错误只能在流内出现。
		if err := cbTrae.StreamAll(c.Writer, rc, tail); err != nil {
			return result, err
		}
		result.Usage = parseTraeStreamUsage(tail.Bytes())
		return result, nil
	}

	aggregated, aggErr := cbTrae.Aggregate(rc)
	if aggErr != nil {
		return nil, s.writeError(c, http.StatusBadGateway, "api_error",
			fmt.Sprintf("聚合上游响应失败: %v", aggErr))
	}
	if echo, ok := aggregated["model"].(string); ok && echo != clientModel {
		aggregated["model"] = clientModel
	}
	payload, _ := json.Marshal(aggregated)
	result.Usage = parseTraeUsage(payload)
	c.Data(http.StatusOK, "application/json", payload)
	return result, nil
}

// parseTraeUsage 映射 usage。
//
// Trae 的 token_usage 帧字段：prompt_tokens / completion_tokens /
// reasoning_tokens / cache_read_input_tokens。与 CodeBuddy/Qoder 相同的
// 重复计费防护：从 input 里扣掉缓存命中量。
func parseTraeUsage(payload []byte) ClaudeUsage {
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

func parseTraeStreamUsage(tail []byte) ClaudeUsage {
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
		if usage := parseTraeUsage([]byte(payload)); usage != (ClaudeUsage{}) {
			return usage
		}
	}
	return ClaudeUsage{}
}

func (s *TraeGatewayService) writeError(c *gin.Context, status int, code, message string) error {
	c.JSON(status, gin.H{"error": gin.H{
		"message": message,
		"type":    code,
		"code":    code,
	}})
	return fmt.Errorf("trae: %s: %s", code, message)
}

// writeTraeError 按 Trae 的错误码分流。
func (s *TraeGatewayService) writeTraeError(c *gin.Context, status int, err error) error {
	msg := err.Error()

	switch {
	case cbTrae.IsModelNotCallable(msg):
		// 4001 = function 渠道与模型不匹配。这是**配置错误**，
		// 换号重试无用，必须让管理员看到。
		c.JSON(http.StatusBadRequest, gin.H{"error": gin.H{
			"message": "Trae 模型不可调用：function 渠道与模型不匹配（检查模型映射）",
			"type":    "invalid_request_error",
			"code":    "trae_model_not_callable",
		}})
		return err

	case cbTrae.IsMessageOrderError(msg):
		// 4027 = tool 结果未紧跟 assistant。
		c.JSON(http.StatusBadRequest, gin.H{"error": gin.H{
			"message": "Trae 消息顺序非法：工具结果必须紧跟对应的 assistant 工具调用",
			"type":    "invalid_request_error",
			"code":    "trae_message_order",
		}})
		return err

	case cbTrae.IsRetryableError(msg):
		c.JSON(http.StatusTooManyRequests, gin.H{"error": gin.H{
			"message": "Trae 账号额度/套餐受限，已切换账号重试",
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
