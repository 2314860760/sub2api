package service

// Qoder 网关服务：把 pkg/qoder 接进 sub2api 的 provider 契约。
//
// # 与 CodeBuddy 的异同
//
// 相同：上游都是流式专用、都要把 SSE 转成客户端协议、都有账号级凭据续期。
// 不同：
//   - Qoder 的响应外面套了一层信封，剥掉后才是标准 OpenAI chunk
//   - Qoder 有**模型级排队**（10605），换账号无用，只能等
//
// # 排队为什么不能交给调度器
//
// sub2api 的失败换号假设「换一个账号可能就好了」。但 Qoder 的队列是模型级的
// （同模型同队列），换账号只会把同一件事重做一遍，还平白消耗账号冷却。
// 所以排队必须在**同一账号内等待重试**，由 pkg/qoder 的 QueuePolicy 处理，
// 这里只负责把排队信息透出成可读的错误/日志。

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

	cbQoder "github.com/Wei-Shaw/sub2api/internal/pkg/qoder"
)

// ErrQoderNoCredential 表示账号缺少可用凭据。
var ErrQoderNoCredential = errors.New("qoder account has no usable credential")

// QoderGatewayService 处理 qoder 平台的转发。
type QoderGatewayService struct {
	accountRepo   AccountRepository
	tokenProvider *QoderTokenProvider
	client        *cbQoder.Client
	// deploySalt 是部署私有指纹盐，保证同一账号在不同部署下指纹不同。
	deploySalt string
}

func NewQoderGatewayService(
	accountRepo AccountRepository,
	tokenProvider *QoderTokenProvider,
	client *cbQoder.Client,
	deploySalt string,
) *QoderGatewayService {
	return &QoderGatewayService{
		accountRepo:   accountRepo,
		tokenProvider: tokenProvider,
		client:        client,
		deploySalt:    deploySalt,
	}
}

// GetTokenProvider 暴露给后台续期服务。
func (s *QoderGatewayService) GetTokenProvider() *QoderTokenProvider { return s.tokenProvider }

// ForwardAsChatCompletions 处理 /v1/chat/completions。
//
// body 是客户端的原始 OpenAI JSON；pkg/qoder 会把它翻译成上游的私有结构。
// 上游恒为流式，所以非流式客户端需要聚合。
func (s *QoderGatewayService) ForwardAsChatCompletions(
	ctx context.Context,
	c *gin.Context,
	account *Account,
	body []byte,
) (*ForwardResult, error) {
	if s.client == nil {
		return nil, s.writeError(c, http.StatusBadGateway, "api_error", "Qoder client not configured")
	}
	if account == nil || !account.IsQoder() {
		return nil, s.writeError(c, http.StatusBadRequest, "invalid_request_error", "account is not a Qoder account")
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
	modelKey := clientModel
	if mapped, matched := account.ResolveMappedModel(clientModel); matched {
		modelKey = mapped
	}

	cred, err := s.tokenProvider.GetCredential(ctx, account, s.deploySalt)
	if err != nil {
		status, code, msg := http.StatusBadGateway, "api_error", err.Error()
		if errors.Is(err, ErrQoderNoCredential) {
			status, code = http.StatusUnauthorized, "authentication_error"
			msg = "Qoder 账号缺少 security_oauth_token 或 uid，请重新导入凭据"
		}
		return nil, s.writeError(c, status, code, msg)
	}

	started := time.Now()
	rc, status, err := s.client.ChatStream(ctx, cred, body, modelKey)
	if err != nil {
		return nil, s.writeQoderError(c, status, err)
	}
	defer rc.Close()

	result := &ForwardResult{
		RequestID:     fmt.Sprintf("qd-%d", time.Now().UnixNano()),
		Model:         clientModel,
		UpstreamModel: modelKey,
		Stream:        probe.Stream,
		Duration:      time.Since(started),
	}

	if probe.Stream {
		// 原样透传；尾部截留用于提取 usage（上游只在末帧给，途中帧为 null）。
		tail := newCodeBuddyTailBuffer(32 << 10)
		if err := cbQoder.StreamAll(c.Writer, rc, tail); err != nil {
			return result, err
		}
		result.Usage = parseQoderStreamUsage(tail.Bytes())
		return result, nil
	}

	aggregated, aggErr := cbQoder.Aggregate(rc)
	if aggErr != nil {
		return nil, s.writeError(c, http.StatusBadGateway, "api_error",
			fmt.Sprintf("聚合上游响应失败: %v", aggErr))
	}
	if echo, ok := aggregated["model"].(string); ok && echo != clientModel {
		aggregated["model"] = clientModel
	}
	payload, _ := json.Marshal(aggregated)
	result.Usage = parseQoderUsage(payload)
	c.Data(http.StatusOK, "application/json", payload)
	return result, nil
}

// parseQoderUsage 把上游 OpenAI 形状 usage 映射成 ClaudeUsage。
//
// 与 CodeBuddy 相同的重复计费防护：上游的 prompt_tokens 含缓存命中量，
// 必须从中扣掉，否则同一批 token 既按 input 又按 cache read 计费。
func parseQoderUsage(payload []byte) ClaudeUsage {
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

// parseQoderStreamUsage 从流尾部找最后一帧带 usage 的 data 帧。
func parseQoderStreamUsage(tail []byte) ClaudeUsage {
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
		if usage := parseQoderUsage([]byte(payload)); usage != (ClaudeUsage{}) {
			return usage
		}
	}
	return ClaudeUsage{}
}

func (s *QoderGatewayService) writeError(c *gin.Context, status int, code, message string) error {
	c.JSON(status, gin.H{"error": gin.H{
		"message": message,
		"type":    code,
		"code":    code,
	}})
	return fmt.Errorf("qoder: %s: %s", code, message)
}

// writeQoderError 按上游错误语义给出状态码。
//
// 三类必须区分（混在一起会让调度器做出错误决定）：
//   - 排队 10605   → 503 + 可读提示，**不冷却账号**（队列是模型级的）
//   - 额度 110     → 402，需要冷却/换号
//   - 鉴权 105     → 401，需要刷新凭据
func (s *QoderGatewayService) writeQoderError(c *gin.Context, status int, err error) error {
	msg := err.Error()

	switch {
	case cbQoder.IsQueueError(msg):
		// 排队已经 pkg/qoder 内部重试过，仍失败说明队列太长；
		// 用 503 让客户端稍后重试，而不是 4xx 让客户端以为请求有问题。
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": gin.H{
			"message": "Qoder 模型当前拥塞（排队中），请稍后重试或改用其他模型",
			"type":    "upstream_queued",
			"code":    "upstream_queued",
		}})
		return err

	case strings.Contains(msg, "110") || strings.Contains(msg, "Billing"):
		c.JSON(http.StatusPaymentRequired, gin.H{"error": gin.H{
			"message": "Qoder 账号当日计费次数已用完",
			"type":    "insufficient_quota",
			"code":    "insufficient_quota",
		}})
		return err

	case strings.Contains(msg, "105") || strings.Contains(msg, "Login expired"):
		c.JSON(http.StatusUnauthorized, gin.H{"error": gin.H{
			"message": "Qoder 凭据已失效，请重新登录",
			"type":    "authentication_error",
			"code":    "authentication_error",
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
