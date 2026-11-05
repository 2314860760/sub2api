package service

// CodeBuddy 网关服务：把移植进来的 upstream.Client 接进 sub2api 的 provider 契约。
//
// ## 与 Antigravity 的关键结构差异
//
// Antigravity 把 Claude Messages 转成 Gemini 再转回来；CodeBuddy 的上游**原生就是
// OpenAI Chat Completions**（实测见 docs/codebuddy-platform-plan.md 第九节），
// 所以 /v1/chat/completions 这条路径是零协议转换的直通。
// Claude Messages 与 Responses 的入口留给后续阶段，它们靠现有的
// OpenAI↔Anthropic 转换层复用，不在本文件里重造。
//
// ## 上游只走流式
//
// 上游忽略 stream:false，永远回 SSE（实测确认）。所以：
//   - 客户端要流式 → 原样透传帧（顺带剥掉上游的 `: heartbeat` 注释帧由 sse 层处理）
//   - 客户端要非流式 → 用 upstream.Aggregate 聚合成一个 chat.completion 对象
// 不存在"上游有非流式端点"这条捷径，别按那个假设写代码。

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/tidwall/gjson"

	cbUpstream "github.com/Wei-Shaw/sub2api/internal/pkg/codebuddy/upstream"
)

// ErrCodeBuddyNoCredential 表示账号缺少可用凭据（没有 access_token）。
// 这不是上游故障，是账号配置问题——按 401 类处理，不去冷却上游。
var ErrCodeBuddyNoCredential = errors.New("codebuddy account has no access token")

// CodeBuddyGatewayService 处理 codebuddy 平台的转发。
type CodeBuddyGatewayService struct {
	accountRepo   AccountRepository
	tokenProvider *CodeBuddyTokenProvider
	client        *cbUpstream.Client
}

func NewCodeBuddyGatewayService(
	accountRepo AccountRepository,
	tokenProvider *CodeBuddyTokenProvider,
	client *cbUpstream.Client,
) *CodeBuddyGatewayService {
	return &CodeBuddyGatewayService{
		accountRepo:   accountRepo,
		tokenProvider: tokenProvider,
		client:        client,
	}
}

// GetTokenProvider 暴露给后台续期服务。
func (s *CodeBuddyGatewayService) GetTokenProvider() *CodeBuddyTokenProvider {
	return s.tokenProvider
}

// ForwardAsChatCompletions 处理 /v1/chat/completions。
//
// body 是客户端的原始 OpenAI Chat Completions JSON——不做协议转换，
// 只把它交给移植包，那里的 prepareBody 会补齐上游要求的字段
// （stream:true、stream_options.include_usage、thinking、prompt_cache_key、
// 每消息的 agent/conversationRequestId 等，见方案文档第九节）。
func (s *CodeBuddyGatewayService) ForwardAsChatCompletions(
	ctx context.Context,
	c *gin.Context,
	account *Account,
	body []byte,
) (*ForwardResult, error) {
	if s.client == nil {
		return nil, s.writeError(c, http.StatusBadGateway, "api_error", "CodeBuddy client not configured")
	}
	if account == nil || !account.IsCodeBuddy() {
		return nil, s.writeError(c, http.StatusBadRequest, "invalid_request_error", "account is not a CodeBuddy account")
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

	// 模型映射：客户端名 → 上游裸名。ResolveMappedModel 未命中时原样返回请求名，
	// 所以不需要先 GetMappedModel 再判断——那样只是多查一次同一张表。
	clientModel := probe.Model
	upstreamModel := clientModel
	if mapped, matched := account.ResolveMappedModel(clientModel); matched {
		upstreamModel = mapped
	}
	if upstreamModel != clientModel {
		body = replaceJSONModel(body, upstreamModel)
	}

	auth, err := s.tokenProvider.GetAccessToken(ctx, account)
	if err != nil {
		// 缺凭据是账号问题，不当上游故障：明确告知需要重新登录。
		status := http.StatusBadGateway
		code := "api_error"
		message := err.Error()
		if errors.Is(err, ErrCodeBuddyNoCredential) {
			status, code = http.StatusUnauthorized, "authentication_error"
			message = "CodeBuddy 账号缺少 access_token，请重新登录后导入凭据"
		}
		return nil, s.writeError(c, status, code, message)
	}

	started := time.Now()
	var timing cbUpstream.ChatTiming
	rc, status, respBody, ferr := s.client.ChatStreamContext(
		ctx, auth, body, c.ClientIP(),
		cbUpstream.ChatMeta{ConversationRequestID: buildCodeBuddyRequestID()},
		&timing,
	)
	if ferr != nil {
		return nil, s.writeUpstreamError(c, status, respBody, ferr)
	}
	defer rc.Close()

	result := &ForwardResult{
		RequestID:     buildCodeBuddyRequestID(),
		Model:         clientModel,
		UpstreamModel: upstreamModel,
		Stream:        probe.Stream,
		Duration:      time.Since(started),
	}

	if probe.Stream {
		// 原样透传，同时在旁路截留尾部字节用于提取 usage。
		//
		// 为什么是"尾部"而不是"全量"：上游只在**最后一帧**给 usage（途中帧为 null，
		// 实测确认）。全量缓存会在 7 万 token 的长对话上白占内存，而尾部 32 KiB
		// 足够覆盖最后一帧及其前若干帧。
		tail := newCodeBuddyTailBuffer(32 << 10)
		if err := cbUpstream.Stream(c.Writer, io.TeeReader(rc, tail)); err != nil {
			// 头已发出，只能在日志侧留痕；不回写错误帧（客户端会看到半截流）。
			return result, err
		}
		result.Usage = parseCodeBuddyStreamUsage(tail.Bytes())
		return result, nil
	}

	// 非流式：上游只给 SSE，这里聚合。
	aggregated, aggErr := cbUpstream.Aggregate(rc)
	if aggErr != nil {
		return nil, s.writeError(c, http.StatusBadGateway, "api_error",
			fmt.Sprintf("聚合上游响应失败: %v", aggErr))
	}

	// 模型名回写客户端原发名：严格校验响应 model 的客户端不会当场报错。
	if echo, ok := aggregated["model"].(string); ok && echo != clientModel {
		aggregated["model"] = clientModel
	}
	payload, _ := json.Marshal(aggregated)
	result.Usage = parseCodeBuddyUsage(payload)

	c.Data(http.StatusOK, "application/json", payload)
	return result, nil
}

// collectUsageFromBuffered 已由尾部缓冲方案取代（见 ForwardAsChatCompletions 流式分支）。

// codeBuddyTailBuffer 是只保留最后 N 字节的 io.Writer。
//
// 用于流式路径提取 usage：上游的 usage 在最后一帧，前面几十万字节没必要留。
// 实现刻意用"满了就整体左移"而不是环形索引——帧边界可能被切断，
// 拿到一段连续尾部字节比拿到按环序排列的片段更容易解析。
type codeBuddyTailBuffer struct {
	buf  []byte
	size int
}

func newCodeBuddyTailBuffer(size int) *codeBuddyTailBuffer {
	if size <= 0 {
		size = 32 << 10
	}
	return &codeBuddyTailBuffer{size: size}
}

func (t *codeBuddyTailBuffer) Write(p []byte) (int, error) {
	t.buf = append(t.buf, p...)
	if len(t.buf) > t.size {
		t.buf = t.buf[len(t.buf)-t.size:]
	}
	return len(p), nil
}

func (t *codeBuddyTailBuffer) Bytes() []byte { return t.buf }

// parseCodeBuddyStreamUsage 从尾部字节里找出最后一个带 usage 的 data 帧。
//
// 从后往前找：usage 一定在最后，倒序扫描通常几次就命中，
// 而顺序扫描要走过整个缓冲区里的每一帧。
func parseCodeBuddyStreamUsage(tail []byte) ClaudeUsage {
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
		// 这一帧可能被尾部截断（JSON 不完整），解析失败就继续往前找。
		if usage := parseCodeBuddyUsage([]byte(payload)); usage != (ClaudeUsage{}) {
			return usage
		}
	}
	return ClaudeUsage{}
}

// parseCodeBuddyUsage 把上游的 OpenAI 形状 usage 映射成 ClaudeUsage。
//
// 复用同包的 openAIUsageFromGJSON（它已处理 prompt_tokens/completion_tokens
// 与 cached_tokens 的全部拼写差异），避免在 CodeBuddy 这里再写一份解析。
//
// 注意上游把 prompt_tokens 定义为**含缓存**的总量，而 cache_read_input_tokens
// 是其中命中部分；直接搬运会导致 input 与 cache read 重复计费，
// 所以这里从 input 里扣掉命中量——与 Anthropic 口径对齐。
func parseCodeBuddyUsage(payload []byte) ClaudeUsage {
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

// replaceJSONModel 只改顶层 model 字段，其余字节保持原样。
// 用 sjson 会重排整个对象，导致出站报文与客户端发的不同——排障时对不上。
func replaceJSONModel(body []byte, model string) []byte {
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

// codeBuddyRequestSeq 让请求 ID 在并发下唯一。
//
// 只用时间戳不够：Windows 时钟粒度约 15ms，同一刻到达的并发请求会拿到完全相同
// 的 ID（单测 TestBuildCodeBuddyRequestIDUnique 就是这么发现的）。ID 撞车会污染
// 日志关联，还可能让上游把两个无关对话当成同一个会话。
var codeBuddyRequestSeq atomic.Uint64

func buildCodeBuddyRequestID() string {
	return fmt.Sprintf("cb-%d-%d", time.Now().UnixNano(), codeBuddyRequestSeq.Add(1))
}

// writeError 写 OpenAI 形状的错误体。与网关其它平台的错误信封保持一致。
func (s *CodeBuddyGatewayService) writeError(c *gin.Context, status int, code, message string) error {
	c.JSON(status, gin.H{"error": gin.H{
		"message": message,
		"type":    code,
		"code":    code,
	}})
	return fmt.Errorf("codebuddy: %s: %s", code, message)
}

// writeUpstreamError 把移植包的错误分类映射成客户端可见的状态码。
//
// 分类来自 upstream.Classify：内容拦截/参数错误属于请求问题（4xx 原样透传），
// 限流/服务端故障属于上游问题（5xx，交给调度层换号）。
func (s *CodeBuddyGatewayService) writeUpstreamError(c *gin.Context, status int, respBody []byte, err error) error {
	var uerr *cbUpstream.Error
	if errors.As(err, &uerr) {
		outStatus := status
		if outStatus < 400 {
			outStatus = http.StatusBadGateway
		}
		message := strings.TrimSpace(uerr.Msg)
		if message == "" {
			message = strings.TrimSpace(string(respBody))
		}
		if message == "" {
			message = uerr.Kind.String()
		}
		c.JSON(outStatus, gin.H{"error": gin.H{
			"message": message,
			"type":    uerr.Kind.String(),
			"code":    uerr.Kind.String(),
		}})
		return err
	}
	// 传输层错误（非 *upstream.Error）：当作上游不可用。
	return s.writeError(c, http.StatusBadGateway, "api_error",
		fmt.Sprintf("CodeBuddy 上游请求失败: %v", err))
}
