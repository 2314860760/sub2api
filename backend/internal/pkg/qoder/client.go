package qoder

// Qoder 推理端点的客户端：payload 构造、请求发送、SSE 信封剥离。
//
// # 端点
//
// 上游真实推理端点不是 OpenAI 兼容的 /model/v1/chat/completions（CN 实测 503），
// 而是：
//
//	POST {base}/algo/api/v2/service/pro/sse/agent_chat_generation
//	     ?FetchKeys=llm_model_result&AgentId=agent_common&Encode=1
//
// base：国际 api2.qoder.sh / 国内 gateway.qoder.com.cn。
//
// # 响应形状
//
// SSE，但每帧外面套一层信封（内层不加密）：
//
//	data:{"headers":{…},"body":"{\"choices\":[…]}","statusCodeValue":200,"statusCode":"OK"}
//
// 剥掉信封后就是**标准 OpenAI chunk**，所以 sub2api 的 OpenAI 网关能直接吃。
// 心跳帧（body 为 null / {} / 空）要丢掉，错误帧要保留 code 供上层分类。
//
// # 两个静默失败点
//
//  1. `business: {type:"agent"}` 必须带。缺了会被路由到坏节点，返回一段
//     `[FAIL]node:… msg:Execution failed` —— 看起来像上游故障，实际是少个字段。
//  2. 顶层 `tools` 必须真的携带函数 schema。缺了模型会把工具调用当 XML 写进正文。

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	// InferPath 是推理端点路径（不含 /algo 前缀的语义见 PathSig）。
	InferPath = "/algo/api/v2/service/pro/sse/agent_chat_generation"
	// InferQuery 是推理端点固定查询参数。
	InferQuery = "FetchKeys=llm_model_result&AgentId=agent_common&Encode=1"

	// BaseGlobal 国际化站点；BaseCN 国内站点。
	BaseGlobal = "https://api2.qoder.sh"
	BaseCN     = "https://gateway.qoder.com.cn"

	// oldProtocol* 是未配置真实设备指纹时使用的旧协议标识。
	// 只能拿到较少模型；新版（clienttype=10 / version=1.1.69）才会多出
	// Sonus / Cantus / Fast 三档。
	oldClientType = "5"
	oldVersion    = "1.0.10"
	oldProduct    = "ide"
	oldUserAgent  = "Go-http-client/2.0"

	newClientType = "10"
	newUserAgent  = "undici"
)

// Credential 是发起一次推理所需的账号材料。
type Credential struct {
	// SecurityOauthToken 与 UID 一起参与 info 加密与 Cosy-User。
	SecurityOauthToken string
	UID                string
	Name               string
	AID                string
	YxUID              string
	OrganizationID     string
	OrganizationName   string
	UserType           string
	RefreshToken       string

	// Fingerprint 由 uid 派生（见 DeriveFingerprint）。空值时用 UID 现推。
	Fingerprint Fingerprint

	// Realm "cn" / "global"，决定 base URL。
	Realm string

	// ModernProtocol 为 true 时使用新版协议标识（clienttype=10 / version=1.1.69）
	// 与 app 身份。配置了真实指纹的账号才应打开。
	ModernProtocol bool
	// CosyVersion 覆盖默认协议版本（空则用 DefaultCosyVersion）。
	CosyVersion string
}

// BaseURL 返回该账号应访问的站点根。
func (c *Credential) BaseURL() string {
	if strings.EqualFold(c.Realm, "cn") {
		return BaseCN
	}
	return BaseGlobal
}

// Client 发往 Qoder 上游的 HTTP 客户端。
type Client struct {
	HTTP *http.Client
	// DeploySalt 是部署私有指纹盐；为空则退化为纯 uid 派生（与社区实现兼容）。
	DeploySalt string
	// Queue 控制模型拥塞时的等待重试；零值用 DefaultQueuePolicy。
	Queue QueuePolicy
}

// New 构造带合理连接池的客户端。
func New() *Client {
	return &Client{
		HTTP: &http.Client{
			Transport: &http.Transport{
				MaxIdleConns:        100,
				MaxIdleConnsPerHost: 20,
				IdleConnTimeout:     90 * time.Second,
			},
			// 不设总超时：流式响应可能很长，生命周期交给 ctx。
			Timeout: 0,
		},
	}
}

// InferURL 拼出完整推理 URL。
func (c *Credential) InferURL() string {
	return c.BaseURL() + InferPath + "?" + InferQuery
}

// PathSig 返回参与签名的路径（去掉 /algo 前缀）。
//
// 上游签名时用的是**不含 /algo 的路径**。用完整 path 会得到
// 长度正确的错签名，服务端回 101 Signature invalid。
func PathSig(fullURL string) (string, error) {
	u, err := url.Parse(fullURL)
	if err != nil {
		return "", err
	}
	p := u.Path
	if strings.HasPrefix(p, "/algo") {
		p = strings.TrimPrefix(p, "/algo")
	}
	return p, nil
}

// buildHeaders 生成全部 18–20 个上游请求头并完成签名。
//
// 返回值用 map 而非有序切片：上游没有可观察到的头顺序要求
// （OFM 走 wasm 时头来自 JS Map，顺序本身不确定），Go 的 http.Header
// 传输顺序不影响语义。
func (c *Client) buildHeaders(ctx context.Context, cred *Credential, pathSig, body, accept string) (map[string]string, error) {
	sess, err := NewSession(Identity{
		Name:               cred.Name,
		AID:                cred.AID,
		UID:                cred.UID,
		YxUID:              cred.YxUID,
		OrganizationID:     cred.OrganizationID,
		OrganizationName:   cred.OrganizationName,
		UserType:           cred.UserType,
		SecurityOauthToken: cred.SecurityOauthToken,
		RefreshToken:       cred.RefreshToken,
	})
	if err != nil {
		return nil, err
	}

	cosyVersion := cred.CosyVersion
	if cosyVersion == "" {
		cosyVersion = DefaultCosyVersion
	}
	// ⚠️ payload 里的 cosyVersion 必须与 cosy-version **头**一致。
	// 两者不一致时服务端不看签名、直接回 FORBIDDEN —— 一个完全不指向字段的报错，
	// 极易误判成 token 失效。旧协议两处都是 1.0.10，新协议两处都是 1.1.69。
	protocolVersion := oldVersion
	if cred.ModernProtocol {
		protocolVersion = cosyVersion
	}
	payloadB64, err := sess.PayloadB64(protocolVersion)
	if err != nil {
		return nil, err
	}

	// ⚠️ cosy-date 是 **unix 秒的十进制字符串**，不是 RFC1123。
	// 它与 body、path 一起参与 MD5 签名，所以必须与签名时用的值完全相同。
	date := fmt.Sprintf("%d", time.Now().Unix())
	sig := SignRequest(payloadB64, sess.CosyKey, date, body, pathSig)

	fp := cred.Fingerprint
	if fp.MachineID == "" {
		fp = DeriveFingerprint(cred.UID, c.DeploySalt)
	}

	clientType, version, product, userAgent, scene := oldClientType, oldVersion, oldProduct, oldUserAgent, "assistant"
	if cred.ModernProtocol {
		clientType, version, product, userAgent, scene = newClientType, protocolVersion, "app", newUserAgent, "app"
	}

	return map[string]string{
		"accept":                accept,
		"authorization":         Bearer(payloadB64, sig),
		"cache-control":         "no-cache",
		"content-type":          "application/json",
		"cosy-business-product": product,
		"cosy-business-type":    "agent",
		"cosy-clienttype":       clientType,
		"cosy-data-policy":      "agree",
		"cosy-date":             date,
		"cosy-key":              sess.CosyKey,
		"cosy-machineid":        fp.MachineID,
		"cosy-machinetoken":     fp.MachineToken,
		"cosy-machinetype":      fp.MachineType,
		"cosy-scene":            scene,
		"cosy-user":             cred.UID,
		"cosy-version":          version,
		"login-version":         "v2",
		"user-agent":            userAgent,
	}, nil
}

// QueuePolicy 控制模型拥塞时的等待重试。
//
// 上游热门模型（qfmodel 免费档、Sonus）会返回 10605 isQueued 并给出
// retryAfterSeconds。这类错误**换账号无用**——队列是模型级的；参考实现的做法是
// 在原账号上等待后重试，与「失败换号」是两套逻辑。
//
// 零值表示用 DefaultQueuePolicy。
type QueuePolicy struct {
	// MaxRetries 最多重试次数（不含首次）。0 用默认 3。
	MaxRetries int
	// MaxWait 单次等待上限，防止上游给出离谱的 retryAfter。
	MaxWait time.Duration
	// OnQueue 每次排队时回调（便于上层记日志/给客户端提示）。
	OnQueue func(attempt int, info QueueInfo)
}

// QueueInfo 是上游排队响应里的可解析字段。
type QueueInfo struct {
	QueueCount        int
	RetryAfterSeconds int
	ModelKey          string
	SubCode           string
}

// DefaultQueuePolicy 与参考实现对齐：3 次重试、单次最多等 60s。
func DefaultQueuePolicy() QueuePolicy {
	return QueuePolicy{MaxRetries: 3, MaxWait: 60 * time.Second}
}

// parseQueueInfo 从错误文案里挖出排队参数。它刻意用宽松解析：
// 上游把 JSON 嵌在 message 字符串里并做了转义，严格反序列化会失败。
func parseQueueInfo(msg string) QueueInfo {
	var info QueueInfo
	info.QueueCount = looseInt(msg, `"queueCount":`)
	info.RetryAfterSeconds = looseInt(msg, `"retryAfterSeconds":`)
	if i := strings.Index(msg, `"modelKey":"`); i >= 0 {
		rest := msg[i+len(`"modelKey":"`):]
		if j := strings.IndexByte(rest, '"'); j > 0 {
			info.ModelKey = rest[:j]
		}
	}
	if i := strings.Index(msg, `"subCode":"`); i >= 0 {
		rest := msg[i+len(`"subCode":"`):]
		if k := strings.IndexByte(rest, '"'); k > 0 {
			info.SubCode = rest[:k]
		}
	}
	return info
}

func looseInt(s, key string) int {
	i := strings.Index(s, key)
	if i < 0 {
		return 0
	}
	rest := s[i+len(key):]
	n := 0
	seen := false
	for _, r := range rest {
		if r >= '0' && r <= '9' {
			n = n*10 + int(r-'0')
			seen = true
			continue
		}
		if seen {
			break
		}
		if r == ' ' {
			continue
		}
		return 0
	}
	return n
}

// ChatStream 发一次流式推理，返回**已剥掉信封**的标准 OpenAI SSE。
//
// 调用方拿到的是可以直接转给客户端的字节流；错误帧会被保留并按 OpenAI
// error 形状重写，便于上层统一分类。
//
// 上游是流式专用的（stream 恒为 true），非流式需求由调用方聚合。
//
// 排队（10605）会按 retryAfterSeconds 在原账号上等待重试，见 QueuePolicy。
func (c *Client) ChatStream(ctx context.Context, cred *Credential, openAIBody []byte, modelKey string) (io.ReadCloser, int, error) {
	policy := c.Queue
	if policy.MaxRetries == 0 {
		policy = DefaultQueuePolicy()
	}
	if policy.MaxWait <= 0 {
		policy.MaxWait = 60 * time.Second
	}

	for attempt := 0; ; attempt++ {
		rc, status, err := c.chatStreamOnce(ctx, cred, openAIBody, modelKey)
		if err == nil {
			return rc, status, nil
		}
		if !IsQueueError(err.Error()) || attempt >= policy.MaxRetries {
			return rc, status, err
		}

		info := parseQueueInfo(err.Error())
		wait := time.Duration(info.RetryAfterSeconds) * time.Second
		if wait <= 0 {
			wait = 15 * time.Second
		}
		if wait > policy.MaxWait {
			wait = policy.MaxWait
		}
		if policy.OnQueue != nil {
			policy.OnQueue(attempt+1, info)
		}
		select {
		case <-ctx.Done():
			return nil, status, ctx.Err()
		case <-time.After(wait):
		}
	}
}

// chatStreamOnce 是单次尝试，不含排队重试。
func (c *Client) chatStreamOnce(ctx context.Context, cred *Credential, openAIBody []byte, modelKey string) (io.ReadCloser, int, error) {
	if cred == nil || strings.TrimSpace(cred.SecurityOauthToken) == "" {
		return nil, 0, fmt.Errorf("qoder: 缺 security_oauth_token")
	}
	if strings.TrimSpace(cred.UID) == "" {
		// uid 参与 info 加密与 Cosy-User；缺了签名会被拒（Signature invalid 101）。
		return nil, 0, fmt.Errorf("qoder: 缺 uid（签名必需）")
	}

	payload, err := BuildInferPayload(openAIBody, modelKey)
	if err != nil {
		return nil, 0, err
	}
	plain, err := json.Marshal(payload)
	if err != nil {
		return nil, 0, err
	}
	body, err := Encode(plain)
	if err != nil {
		return nil, 0, err
	}

	fullURL := cred.InferURL()
	pathSig, err := PathSig(fullURL)
	if err != nil {
		return nil, 0, err
	}
	headers, err := c.buildHeaders(ctx, cred, pathSig, body, "text/event-stream")
	if err != nil {
		return nil, 0, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, fullURL, bytes.NewReader([]byte(body)))
	if err != nil {
		return nil, 0, err
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, 0, err
	}
	if resp.StatusCode != http.StatusOK {
		defer resp.Body.Close()
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		return nil, resp.StatusCode, fmt.Errorf("qoder: 上游 %d: %s", resp.StatusCode, truncate(string(raw), 300))
	}

	// 建流成功后上游仍可能立刻投递错误帧（排队 10605 / 额度 110 / 鉴权 105）。
	// 这些错误**在 HTTP 状态上是 200**，只有读首块才看得见 —— 所以先窥探首块：
	// 是错误帧就关流并把它变成 error 返回，让上面的排队重试能生效。
	// 不窥探的话，排队会被当成"正常流里的一个 error 帧"直接透给客户端，
	// 用户看到一次失败，而实际只要等 30 秒就能成功。
	br := bufio.NewReaderSize(resp.Body, peekSize)
	head, peekErr := br.Peek(peekSize)
	if len(head) > 0 {
		if msg := firstFrameError(head); msg != "" {
			resp.Body.Close()
			return nil, http.StatusOK, &QueueOrUpstreamError{Message: msg}
		}
	}
	_ = peekErr // EOF 时仍按正常流放行，让下游自行处理截断

	pr, pw := io.Pipe()
	go func() {
		defer resp.Body.Close()
		defer pw.Close()
		stripEnvelope(br, pw)
	}()
	return pr, resp.StatusCode, nil
}

// peekSize 是首块窥探窗口。错误帧总在流首且很短（实测 < 1 KB），
// 而正常首帧通常也要几百字节，4 KB 足够判定。
const peekSize = 4 << 10

// QueueOrUpstreamError 表示「HTTP 200 但流首是错误帧」。
//
// 单独立一个类型是因为它的处置与普通错误不同：排队要等，鉴权要刷新，
// 额度要冷却。混成一个 error 字符串会让上层只能靠子串匹配。
type QueueOrUpstreamError struct {
	Message string
}

func (e *QueueOrUpstreamError) Error() string { return e.Message }

// firstFrameError 在首块里找错误帧，返回其消息（空 = 首块正常）。
func firstFrameError(head []byte) string {
	scanner := bufio.NewScanner(bytes.NewReader(head))
	scanner.Buffer(make([]byte, 0, peekSize), peekSize)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if !strings.HasPrefix(line, "data:") {
			continue
		}
		payload := strings.TrimSpace(strings.TrimPrefix(line, "data:"))
		if payload == "" || payload == "[DONE]" {
			continue
		}
		var env struct {
			Body            *string         `json:"body"`
			StatusCodeValue int             `json:"statusCodeValue"`
			StatusCode      string          `json:"statusCode"`
			Code            json.RawMessage `json:"code"`
			Msg             string          `json:"msg"`
			Message         string          `json:"message"`
		}
		if err := json.Unmarshal([]byte(payload), &env); err != nil {
			continue
		}
		return envelopeError(&env)
	}
	return ""
}

// stripEnvelope 把上游的「信封 + 内层 OpenAI chunk」逐帧改写成标准 SSE。
//
// 逐帧处理而非整体缓冲：Qoder 的首字延迟可能到秒级，整体缓冲会把流式体验
// 变成「等完才出字」。
func stripEnvelope(src io.Reader, dst io.Writer) {
	scanner := bufio.NewScanner(src)
	scanner.Buffer(make([]byte, 0, 1<<20), 4<<20)

	for scanner.Scan() {
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)

		// 非 data 行原样透传：`: heartbeat` 注释帧、空行分隔符都要保留，
		// 否则客户端会误判流已结束。
		if !strings.HasPrefix(trimmed, "data:") {
			fmt.Fprintf(dst, "%s\n", line)
			continue
		}

		payload := strings.TrimSpace(strings.TrimPrefix(trimmed, "data:"))
		if payload == "" {
			fmt.Fprint(dst, "\n")
			continue
		}
		if payload == "[DONE]" {
			fmt.Fprint(dst, "data: [DONE]\n\n")
			continue
		}

		var env struct {
			Body            *string         `json:"body"`
			StatusCodeValue int             `json:"statusCodeValue"`
			StatusCode      string          `json:"statusCode"`
			Code            json.RawMessage `json:"code"`
			Msg             string          `json:"msg"`
			Message         string          `json:"message"`
		}
		if err := json.Unmarshal([]byte(payload), &env); err != nil {
			// 不是信封（可能上游直接给了裸 OpenAI chunk）：原样透传。
			fmt.Fprintf(dst, "data: %s\n\n", payload)
			continue
		}

		// 错误帧：上游把业务错误塞在信封里（如 10605 排队、110 额度）。
		// 转成 OpenAI error 形状，让上层能统一分类重试/换号。
		if errText := envelopeError(&env); errText != "" {
			out, _ := json.Marshal(map[string]any{
				"error": map[string]any{"message": errText, "type": "upstream_error"},
			})
			fmt.Fprintf(dst, "data: %s\n\n", out)
			continue
		}

		// 心跳帧：body 为空/null/{} —— 丢弃，不产生空 chunk。
		if env.Body == nil {
			continue
		}
		inner := strings.TrimSpace(*env.Body)
		if inner == "" || inner == "null" || inner == "{}" {
			continue
		}

		fmt.Fprintf(dst, "data: %s\n\n", inner)
	}
}

// envelopeError 判定信封是否为错误帧，返回要展示的消息（空 = 不是错误）。
//
// ⚠️ 真实的错误文案在 **body** 里，不在 msg/message 字段。取错字段会把
// 「403 排队中，前方 14623 人」压成一句干巴巴的 `FORBIDDEN` —— 于是看起来像
// 权限问题，实际是拥塞，而且**排队是可以在同账号上等出来的**。
// 这个误判让整个排查方向跑偏过一轮，所以先解 body。
func envelopeError(env *struct {
	Body            *string         `json:"body"`
	StatusCodeValue int             `json:"statusCodeValue"`
	StatusCode      string          `json:"statusCode"`
	Code            json.RawMessage `json:"code"`
	Msg             string          `json:"msg"`
	Message         string          `json:"message"`
}) string {
	bodyMsg, bodyCode := bodyError(env.Body)

	if len(env.Code) > 0 {
		raw := strings.Trim(string(env.Code), `"`)
		if raw != "" && raw != "0" && raw != "null" {
			return fmt.Sprintf("code=%s msg=%s", raw, firstNonEmpty(env.Msg, env.Message, bodyMsg))
		}
	}
	if bodyCode != "" {
		return fmt.Sprintf("code=%s msg=%s", bodyCode, bodyMsg)
	}
	if env.StatusCodeValue >= 400 {
		if msg := firstNonEmpty(env.Msg, env.Message, bodyMsg); msg != "" {
			return msg
		}
		return env.StatusCode
	}
	if bodyMsg != "" {
		return bodyMsg
	}
	return ""
}

// bodyError 从信封 body 里解出错误码与文案。
// body 可能是 JSON 字符串，也可能是纯文本，两种都认。
func bodyError(body *string) (msg, code string) {
	if body == nil {
		return "", ""
	}
	raw := strings.TrimSpace(*body)
	if raw == "" || raw == "null" || raw == "{}" {
		return "", ""
	}
	var e struct {
		Code    json.RawMessage `json:"code"`
		Message string          `json:"message"`
		Msg     string          `json:"msg"`
		Error   string          `json:"error"`
	}
	if err := json.Unmarshal([]byte(raw), &e); err == nil {
		code = strings.Trim(string(e.Code), `"`)
		if code == "0" || code == "null" {
			code = ""
		}
		msg = firstNonEmpty(e.Message, e.Msg, e.Error)
		if msg != "" || code != "" {
			return msg, code
		}
	}
	// 纯文本错误体：只在明显像错误时透出，避免把正常 chunk 当错误。
	if strings.Contains(raw, "error") || strings.Contains(raw, "exceeded") ||
		strings.Contains(raw, "队列") || strings.Contains(raw, "排队") {
		return raw, ""
	}
	return "", ""
}

// queueMarkers 是上游「模型拥塞、可等待重试」的文案特征。
//
// 这类错误**不能换号**：队列是模型级的，换账号还是同一队列。参考实现的做法是
// 在原账号上按 retryAfter 等待重试，与换号逻辑分开。
var queueMarkers = []string{"排队", "队列", "isQueued", "使用人数较多", "retryAfter"}

// IsQueueError 报告错误是否为可等待的模型拥塞。
func IsQueueError(msg string) bool {
	if msg == "" {
		return false
	}
	// 10605 是上游的排队码。
	if strings.Contains(msg, "10605") {
		return true
	}
	for _, m := range queueMarkers {
		if strings.Contains(msg, m) {
			return true
		}
	}
	return false
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if s := strings.TrimSpace(v); s != "" {
			return s
		}
	}
	return ""
}

func truncate(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

// ─────────────────────────────────────────────────────────────
// 模型目录
// ─────────────────────────────────────────────────────────────

// ModelListPath 是模型目录端点。它**不消耗推理计费**，所以是验证签名是否
// 正确的最佳探针：签名错会 401/403，签名对则返回几十 KB 的 JSON。
//
// 这条路径的价值在于把两件事分开：
//   - 签名/加密层是否正确（本方法能否拿到目录）
//   - 账号推理权益是否存在（infer 是否被 110/排队拒绝）
//
// 混淆这两件事会浪费大量时间：推理被拒时第一反应总是怀疑签名。
const ModelListPath = "/algo/api/v2/model/list"

// ModelEntry 是目录里的一条模型描述（只取 sub2api 需要的字段）。
type ModelEntry struct {
	Key            string  `json:"key"`
	DisplayName    string  `json:"display_name"`
	Status         string  `json:"status"`
	Format         string  `json:"format"`
	IsVL           bool    `json:"is_vl"`
	IsReasoning    bool    `json:"is_reasoning"`
	PriceFactor    float64 `json:"price_factor"`
	MaxInputTokens int     `json:"max_input_tokens"`
	IsFree         bool    `json:"is_free"`
}

// FetchModels 取模型目录。用于验证签名 + 同步模型清单。
func (c *Client) FetchModels(ctx context.Context, cred *Credential) ([]ModelEntry, error) {
	fullURL := cred.BaseURL() + ModelListPath + "?Encode=1"
	pathSig, err := PathSig(fullURL)
	if err != nil {
		return nil, err
	}
	// GET 的 body 参与签名时为空串（与上游一致）。
	headers, err := c.buildHeaders(ctx, cred, pathSig, "", "application/json")
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, fullURL, nil)
	if err != nil {
		return nil, err
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("qoder: model/list %d: %s", resp.StatusCode, truncate(string(raw), 300))
	}

	// 上游把目录包在 {"chat":[…], "completions":[…]?} 里。
	var doc struct {
		Chat []ModelEntry `json:"chat"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("qoder: 解析模型目录失败: %w (前 200 字节: %s)", err, truncate(string(raw), 200))
	}
	return doc.Chat, nil
}
// ─────────────────────────────────────────────────────────────
// 下游出口
// ─────────────────────────────────────────────────────────────

// StreamAll 把已剥信封的 SSE 原样写给客户端，同时把内容镜像进 sink。
//
// sink 用于提取 usage（上游只在末帧给，故调用方通常传一个尾部缓冲）。
// 这里不做任何格式改写：pkg/qoder 的 stripEnvelope 已经产出标准 OpenAI chunk，
// 再包一层只会让客户端看到非标准帧。
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
// 与 Sub2API 其它平台的非流式路径语义一致：把 delta 累积成 message，
// 取末帧的 finish_reason 与 usage。上游没有非流式端点，所以非流式客户端
// 只能靠这里聚合——这是协议约束，不是实现选择。
func Aggregate(rc io.Reader) (map[string]any, error) {
	scanner := bufio.NewScanner(rc)
	scanner.Buffer(make([]byte, 0, 1<<20), 8<<20)

	var content, reasoning strings.Builder
	var toolCalls []any
	finishReason := ""
	var usage map[string]any
	id, model, created := "", "", any(nil)

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
			if len(ch.Delta.ToolCalls) > 0 {
				toolCalls = append(toolCalls, ch.Delta.ToolCalls...)
			}
			if len(ch.Message.ToolCalls) > 0 {
				toolCalls = append(toolCalls, ch.Message.ToolCalls...)
			}
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
		"id":      id,
		"object":  "chat.completion",
		"model":   model,
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