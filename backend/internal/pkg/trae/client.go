// Package trae 实现 Trae（trae.cn / trae.com.cn，字节跳动）的上游协议。
//
// # 这个包解决什么问题
//
// Trae 的推理端点不是标准 OpenAI/Anthropic 形状，而是一个叫 "SOLO" 的私有结构：
// OpenAI Chat Completions 的超集 + 字节跳动自己的字段。响应也不是 OpenAI chunk，
// 而是 `event:<name>` + `data:<json>` 的事件流。
//
// # 协议要点（照 OFM 的 TS 实现逐条核对过）
//
//	POST {host}/api/agent/v3/llm_utils_chat
//	Authorization: Cloud-IDE-JWT <token>   ← 不是 Bearer
//	X-Cloudide-Token / X-Ide-Token: 同一个 token（三处都要带）
//	X-Machine-Id / X-Device-Id: hex32
//
// 请求体：`model` 会被 `config_name` 的值**覆盖**（不是透传），
// `tools[].function.parameters` 必须是 **JSON 字符串**（对象形式会被静默拒绝）。
//
// 响应：`event:error` 也是 **HTTP 200**，所以必须自己判事件类型。
//
// # 为什么这些细节值得写进注释
//
// 它们都是「做错了不报错、只是结果不对」的类型：缺一个头得到 401、
// parameters 用对象形式得到静默拒绝、`model` 不透传 config_name 得到 4001。
// 每一条都是踩过一次才知道的，记在这里省下一次。
package trae

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

const (
	// ChatPath 是推理端点。
	ChatPath = "/api/agent/v3/llm_utils_chat"
	// ModelsPath 是模型目录端点。
	ModelsPath = "/api/ide/v1/get_detail_param"
	// ExchangePath 是登录时的 token 交换端点。
	ExchangePath = "/cloudide/api/v3/trae/oauth/ExchangeToken"

	// ⚠️ Trae 有**四个不同的 host**，各司其职，混用会得到 404 而不是明确报错：
	//
	//   推理 chat     trae-api-cn.mchost.guru   ← 本常量
	//   用户/签到     api.trae.cn
	//   OAuth 交换    api.trae.com.cn           ← 最容易被误当成 chat host
	//   控制台        www.trae.cn
	//
	// 把 chat 打到 api.trae.com.cn 会返回一段 TLB 404 HTML 页，
	// 看起来像"端点不存在"，实际是打错了域。
	BaseCN     = "https://trae-api-cn.mchost.guru"
	BaseGlobal = "https://trae-api-cn.mchost.guru"

	// OAuthHost 是登录/续期用的 host，与 BaseCN 不同。
	OAuthHost     = "https://api.trae.com.cn"
	OAuthHostAlt  = "https://api.trae.cn"

	// 客户端指纹常量。上游按这套值判断请求是否来自官方 IDE。
	// 版本号会随官方发版变化，做成变量便于注入。
	DefaultIDEVersion    = "0.1.52"
	// DefaultIDEVersionCode 是 IDE 的**构建号**，与版本号是两个独立字段。
	// 缺少它上游会回 4001 `binding: expr_path=app_version_code` —— 错误信息
	// 说的是"缺 app_version_code"，但实际那个值来自 X-App-Version-Code 头，
	// 与请求体无关，很容易往 body 里找。
	DefaultIDEVersionCode = "20260811"
	DefaultAppID          = "6eefa01c-1036-4c7e-9ca5-d891f63bfcd8"
	DefaultUserAgent      = "Trae/0.1.52"
	// DefaultClientID 是 OAuth 客户端标识（登录/续期用，chat 不需要）。
	DefaultClientID = "en1oxy7wnwj9n"
)

// Credential 是发起一次推理所需的账号材料。
type Credential struct {
	// AccessToken 是 JWT（形如 eyJhbGciOiJSUzI1NiIs…）。
	AccessToken string
	RefreshToken string
	// ExpiresAt 是 Unix 秒。上游的 JWT exp 也带这个信息，但凭据里单独存了一份。
	ExpiresAt int64

	// UID / Nickname / EnterpriseID 仅用于展示与日志。
	UID          string
	Nickname     string
	EnterpriseID string

	// MachineID / DeviceID 是 hex32，参与请求头。
	// 上游不校验其与硬件的对应关系（OFM 实测可轮换），所以可以派生。
	MachineID string
	DeviceID  string

	// Realm "cn" / "global"，决定 base URL。
	Realm string

	// 可选覆盖：客户端版本、UA、AppID。
	IDEVersion     string
	IDEVersionCode string
	AppID         string
	UserAgent     string
}

// BaseURL 返回该账号应访问的站点根。
func (c *Credential) BaseURL() string {
	if strings.EqualFold(c.Realm, "global") {
		return BaseGlobal
	}
	return BaseCN
}

// Client 是发往 Trae 上游的 HTTP 客户端。
type Client struct {
	HTTP *http.Client
	// DeploySalt 是部署私有指纹盐；为空则退化为纯 uid 派生。
	DeploySalt string
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
			// 流式响应可能很长，生命周期交给 ctx。
			Timeout: 0,
		},
	}
}

// buildHeaders 生成上游要求的请求头。
//
// 三个 token 头缺一不可：上游分别校验 Authorization、X-Cloudide-Token、X-Ide-Token，
// 只带 Authorization 会得到 401（且报错不指明是哪个头）。
func (c *Client) buildHeaders(cred *Credential, accept string) map[string]string {
	ideVersion := firstNonEmpty(cred.IDEVersion, DefaultIDEVersion)
	ideVersionCode := firstNonEmpty(cred.IDEVersionCode, DefaultIDEVersionCode)
	appID := firstNonEmpty(cred.AppID, DefaultAppID)
	ua := firstNonEmpty(cred.UserAgent, DefaultUserAgent)

	machineID := cred.MachineID
	deviceID := cred.DeviceID
	if machineID == "" || deviceID == "" {
		fp := DeriveFingerprint(cred.UID, c.DeploySalt)
		if machineID == "" {
			machineID = fp.MachineID
		}
		if deviceID == "" {
			deviceID = fp.DeviceID
		}
	}

	return map[string]string{
		"accept":                accept,
		"authorization":         "Cloud-IDE-JWT " + cred.AccessToken,
		"content-type":          "application/json",
		"request-traffic-type":  "prod",
		"user-agent":            ua,
		"x-app-id":              appID,
		"x-app-version":         "default",
		"x-app-version-code":    ideVersionCode,
		"x-cloudide-token":      cred.AccessToken,
		"x-device-brand":        "Apple",
		"x-device-id":           deviceID,
		"x-device-type":         "macos",
		"x-ide-token":           cred.AccessToken,
		"x-ide-version":         ideVersion,
		"x-ide-version-code":    ideVersionCode,
		"x-ide-version-type":    "stable",
		"x-machine-id":          machineID,
		"x-os-version":          "macOS 15.7.4",
		"x-uid":                 cred.UID,
	}
}

// ChatStream 发一次流式推理，返回**已转换成标准 OpenAI SSE** 的字节流。
//
// 上游是流式专用的（非流式会被忽略），非流式需求由调用方聚合。
func (c *Client) ChatStream(ctx context.Context, cred *Credential, openAIBody []byte, configName string) (io.ReadCloser, int, error) {
	if cred == nil || strings.TrimSpace(cred.AccessToken) == "" {
		return nil, 0, fmt.Errorf("trae: 缺 access_token")
	}

	payload, err := BuildSOLOBody(openAIBody, configName)
	if err != nil {
		return nil, 0, err
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		return nil, 0, err
	}

	url := cred.BaseURL() + ChatPath
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, strings.NewReader(string(raw)))
	if err != nil {
		return nil, 0, err
	}
	for k, v := range c.buildHeaders(cred, "text/event-stream") {
		req.Header.Set(k, v)
	}

	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, 0, err
	}
	if resp.StatusCode != http.StatusOK {
		defer resp.Body.Close()
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		return nil, resp.StatusCode, fmt.Errorf("trae: 上游 %d: %s", resp.StatusCode, truncate(string(body), 300))
	}

	pr, pw := io.Pipe()
	go func() {
		defer resp.Body.Close()
		defer pw.Close()
		convertSSE(resp.Body, pw)
	}()
	return pr, resp.StatusCode, nil
}

// FetchModels 取模型目录（用于同步模型清单）。
func (c *Client) FetchModels(ctx context.Context, cred *Credential) ([]ModelEntry, error) {
	url := cred.BaseURL() + ModelsPath
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	for k, v := range c.buildHeaders(cred, "application/json") {
		if k == "content-type" {
			continue // GET 不设 content-type
		}
		req.Header.Set(k, v)
	}

	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("trae: models %d: %s", resp.StatusCode, truncate(string(raw), 200))
	}

	var doc struct {
		Data []ModelEntry `json:"data"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("trae: 解析模型目录失败: %w (前 200 字节: %s)", err, truncate(string(raw), 200))
	}
	return doc.Data, nil
}

// ModelEntry 是目录里的一条模型描述。
type ModelEntry struct {
	ConfigName  string `json:"config_name"`
	DisplayName string `json:"display_name"`
	Model       string `json:"model"`
	Multimodal  bool   `json:"multimodal"`
	MaxMode     bool   `json:"max_mode"`
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

// ProbeChannel 用指定 function 渠道发一次最小请求，返回是否可调用。
//
// 存在的理由：上游模型目录接口对某些账号返回 2001（目录未下发），
// 但推理实际可用。此时唯一可靠的判断是**真的调一次**。
// 这个函数让「找出可用渠道」变成一次自动化探测，而不是逐个手工试。
func ProbeChannel(ctx context.Context, cl *Client, cred *Credential, openAIBody []byte, configName, channel string) error {
	payload, err := BuildSOLOBody(openAIBody, configName)
	if err != nil {
		return err
	}
	// 覆盖渠道标识。BuildSOLOBody 默认填 DefaultFunction，
	// 但渠道必须与模型匹配，所以探测时需要逐渠道试。
	payload.Function = channel
	payload.MaxTokens = intPtr(16)

	raw, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, cred.BaseURL()+ChatPath, strings.NewReader(string(raw)))
	if err != nil {
		return err
	}
	for k, v := range cl.buildHeaders(cred, "text/event-stream") {
		req.Header.Set(k, v)
	}

	resp, err := cl.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		buf := make([]byte, 2048)
		n, _ := resp.Body.Read(buf)
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, truncate(string(buf[:n]), 200))
	}

	// ⚠️ 必须读到内容帧为止，不能只看首块。
	// 上游会先发 metadata / timing 帧，错误帧可能在**第二或第三帧**；
	// 只 peek 首块会把「metadata 正常」误判成「渠道可调用」，
	// 而实际推理在下一帧就失败了 —— 这个假阳性让排查方向偏过一轮。
	scanner := bufio.NewScanner(resp.Body)
	scanner.Buffer(make([]byte, 0, 64<<10), 1<<20)
	frames := 0
	for scanner.Scan() {
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)

		// 任何错误帧都算失败。
		if strings.HasPrefix(trimmed, "event:error") {
			// 下一行是 data，读出来作为详情。
			if scanner.Scan() {
				return fmt.Errorf("event:error: %s", truncate(strings.TrimSpace(scanner.Text()), 200))
			}
			return fmt.Errorf("event:error")
		}
		// data 里直接带 code 也算。
		if strings.HasPrefix(trimmed, "data:") {
			frames++
			payload := strings.TrimSpace(strings.TrimPrefix(trimmed, "data:"))
			for _, code := range []string{"4001", "4027", "2001", "1005", "4008", "4011"} {
				if strings.Contains(payload, `"code":`+code) || strings.Contains(payload, `"code":"`+code+`"`) {
					return fmt.Errorf("code=%s: %s", code, truncate(payload, 180))
				}
			}
			// 收到真正的 output 内容帧 = 确实可调用。
			if strings.Contains(payload, `"response"`) || strings.Contains(payload, `"reasoning_content"`) {
				return nil
			}
		}
		// 帧数上限，避免长流把探测拖久。
		if frames > 40 {
			return nil
		}
	}
	if err := scanner.Err(); err != nil {
		return err
	}
	return fmt.Errorf("流结束但无内容帧（frames=%d）", frames)
}

func intPtr(v int) *int { return &v }