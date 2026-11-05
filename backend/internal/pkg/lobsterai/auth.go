package lobsterai

// 登录与鉴权客户端：1:1 对照官方开源客户端实现。
//
// # 官方请求三段式
//
//	1. GET  LoginURLPath            → {"data":{"value":"<登录页 URL>"}}
//	2. 用户在该页登录 → 回调带 code
//	3. POST /api/auth/exchange      {authCode, keyfrom*} → {code:0, data:{accessToken,…}}
//
// 续期是同一形态：POST /api/auth/refresh {refreshToken, keyfrom*}。
//
// # keyfrom 归因字段为什么不能省
//
// 官方每个 auth 请求都带 `withKeyfromBody(...)`（src/main/main.ts:5969），
// 即把 `firstKeyfrom` / `latestKeyfrom` / `uuid` / `userId` / `version` 一起发出去。
// 这些字段用于渠道归因与客户端识别。第三方实现少发或改名，就可能被判定为
// 非官方客户端 —— 这与「注册完没登录就被封」的典型症状吻合。
//
// 所以本包把 Keyfrom 做成显式参数，调用方必须提供，而不是给个默认值糊过去。

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// Keyfrom 是官方的渠道归因载荷。
//
// 官方 buildKeyfromPayload（src/main/main.ts:5950）：
//
//	{ firstKeyfrom, latestKeyfrom, uuid?, userId?, version }
//
// uuid 与 userId 是可选（空则不发），其余三项必发。
type Keyfrom struct {
	// FirstKeyfrom 是首次安装时的渠道标识。官方从 store 读取并持久化。
	FirstKeyfrom string `json:"firstKeyfrom"`
	// LatestKeyfrom 是最近一次的渠道标识。
	LatestKeyfrom string `json:"latestKeyfrom"`
	// InstallationUUID 是安装标识（官方 getOrCreateInstallationId）。
	// 首次登录前就应存在，且**永不变更** —— 变更等于换设备。
	InstallationUUID string `json:"uuid,omitempty"`
	// UserID 是已登录用户 id；首登时为空。
	UserID string `json:"userId,omitempty"`
	// Version 是客户端版本号，官方用 app.getVersion()。
	Version string `json:"version"`
}

// Tokens 是登录/续期后的令牌对。
type Tokens struct {
	AccessToken  string
	RefreshToken string
}

// User 是官方 exchange 响应里的 user 对象（只取网关需要的字段）。
type User struct {
	ID        string
	UID       string
	Nickname  string
	Phone     string
	AvatarURL string
}

// ExchangeResult 是 exchange 的完整结果。
type ExchangeResult struct {
	Tokens Tokens
	User   User
	// Raw 保留原始 data，便于排障时对照官方字段。
	Raw map[string]any
}

// Client 是 LobsterAI 鉴权与业务客户端。
type Client struct {
	HTTP *http.Client
	// ClientVersion 参与 User-Agent 与 keyfrom.version。
	// 空则用 FallbackClientVersion。
	ClientVersion string
}

// New 构造客户端。
func New() *Client {
	return &Client{
		HTTP: &http.Client{Timeout: 60 * time.Second},
	}
}

func (c *Client) version() string {
	if v := strings.TrimSpace(c.ClientVersion); v != "" {
		return v
	}
	return FallbackClientVersion
}

// FetchLoginURL 取登录页地址。
//
// 官方 auth.ts:566 fetchLoginUrl：先打 overmind，拿 data.value；
// 失败或字段缺失时回落 PortalLoginURL。这里保持同样的两段逻辑，
// 因为 overmind 偶发不可用，直接硬编码会在那时整个登录不可用。
func (c *Client) FetchLoginURL(ctx context.Context) string {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, LoginURLPath, nil)
	if err != nil {
		return PortalLoginURL
	}
	req.Header.Set("accept", "application/json")

	resp, err := c.HTTP.Do(req)
	if err != nil {
		return PortalLoginURL
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return PortalLoginURL
	}
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))

	var env struct {
		Data struct {
			Value string `json:"value"`
		} `json:"data"`
	}
	if err := json.Unmarshal(raw, &env); err != nil {
		return PortalLoginURL
	}
	if v := strings.TrimSpace(env.Data.Value); v != "" {
		return v
	}
	return PortalLoginURL
}

// Exchange 用 authCode 换 token。
//
// 官方 main.ts:8218-8237：
//
//	POST {server}/api/auth/exchange
//	{"authCode":"<code>", ...keyfrom}
//	→ {code:0, data:{accessToken, refreshToken, user, quota}}
//
// 注意字段是 **camelCase**（accessToken 而非 access_token）。
// 用错大小写在 Go 里不会报错、只会解出空值，表现为"登录成功但没 token"。
func (c *Client) Exchange(ctx context.Context, authCode string, kf Keyfrom) (*ExchangeResult, error) {
	return c.exchangeAt(ctx, ServerBase+ExchangePath, authCode, kf)
}

// exchangeAt 是 Exchange 的可注入 URL 版本（测试用）。
func (c *Client) exchangeAt(ctx context.Context, url, authCode string, kf Keyfrom) (*ExchangeResult, error) {
	if strings.TrimSpace(authCode) == "" {
		return nil, fmt.Errorf("lobsterai: authCode 为空")
	}
	body := kf.merge(map[string]any{"authCode": authCode})

	data, err := c.postJSON(ctx, url, body, "")
	if err != nil {
		return nil, err
	}

	out := &ExchangeResult{Raw: data}
	out.Tokens.AccessToken = str(data, "accessToken")
	out.Tokens.RefreshToken = str(data, "refreshToken")
	if user, ok := data["user"].(map[string]any); ok {
		out.User = User{
			ID:        str(user, "id"),
			UID:       firstNonEmpty(str(user, "uid"), str(user, "userId")),
			Nickname:  str(user, "nickname"),
			Phone:     str(user, "phone"),
			AvatarURL: str(user, "avatar"),
		}
	}
	if out.Tokens.AccessToken == "" {
		return nil, fmt.Errorf("lobsterai: exchange 响应无 accessToken（检查字段大小写）：%s", truncateJSON(data))
	}
	return out, nil
}

// Refresh 用 refreshToken 续期。
//
// 官方 main.ts:6027-6028：
//
//	POST {server}/api/auth/refresh
//	{"refreshToken":"<rt>", ...keyfrom}
//
// 响应与 exchange 同形（data.accessToken / data.refreshToken）。
// 官方 TERMINAL_REFRESH_ERROR_CODES = {40100, 40101, NotMember}：
// 命中这些码说明 refreshToken 已废，必须重新登录 —— 重试无意义。
func (c *Client) Refresh(ctx context.Context, refreshToken string, kf Keyfrom) (*Tokens, error) {
	if strings.TrimSpace(refreshToken) == "" {
		return nil, fmt.Errorf("lobsterai: refreshToken 为空")
	}
	body := kf.merge(map[string]any{"refreshToken": refreshToken})

	data, err := c.postJSON(ctx, ServerBase+RefreshPath, body, "")
	if err != nil {
		return nil, err
	}
	access := str(data, "accessToken")
	if access == "" {
		return nil, fmt.Errorf("lobsterai: refresh 响应无 accessToken，需重新登录")
	}
	return &Tokens{AccessToken: access, RefreshToken: str(data, "refreshToken")}, nil
}

// Logout 注销。失败不致命（本地清 token 即可）。
func (c *Client) Logout(ctx context.Context, accessToken string, kf Keyfrom) error {
	_, err := c.postJSON(ctx, ServerBase+LogoutPath, kf.merge(map[string]any{}), accessToken)
	return err
}

// postJSON 发 POST 并解官方信封 {code, message, data}。
//
// 官方把业务错误也放在 200 响应里（code != 0），所以状态码检查之后
// 还要检查 code —— 只看 HTTP 状态会把「code=40100 已过期」当成成功。
func (c *Client) postJSON(ctx context.Context, url string, body map[string]any, bearer string) (map[string]any, error) {
	raw, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(raw))
	if err != nil {
		return nil, err
	}
	req.Header.Set("content-type", "application/json")
	req.Header.Set("accept", "application/json")
	req.Header.Set("user-agent", "LobsterAI/"+c.version())
	if bearer != "" {
		req.Header.Set("authorization", "Bearer "+bearer)
	}

	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	respRaw, _ := io.ReadAll(io.LimitReader(resp.Body, 2<<20))

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("lobsterai: %s %d: %s", url, resp.StatusCode, truncate(string(respRaw), 300))
	}

	var env struct {
		Code    int            `json:"code"`
		Message string         `json:"message"`
		Data    map[string]any `json:"data"`
	}
	if err := json.Unmarshal(respRaw, &env); err != nil {
		return nil, fmt.Errorf("lobsterai: 解析响应失败: %w (%s)", err, truncate(string(respRaw), 200))
	}
	if env.Code != 0 {
		return nil, fmt.Errorf("lobsterai: code=%d %s", env.Code, env.Message)
	}
	return env.Data, nil
}

// merge 把 keyfrom 摊平进请求体。
//
// 官方 withKeyfromBody（main.ts:5969）就是 `{...body, ...buildKeyfromPayload()}`，
// 即 keyfrom 字段与业务字段**同级**，不是嵌套对象。嵌套会让服务端读不到归因。
func (kf Keyfrom) merge(body map[string]any) map[string]any {
	out := make(map[string]any, len(body)+5)
	for k, v := range body {
		out[k] = v
	}
	out["firstKeyfrom"] = kf.FirstKeyfrom
	out["latestKeyfrom"] = kf.LatestKeyfrom
	out["version"] = firstNonEmpty(kf.Version, FallbackClientVersion)
	if kf.InstallationUUID != "" {
		out["uuid"] = kf.InstallationUUID
	}
	if kf.UserID != "" {
		out["userId"] = kf.UserID
	}
	return out
}

func str(m map[string]any, key string) string {
	if m == nil {
		return ""
	}
	if v, ok := m[key].(string); ok {
		return strings.TrimSpace(v)
	}
	return ""
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

func truncateJSON(m map[string]any) string {
	raw, _ := json.Marshal(m)
	return truncate(string(raw), 300)
}
