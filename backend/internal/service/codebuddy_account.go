package service

// CodeBuddy（WorkBuddy / 腾讯 CodeBuddy）账号模型与凭据映射。
//
// 凭据来源是 wb2api-panel 的 auth JSON（嵌套或扁平两种形态都接受）。
// 移植包 pkg/codebuddy/auth 负责解析，这里只做两件事：
//   1. 把 sub2api 的 credentials map 还原成 *auth.Auth
//   2. 把上游刷新后的 *auth.Auth 写回 credentials

import (
	"encoding/json"
	"strconv"
	"strings"

	cbAuth "github.com/Wei-Shaw/sub2api/internal/pkg/codebuddy/auth"
)

// CodeBuddy 在 sub2api credentials 里的键名。
//
// 刻意与上游 auth 文件保持同名（snake_case），这样从面板导出的 auth JSON
// 可以近乎原样塞进来；只有嵌套结构被拍平，字段名不变。
// 改名会在两侧之间引入一张翻译表，而翻译表必然漂移——下游表现是 401/403，
// 极难排查，所以这里不做任何重命名。
const (
	codeBuddyCredAccessToken  = "access_token"
	codeBuddyCredRefreshToken = "refresh_token"
	codeBuddyCredExpiresAt    = "expires_at"
	codeBuddyCredRealm        = "realm"         // "cn" / "global"：决定上游域名
	codeBuddyCredUID          = "uid"           // 派生 X-Machine-ID / X-Session-ID
	codeBuddyCredEnterpriseID = "enterprise_id"
	codeBuddyCredNickname     = "nickname"
	codeBuddyCredDeviceToken  = "device_token"
	codeBuddyCredDomain       = "domain"
)

// IsCodeBuddy 报告账号是否为 CodeBuddy 平台。
func (a *Account) IsCodeBuddy() bool {
	return a != nil && a.Platform == PlatformCodeBuddy
}

// GetCodeBuddyAuth 把账号凭据还原成移植包能吃的 *auth.Auth。
//
// 返回 nil 表示凭据不足以发起请求（缺 access_token），调用方应报错而不是硬发——
// 没有 token 的请求必然 401，还会白白消耗一次账号冷却。
func (a *Account) GetCodeBuddyAuth() *cbAuth.Auth {
	if a == nil {
		return nil
	}
	accessToken := strings.TrimSpace(a.GetCredential(codeBuddyCredAccessToken))
	if accessToken == "" {
		return nil
	}
	out := &cbAuth.Auth{
		AccessToken:  accessToken,
		RefreshToken: strings.TrimSpace(a.GetCredential(codeBuddyCredRefreshToken)),
		UID:          strings.TrimSpace(a.GetCredential(codeBuddyCredUID)),
		EnterpriseID: strings.TrimSpace(a.GetCredential(codeBuddyCredEnterpriseID)),
		Nickname:     strings.TrimSpace(a.GetCredential(codeBuddyCredNickname)),
		Domain:       strings.TrimSpace(a.GetCredential(codeBuddyCredDomain)),
		DeviceToken:  strings.TrimSpace(a.GetCredential(codeBuddyCredDeviceToken)),
	}
	// expires_at 在凭据里存成字符串（JSON 数字经 map[string]any 会变 float64，
	// 两种都要能吃）。解析失败按 0 处理＝按「已过期」看待，触发一次续期。
	if raw := strings.TrimSpace(a.GetCredential(codeBuddyCredExpiresAt)); raw != "" {
		if v, err := strconv.ParseInt(raw, 10, 64); err == nil {
			out.ExpiresAt = v
		}
	}
	// realm 走未导出字段，只能通过 Parse 的路径写入；这里用上游自己的解析器
	// 重建一份最小 JSON，避免复制 realm 归一化逻辑（那是上游的知识）。
	if realm := strings.TrimSpace(a.GetCredential(codeBuddyCredRealm)); realm != "" {
		if parsed, err := cbAuth.Parse(buildCodeBuddyAuthJSON(out, realm)); err == nil {
			return parsed
		}
	}
	return out
}

// buildCodeBuddyAuthJSON 用上游接受的扁平形态重建一份最小 auth JSON。
// 只为把 realm 传进 Parse（Auth.realm 未导出，无法直接赋值）。
func buildCodeBuddyAuthJSON(a *cbAuth.Auth, realm string) []byte {
	payload := map[string]any{
		"accessToken":  a.AccessToken,
		"refreshToken": a.RefreshToken,
		"expiresAt":    a.ExpiresAt,
		"domain":       a.Domain,
		"realm":        realm,
		"uid":          a.UID,
		"enterpriseId": a.EnterpriseID,
		"nickname":     a.Nickname,
	}
	if a.DeviceToken != "" {
		payload["device_token"] = a.DeviceToken
	}
	raw, _ := json.Marshal(payload)
	return raw
}

// cloneCodeBuddyAuth 复制一份 Auth 用于就地刷新。
//
// 不走 `*a`（按值复制）：auth.Auth 内含 sync.Mutex，复制锁既是 go vet 的
// copylocks 违例，也真的会让两个副本各自加不同的锁、失去互斥意义。
// 这里经上游自己的 Parse 重建，得到独立的零值互斥锁。
func cloneCodeBuddyAuth(a *cbAuth.Auth) (*cbAuth.Auth, error) {
	if a == nil {
		return nil, ErrCodeBuddyNoCredential
	}
	cloned, err := cbAuth.Parse(buildCodeBuddyAuthJSON(a, a.Realm()))
	if err != nil {
		return nil, err
	}
	return cloned, nil
}

// ApplyCodeBuddyAuth 把刷新后的凭据写回 accounts.credentials 的更新 map。
//
// 上游刷新会改变 access_token / refresh_token / expires_at，三者必须一起写回；
// 只写 access_token 会让下一次刷新用旧的 refresh_token，最终整号失效。
func ApplyCodeBuddyAuth(a *Account, refreshed *cbAuth.Auth) map[string]any {
	next := map[string]any{}
	if a != nil && a.Credentials != nil {
		for k, v := range a.Credentials {
			next[k] = v
		}
	}
	if refreshed == nil {
		return next
	}
	next[codeBuddyCredAccessToken] = refreshed.AccessToken
	next[codeBuddyCredExpiresAt] = strconv.FormatInt(refreshed.ExpiresAt, 10)
	if refreshed.RefreshToken != "" {
		next[codeBuddyCredRefreshToken] = refreshed.RefreshToken
	}
	return next
}
