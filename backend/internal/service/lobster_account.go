package service

// LobsterAI 账号模型与凭据映射。
//
// 凭据按官方 keyfrom 结构存：除了 token，还要保存 firstKeyfrom /
// latestKeyfrom / uuid —— 它们参与每个鉴权请求的归因，缺了会被当成非官方客户端。

import (
	"strconv"
	"strings"
	"time"

	cbLobster "github.com/Wei-Shaw/sub2api/internal/pkg/lobsterai"
)

const (
	lobsterCredAccessToken  = "access_token"
	lobsterCredRefreshToken = "refresh_token"
	lobsterCredExpiresAt    = "expires_at" // Unix 秒
	lobsterCredUID          = "uid"
	lobsterCredNickname     = "nickname"
	lobsterCredPhone        = "phone"
	// keyfrom 归因三件套：每个鉴权请求都要带。
	lobsterCredFirstKeyfrom  = "first_keyfrom"
	lobsterCredLatestKeyfrom = "latest_keyfrom"
	lobsterCredInstallUUID   = "installation_uuid"
	lobsterCredClientVersion = "client_version"
)

// IsLobsterAI 报告账号是否为 LobsterAI 平台。
func (a *Account) IsLobsterAI() bool {
	return a != nil && a.Platform == PlatformLobsterAI
}

// GetLobsterKeyfrom 还原官方 keyfrom 归因载荷。
//
// 缺失时用合理默认：官方首次安装会把 firstKeyfrom 与 latestKeyfrom 设成同一个
// 渠道标识。这里缺省用 "client"（官方 client_menu / site_deployment 都是渠道值，
// 具体值不影响鉴权，只影响归因统计）。
func (a *Account) GetLobsterKeyfrom(clientVersion string) cbLobster.Keyfrom {
	kf := cbLobster.Keyfrom{
		FirstKeyfrom:     "client",
		LatestKeyfrom:    "client",
		InstallationUUID: strings.TrimSpace(a.GetCredential(lobsterCredInstallUUID)),
		Version:          firstNonEmptyStr(strings.TrimSpace(a.GetCredential(lobsterCredClientVersion)), clientVersion),
	}
	if v := strings.TrimSpace(a.GetCredential(lobsterCredFirstKeyfrom)); v != "" {
		kf.FirstKeyfrom = v
	}
	if v := strings.TrimSpace(a.GetCredential(lobsterCredLatestKeyfrom)); v != "" {
		kf.LatestKeyfrom = v
	}
	// 已登录时官方会把 userId 一起带上。
	kf.UserID = strings.TrimSpace(a.GetCredential(lobsterCredUID))
	return kf
}

// LobsterAccessToken 返回当前 access token（空表示未登录）。
func (a *Account) LobsterAccessToken() string {
	if a == nil {
		return ""
	}
	return strings.TrimSpace(a.GetCredential(lobsterCredAccessToken))
}

// LobsterNeedsRefresh 报告是否该续期。
//
// 官方在 401 时被动刷新，并另有一个主动刷新循环。这里用「提前 10 分钟」
// 的主动策略，减少一次 401 往返。
func (a *Account) LobsterNeedsRefresh(skew time.Duration) bool {
	if a == nil || strings.TrimSpace(a.GetCredential(lobsterCredRefreshToken)) == "" {
		return false
	}
	raw := strings.TrimSpace(a.GetCredential(lobsterCredExpiresAt))
	if raw == "" {
		return true
	}
	v, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || v <= 0 {
		return true
	}
	if v > 1e12 {
		v /= 1000
	}
	return time.Now().Add(skew).Unix() >= v
}

// ApplyLobsterTokens 把 token 写回 credentials。
func ApplyLobsterTokens(a *Account, tokens *cbLobster.Tokens, expiresAt int64) map[string]any {
	next := map[string]any{}
	if a != nil && a.Credentials != nil {
		for k, v := range a.Credentials {
			next[k] = v
		}
	}
	if tokens == nil {
		return next
	}
	if tokens.AccessToken != "" {
		next[lobsterCredAccessToken] = tokens.AccessToken
	}
	if tokens.RefreshToken != "" {
		next[lobsterCredRefreshToken] = tokens.RefreshToken
	}
	if expiresAt > 0 {
		next[lobsterCredExpiresAt] = strconv.FormatInt(expiresAt, 10)
	}
	return next
}

// ApplyLobsterExchange 把登录结果写回 credentials（含用户信息与 keyfrom）。
func ApplyLobsterExchange(a *Account, res *cbLobster.ExchangeResult, kf cbLobster.Keyfrom, expiresAt int64) map[string]any {
	next := ApplyLobsterTokens(a, &res.Tokens, expiresAt)
	next[lobsterCredFirstKeyfrom] = kf.FirstKeyfrom
	next[lobsterCredLatestKeyfrom] = kf.LatestKeyfrom
	if kf.InstallationUUID != "" {
		next[lobsterCredInstallUUID] = kf.InstallationUUID
	}
	if kf.Version != "" {
		next[lobsterCredClientVersion] = kf.Version
	}
	if res.User.Nickname != "" {
		next[lobsterCredNickname] = res.User.Nickname
	}
	if res.User.Phone != "" {
		next[lobsterCredPhone] = res.User.Phone
	}
	if v := firstNonEmptyStr(res.User.UID, res.User.ID); v != "" {
		next[lobsterCredUID] = v
	}
	return next
}
