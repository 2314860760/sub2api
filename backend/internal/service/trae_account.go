package service

// Trae 账号模型与凭据映射。
//
// 凭据来自 OFM 的 auth JSON：
//   {access_token(JWT,1003), refresh_token(61), expires_at, uid, nickname,
//    phone, machine_id(hex32), device_id(hex32), enterprise_id}
//
// 注意 access_token 是 **JWT**，长度约 1 KB —— 不要假定 token 都很短。

import (
	"strconv"
	"strings"
	"time"

	cbTrae "github.com/Wei-Shaw/sub2api/internal/pkg/trae"
)

const (
	traeCredAccessToken  = "access_token"
	traeCredRefreshToken = "refresh_token"
	traeCredExpiresAt    = "expires_at" // Unix 秒（字符串或数字）
	traeCredUID          = "uid"
	traeCredNickname     = "nickname"
	traeCredEnterpriseID = "enterprise_id"
	traeCredMachineID    = "machine_id"
	traeCredDeviceID     = "device_id"
	traeCredRealm        = "realm"
)

// IsTrae 报告账号是否为 Trae 平台。
func (a *Account) IsTrae() bool {
	return a != nil && a.Platform == PlatformTrae
}

// GetTraeCredential 把账号凭据还原成 trae 包能吃的结构。
func (a *Account) GetTraeCredential(deploySalt string) *cbTrae.Credential {
	if a == nil {
		return nil
	}
	token := strings.TrimSpace(a.GetCredential(traeCredAccessToken))
	if token == "" {
		return nil
	}
	uid := strings.TrimSpace(a.GetCredential(traeCredUID))

	cred := &cbTrae.Credential{
		AccessToken:  token,
		RefreshToken: strings.TrimSpace(a.GetCredential(traeCredRefreshToken)),
		UID:          uid,
		Nickname:     strings.TrimSpace(a.GetCredential(traeCredNickname)),
		EnterpriseID: strings.TrimSpace(a.GetCredential(traeCredEnterpriseID)),
		Realm:        strings.TrimSpace(a.GetCredential(traeCredRealm)),
	}
	if cred.Realm == "" {
		// 缺省按国内站：trae.cn 的账号占多数，而打错站点会得到
		// 一个与凭据无关的 401，很难定位。
		cred.Realm = "cn"
	}

	// 凭据里的 machine_id/device_id 可能是 UUID 形态（带连字符），
	// 上游只要 hex32，这里统一规整。
	mid := strings.TrimSpace(a.GetCredential(traeCredMachineID))
	did := strings.TrimSpace(a.GetCredential(traeCredDeviceID))
	if mid != "" {
		cred.MachineID = cbTrae.NormalizeHex32(mid)
	}
	if did != "" {
		cred.DeviceID = cbTrae.NormalizeHex32(did)
	}
	if cred.MachineID == "" || cred.DeviceID == "" {
		fp := cbTrae.DeriveFingerprint(uid, deploySalt)
		if cred.MachineID == "" {
			cred.MachineID = fp.MachineID
		}
		if cred.DeviceID == "" {
			cred.DeviceID = fp.DeviceID
		}
	}

	if raw := strings.TrimSpace(a.GetCredential(traeCredExpiresAt)); raw != "" {
		if v, err := strconv.ParseInt(raw, 10, 64); err == nil {
			// 上游存的是秒；万一是毫秒则换算，避免把 1970 当有效期。
			if v > 1e12 {
				v /= 1000
			}
			cred.ExpiresAt = v
		}
	}
	return cred
}

// TraeNeedsRefresh 报告凭据是否该续期。
//
// Trae 的 refresh_token 是**轮换式**的：刷新后旧的立即失效。
// 所以并发刷新必须单飞，否则会有一个请求拿着已作废的 token 打上游。
func (a *Account) TraeNeedsRefresh(skew time.Duration) bool {
	if a == nil || strings.TrimSpace(a.GetCredential(traeCredRefreshToken)) == "" {
		return false
	}
	raw := strings.TrimSpace(a.GetCredential(traeCredExpiresAt))
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

// ApplyTraeRefresh 把续期结果写回 credentials。
//
// access / refresh / expires_at 三者必须一起写：只写 access 会让下次续期
// 用已作废的 refresh_token（上游轮换式）。
func ApplyTraeRefresh(a *Account, accessToken, refreshToken string, expiresAt int64) map[string]any {
	next := map[string]any{}
	if a != nil && a.Credentials != nil {
		for k, v := range a.Credentials {
			next[k] = v
		}
	}
	if accessToken != "" {
		next[traeCredAccessToken] = accessToken
	}
	if refreshToken != "" {
		next[traeCredRefreshToken] = refreshToken
	}
	if expiresAt > 0 {
		next[traeCredExpiresAt] = strconv.FormatInt(expiresAt, 10)
	}
	return next
}
