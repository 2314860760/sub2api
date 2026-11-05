package service

// Qoder 账号模型与凭据映射。
//
// 凭据来自 OFM / qoder2api 的 auth JSON，形态与 CodeBuddy 类似（dt-/drt- 前缀），
// 但字段名不同：qoder 用 security_oauth_token + expire_time（毫秒）。

import (
	"encoding/json"
	"strconv"
	"strings"
	"time"

	cbQoder "github.com/Wei-Shaw/sub2api/internal/pkg/qoder"
)

// Qoder 在 sub2api credentials 里的键名。
//
// 刻意与上游 auth 文件同名，方便直接从 OFM 导出后原样粘贴；
// 只把嵌套结构拍平，不改字段名。
const (
	qoderCredSecurityToken = "security_oauth_token" // 推理与签名主凭据（dt- 前缀）
	qoderCredRefreshToken  = "refresh_token"        // drt- 前缀
	qoderCredExpireTime    = "expire_time"          // 毫秒
	qoderCredMachineID     = "machine_id"           // 设备标识，参与签名
	qoderCredUID           = "uid"                  // 签名必需
	qoderCredNickname      = "nickname"
	qoderCredRealm         = "realm" // cn / global
)

// IsQoder 报告账号是否为 Qoder 平台。
func (a *Account) IsQoder() bool {
	return a != nil && a.Platform == PlatformQoder
}

// GetQoderCredential 把账号凭据还原成 qoder 包能吃的结构。
//
// 返回 nil 表示凭据不足以发起请求（缺 security_oauth_token 或 uid）。
// **uid 是必需的**：它参与 info 加密与 Cosy-User 头，缺了签名会被服务端拒
// （回 101 Signature invalid），但报错信息完全指不到 uid。
func (a *Account) GetQoderCredential(deploySalt string) *cbQoder.Credential {
	if a == nil {
		return nil
	}
	token := strings.TrimSpace(a.GetCredential(qoderCredSecurityToken))
	uid := strings.TrimSpace(a.GetCredential(qoderCredUID))
	if token == "" || uid == "" {
		return nil
	}

	realm := strings.TrimSpace(a.GetCredential(qoderCredRealm))
	if realm == "" {
		// 缺省按国际站；CN 账号必须显式写 realm=cn，否则会打到 api2.qoder.sh
		// 得到 `code=105 Login expired`（凭据有效但站点不对）。
		realm = "global"
	}

	cred := &cbQoder.Credential{
		SecurityOauthToken: token,
		RefreshToken:       strings.TrimSpace(a.GetCredential(qoderCredRefreshToken)),
		UID:                uid,
		Name:               strings.TrimSpace(a.GetCredential(qoderCredNickname)),
		Realm:              realm,
		Fingerprint:        cbQoder.DeriveFingerprint(uid, deploySalt),
	}
	// 上游若给了 machine_id 就用它的；否则用派生值（实测服务端只要求同账号稳定）。
	if mid := strings.TrimSpace(a.GetCredential(qoderCredMachineID)); mid != "" {
		cred.Fingerprint.MachineID = mid
	}
	return cred
}

// QoderNeedsRefresh 报告凭据是否该续期。
//
// expire_time 是毫秒；没有 refresh_token 时永不续期（只能重新登录）。
func (a *Account) QoderNeedsRefresh(skewMillis int64) bool {
	if a == nil || strings.TrimSpace(a.GetCredential(qoderCredRefreshToken)) == "" {
		return false
	}
	raw := strings.TrimSpace(a.GetCredential(qoderCredExpireTime))
	if raw == "" {
		return true
	}
	ms, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || ms <= 0 {
		return true
	}
	if t, ok := cbQoder.ExpireTimeMillis(raw); ok {
		return time.Until(t).Milliseconds() <= skewMillis
	}
	return true
}

// ApplyQoderRefresh 把续期结果写回 credentials 的更新 map。
//
// access / refresh / expire_time 必须一起写：只写 access 会让下次续期
// 用已作废的 refresh_token（上游是轮换式的）。
func ApplyQoderRefresh(a *Account, token, refreshToken string, expireTimeMillis int64) map[string]any {
	next := map[string]any{}
	if a != nil && a.Credentials != nil {
		for k, v := range a.Credentials {
			next[k] = v
		}
	}
	if token != "" {
		next[qoderCredSecurityToken] = token
		// access_token 与 security_oauth_token 在上游是同一个值，
		// 两份都写以免下游读到过期的那份。
		next["access_token"] = token
	}
	if refreshToken != "" {
		next[qoderCredRefreshToken] = refreshToken
	}
	if expireTimeMillis > 0 {
		next[qoderCredExpireTime] = strconv.FormatInt(expireTimeMillis, 10)
	}
	return next
}

// QoderCredentialShape 供管理端预览凭据结构（不含敏感值）。
func QoderCredentialShape(creds map[string]any) map[string]any {
	if creds == nil {
		return nil
	}
	out := map[string]any{}
	for k, v := range creds {
		if s, ok := v.(string); ok && (k == qoderCredSecurityToken || k == qoderCredRefreshToken) {
			if len(s) > 8 {
				out[k] = s[:4] + "…(len=" + strconv.Itoa(len(s)) + ")"
			} else {
				out[k] = "<short>"
			}
			continue
		}
		out[k] = v
	}
	return out
}

var _ = json.Marshal
