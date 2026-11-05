package trae

// 设备指纹派生。
//
// # 为什么可以派生
//
// Trae 要求 `X-Machine-Id` / `X-Device-Id`（hex32），但 OFM 实测这两个值
// **可以轮换**（其实现里甚至有 `TRAE_ROTATE_MACHINE_ID` 开关），说明上游并不
// 把它们与真实硬件绑定校验。所以派生是安全的：
//
//   - 同一账号长期稳定 → 不会因"换机器"触发风控
//   - 不同账号指纹不同 → 阻断跨账号关联
//
// # 盐的意义
//
// 纯 uid 派生的问题是「知道 uid 就能算出指纹，且所有部署算出的完全一样」。
// 上游一旦识别出该模式，可以按指纹模式批量封。加部署私有盐后每个部署
// 有独立指纹空间。**盐一旦设定必须永久保持** —— 变更等于换设备。

import (
	"crypto/md5"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

// Fingerprint 是上游要求的两个设备标识。
type Fingerprint struct {
	MachineID string // hex32
	DeviceID  string // hex32
}

// DeriveFingerprint 由 uid 派生指纹。
func DeriveFingerprint(uid, salt string) Fingerprint {
	seed := func(purpose string) string {
		base := purpose + ":" + uid
		if salt != "" {
			base += "|salt:" + salt
		}
		return base
	}
	return Fingerprint{
		MachineID: md5Hex(seed("machine"))[:32],
		// DeviceID 用不同 purpose + 不同算法，避免两者相同
		// （相同会被上游当成「同一设备两个身份」，可能触发关联检查）。
		DeviceID: sha256Hex(seed("device"))[:32],
	}
}

func md5Hex(s string) string {
	sum := md5.Sum([]byte(s))
	return hex.EncodeToString(sum[:])
}

func sha256Hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// NormalizeHex32 把任意字符串规整成 hex32。
//
// 凭据里的 machine_id 有时是带连字符的 UUID（36 字符），有时是 hex32。
// 上游只要 hex32，所以这里统一处理而不是让调用方各写一遍。
func NormalizeHex32(s string) string {
	clean := make([]byte, 0, 32)
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F') {
			clean = append(clean, c)
		}
	}
	if len(clean) >= 32 {
		return string(clean[:32])
	}
	// 不足 32 位：用 md5 补齐，保证长度合法且稳定。
	return md5Hex(string(clean))
}

var _ = fmt.Sprintf
