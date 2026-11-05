// Package qoder 实现腾讯 Qoder（qoder.com / qoder.cn）的上游协议。
//
// # 这个包解决什么问题
//
// Qoder 的推理端点不是公开的 OpenAI 兼容接口：`/model/v1/chat/completions` 在
// 国内实测返回 503（alb 无上游路由），真正可用的是 `/algo/api/v2/service/pro/sse/
// agent_chat_generation`，请求体经过一层自定义编码、并带一个 MD5 签名头。
//
// # 与 OFM 的 WASM 方案的关系
//
// OFM（dsh-our-free-model）把官方客户端的 Rust 编译成 292 KB 的 wasm 来完成签名与
// body 编码，看起来不可复现。但社区已把算法还原成普通 Go：
// github.com/Zhengyuuuui/qoder2api 的 internal/cosy/（MIT）。
//
// 本包按该实现重写，去掉了 sub2api 不需要的部分（token 持久化、账号池、
// 签到任务），保留协议必需的四件事：
//
//	encoding.go  body 的「加密」= 自定义字母表 base64 + 字符旋转
//	cosy.go      签名 = MD5；会话 = RSA 包 tempKey + AES-CBC 包身份
//	fingerprint 设备指纹 = 由 uid 单向派生（不需要真机）
//
// # 关于「加密」的诚实说明
//
// body 那层不是密码学意义上的加密，是可逆的编码混淆：标准 base64 后按 n/3
// 旋转、再逐字符映射到自定义字母表。没有密钥参与。把它当签名的一部分看待即可。
//
// 真正的密码学只有两处：RSA(PKCS1v15) 包裹客户端生成的 tempKey，
// 以及 AES-128-CBC 用该 tempKey 加密身份 JSON。两者都用公开的
// 服务端公钥 / 客户端随机 key，所以可完整复现。
package qoder

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// ─────────────────────────────────────────────────────────────
// 协议常量
// ─────────────────────────────────────────────────────────────

const (
	// AppCode 参与旧版签名（见 SignLegacy）。
	AppCode = "cosy"
	// SecretB64 是旧版签名的固定密钥。上游客户端把 base64("war, war never changes")
	// 写死在代码里 —— 这是社区实测出来的，不是我们编的。
	SecretB64 = "d2FyLCB3YXIgbmV2ZXIgY2hhbmdlcw=="

	// CosyVersion 参与 bearer payload 与 Cosy-Version 头。
	//
	// ⚠️ 这个常量决定上游下发哪套模型清单：旧版本（如 1.0.10）只能拿到较少模型，
	// 新版才会多出 Sonus / Cantus / Fast 三档。上游客户端升级时要跟。
	// 建议做成配置项而不是编译常量（见 Config.CosyVersion）。
	DefaultCosyVersion = "1.1.69"

	// ServerPubKeyPEM 是 Qoder 服务端公钥，用于包裹客户端随机 tempKey。
	// 它出现在官方客户端里，属于公开材料。
	ServerPubKeyPEM = `-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDA8iMH5c02LilrsERw9t6Pv5Nc
4k6Pz1EaDicBMpdpxKduSZu5OANqUq8er4GM95omAGIOPOh+Nx0spthYA2BqGz+l
6HRkPJ7S236FZz73In/KVuLnwI8JJ2CbuJap8kvheCCZpmAWpb/cPx/3Vr/J6I17
XcW+ML9FoCI6AOvOzwIDAQAB
-----END PUBLIC KEY-----`
)

// customAlphabet 是 body 编码用的自定义字母表（64 字符 + 填充符）。
const (
	customAlphabet = "_doRTgHZBKcGVjlvpC,@aFSx#DPuNJme&i*MzLOEn)sUrthbf%Y^w.(kIQyXqWA!"
	stdAlphabet    = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	customPad      = '$'
)

var (
	encodeMap [128]byte // std → custom
	decodeMap [128]int  // custom → std
)

func init() {
	for i := range decodeMap {
		decodeMap[i] = -1
	}
	for i := 0; i < 64; i++ {
		encodeMap[stdAlphabet[i]] = customAlphabet[i]
		decodeMap[customAlphabet[i]] = int(stdAlphabet[i])
	}
	encodeMap['='] = customPad
	decodeMap[customPad] = '='
}

// ─────────────────────────────────────────────────────────────
// body 编码
// ─────────────────────────────────────────────────────────────

// Encode 把明文编成上游要求的 body 形态：标准 base64 → 按 n/3 旋转 → 映射自定义字母表。
//
// 旋转方式是「尾 a 字节 + 中段 + 首 a 字节」，其中 a = n/3。这不是填充对齐，
// 纯粹是打乱字符分布。实现必须与上游逐字节一致，否则服务端解不出来 ——
// 表现为 400 而非签名失败，容易误判成参数问题。
func Encode(plaintext []byte) (string, error) {
	std := base64.StdEncoding.EncodeToString(plaintext)
	n := len(std)
	if n == 0 {
		return "", nil
	}
	a := n / 3
	rotated := std[n-a:] + std[a:n-a] + std[:a]

	out := make([]byte, n)
	for i := 0; i < n; i++ {
		c := int(rotated[i])
		if c >= 128 {
			return "", fmt.Errorf("qoder: 字符越界 %d", c)
		}
		if encodeMap[c] == 0 {
			return "", fmt.Errorf("qoder: 字符不在标准字母表 %d", c)
		}
		out[i] = encodeMap[c]
	}
	return string(out), nil
}

// Decode 逆运算；仅用于测试与排障（生产只发不接）。
func Decode(encoded string) ([]byte, error) {
	n := len(encoded)
	if n == 0 {
		return nil, nil
	}
	mapped := make([]byte, n)
	for i := 0; i < n; i++ {
		c := int(encoded[i])
		if c >= 128 || decodeMap[c] < 0 {
			return nil, fmt.Errorf("qoder: 字符不在自定义字母表 %d", c)
		}
		mapped[i] = byte(decodeMap[c])
	}
	a := n / 3
	std := string(mapped[n-a:]) + string(mapped[a:n-a]) + string(mapped[:a])
	return base64.StdEncoding.DecodeString(std)
}

// ─────────────────────────────────────────────────────────────
// 签名
// ─────────────────────────────────────────────────────────────

// SignLegacy 是旧版固定密钥签名：md5("cosy&<secret>&<date>")。
// 保留它是为了排障时能区分「旧路径还在用」还是「新签名算错了」。
func SignLegacy(date string) string {
	return md5Hex(AppCode + "&" + SecretB64 + "&" + date)
}

// SignRequest 是当前使用的请求签名。
//
// 输入是五段按固定顺序用 \n 拼接：bearer payload、cosyKey、Cosy-Date、body、去前缀 path。
// 顺序固定，任何一段变化都会改变结果。
//
// 注意 pathWithoutAlgo：上游签名时用的是**去掉 /algo 前缀**的路径，
// 直接用完整 URL path 会得到签名不匹配（服务端回 101）。
func SignRequest(payloadB64, cosyKey, cosyDate, body, pathWithoutAlgo string) string {
	joined := strings.Join([]string{payloadB64, cosyKey, cosyDate, body, pathWithoutAlgo}, "\n")
	return md5Hex(joined)
}

func md5Hex(s string) string {
	sum := md5.Sum([]byte(s))
	return fmt.Sprintf("%x", sum)
}

// CurrentDate 返回 Cosy-Date / Date 头要求的 RFC1123 GMT 形态。
//
// 上游把这个值一起签名，所以主机时钟必须准 —— 偏差过大会导致签名被拒。
func CurrentDate() string {
	return time.Now().UTC().Format("Mon, 02 Jan 2006 15:04:05 GMT")
}

// ─────────────────────────────────────────────────────────────
// 会话（bearer payload / info / cosyKey）
// ─────────────────────────────────────────────────────────────

// Identity 是放进 info（AES 加密后再 base64）的身份字段。
type Identity struct {
	Name               string
	AID                string
	UID                string
	YxUID              string
	OrganizationID     string
	OrganizationName   string
	UserType           string
	SecurityOauthToken string
	RefreshToken       string
}

// Session 是一次推理所需的加密材料。
type Session struct {
	CosyKey  string // RSA 包裹的 tempKey，base64
	Info     string // AES 加密的身份，base64
	Identity Identity
}

// NewSession 生成一次推理会话。
//
// 流程与上游客户端一致：
//  1. 随机 16 字节作 tempKey（取 hex 前 16 字符）
//  2. cosyKey = base64(RSA_PKCS1v15(服务端公钥, tempKey))
//  3. info    = base64(AES-128-CBC(tempKey, IV=tempKey, 身份JSON))
//
// tempKey 每次请求都换，所以同一账号连续两次请求的 Authorization 必然不同 ——
// 这是正常的，不要为此做缓存。
func NewSession(id Identity) (*Session, error) {
	rawKey := make([]byte, 16)
	if _, err := rand.Read(rawKey); err != nil {
		return nil, fmt.Errorf("qoder: 生成 tempKey 失败: %w", err)
	}
	tempKey := []byte(fmt.Sprintf("%x", rawKey)[:16])

	wrapped, err := rsaEncrypt(tempKey)
	if err != nil {
		return nil, err
	}

	plaintext, err := json.Marshal(map[string]string{
		"name":                 id.Name,
		"aid":                  id.AID,
		"uid":                  id.UID,
		"yx_uid":               id.YxUID,
		"organization_id":      id.OrganizationID,
		"organization_name":    id.OrganizationName,
		"user_type":            id.UserType,
		"security_oauth_token": id.SecurityOauthToken,
		"refresh_token":        id.RefreshToken,
	})
	if err != nil {
		return nil, err
	}

	ciphertext, err := aesEncrypt(plaintext, tempKey)
	if err != nil {
		return nil, err
	}

	return &Session{
		CosyKey:  base64.StdEncoding.EncodeToString(wrapped),
		Info:     base64.StdEncoding.EncodeToString(ciphertext),
		Identity: id,
	}, nil
}

// PayloadB64 生成 bearer 的第二段（base64 的 JSON 元数据）。
func (s *Session) PayloadB64(cosyVersion string) (string, error) {
	if cosyVersion == "" {
		cosyVersion = DefaultCosyVersion
	}
	requestID, err := newUUID()
	if err != nil {
		return "", err
	}
	raw, err := json.Marshal(map[string]string{
		"cosyVersion": cosyVersion,
		"ideVersion":  "",
		"info":        s.Info,
		"requestId":   requestID,
		"version":     "v1",
	})
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(raw), nil
}

// Bearer 组装 Authorization 头：`Bearer COSY.<payloadB64>.<sig>`。
func Bearer(payloadB64, sig string) string {
	return "Bearer COSY." + payloadB64 + "." + sig
}

func rsaEncrypt(plaintext []byte) ([]byte, error) {
	block, _ := pem.Decode([]byte(strings.ReplaceAll(ServerPubKeyPEM, "\r", "")))
	if block == nil {
		return nil, fmt.Errorf("qoder: 服务端公钥 PEM 解析失败")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("qoder: 公钥解析失败: %w", err)
	}
	rsaPub, ok := pub.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("qoder: 不是 RSA 公钥")
	}
	// PKCS#1 v1.5 与上游一致；换成 OAEP 会得到错误长度的 cosyKey。
	return rsa.EncryptPKCS1v15(rand.Reader, rsaPub, plaintext)
}

func aesEncrypt(plain, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	bs := block.BlockSize()
	pad := bs - len(plain)%bs
	padded := make([]byte, len(plain)+pad)
	copy(padded, plain)
	for i := len(plain); i < len(padded); i++ {
		padded[i] = byte(pad)
	}
	out := make([]byte, len(padded))
	// IV 取 key 本身 —— 上游就是这么做的（不是随机 IV）。
	// 这削弱了语义安全性，但我们必须与上游一致才能被解开。
	cipher.NewCBCEncrypter(block, key[:bs]).CryptBlocks(out, padded)
	return out, nil
}

// ─────────────────────────────────────────────────────────────
// 设备指纹
// ─────────────────────────────────────────────────────────────

// Fingerprint 是上游要求的三个设备标识。
//
// 关键认知：**它们不是真实硬件指纹**，而是由账号 uid 单向派生出来的稳定伪标识。
// 上游客户端从本地加密文件里读，但实测服务端并不校验其与硬件的对应关系，
// 只要求「同一账号长期一致」。所以我们可以派生。
//
// 这样做的两个好处：
//   - 同一账号永远来自同一台「虚拟设备」，不会因换机器触发风控
//   - 不同账号指纹天然不同，阻断跨账号关联
type Fingerprint struct {
	MachineID    string // 32 位十六进制
	MachineType  string // 18 位十六进制（md5 截断）
	MachineToken string // 43 字符 base64url（sha512 截断）
}

// DeriveFingerprint 由 uid 派生指纹。
//
// salt 用于隔离不同部署：纯 uid 派生的问题是「知道 uid 就能算出指纹，
// 且所有部署算出的一样」，上游若识别出该模式可全局封。加了部署私有盐后
// 每个部署有独立指纹空间。**盐一旦设定必须永久保持** —— 变更等于换设备。
func DeriveFingerprint(uid, salt string) Fingerprint {
	seed := func(purpose string) string {
		base := purpose + ":" + uid
		if salt != "" {
			base += "|salt:" + salt
		}
		return base
	}
	return Fingerprint{
		MachineID:    md5Hex(seed("machine")),
		MachineType:  md5Hex(seed("machinetype"))[:18],
		MachineToken: sha512B64URL(seed("machinetoken"))[:43],
	}
}

// ─────────────────────────────────────────────────────────────
// 小工具
// ─────────────────────────────────────────────────────────────

func newUUID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16]), nil
}

func sha512B64URL(s string) string {
	sum := sha512.Sum512([]byte(s))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// ExpireTimeMillis 把上游的毫秒时间戳转成 time.Time；0 表示未设置。
func ExpireTimeMillis(v string) (time.Time, bool) {
	if strings.TrimSpace(v) == "" {
		return time.Time{}, false
	}
	ms, err := strconv.ParseInt(strings.TrimSpace(v), 10, 64)
	if err != nil || ms <= 0 {
		return time.Time{}, false
	}
	return time.UnixMilli(ms), true
}
