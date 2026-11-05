package qoder

import (
	"encoding/base64"
	"strings"
	"testing"
)

// ─────────────────────────────────────────────────────────────
// body 编码
// ─────────────────────────────────────────────────────────────

func TestEncodeDecodeRoundTrip(t *testing.T) {
	cases := [][]byte{
		[]byte(`{"model":"qfmodel","messages":[{"role":"user","content":"hi"}]}`),
		[]byte(`a`),
		[]byte(`ab`),
		[]byte(`abc`),
		[]byte(`{"nested":{"deep":[1,2,3]},"unicode":"中文测试"}`),
		{},
	}
	for _, plain := range cases {
		encoded, err := Encode(plain)
		if err != nil {
			t.Fatalf("Encode(%q) 失败: %v", plain, err)
		}
		got, err := Decode(encoded)
		if err != nil {
			t.Fatalf("Decode(%q) 失败: %v", encoded, err)
		}
		if string(got) != string(plain) {
			t.Errorf("round-trip 不一致: %q → %q → %q", plain, encoded, got)
		}
	}
}

// TestEncodeUsesCustomAlphabet 钉住编码产物只含自定义字母表。
//
// OFM 侧观察到的 body 字母表恰是 `* # , ) . % ^ $ (` 这批字符，
// 它们都来自 customAlphabet。如果实现漂移成标准 base64，
// 上游会解不出来、回 400，但报错信息完全指不到编码层。
func TestEncodeUsesCustomAlphabet(t *testing.T) {
	plain := []byte(`{"model":"qfmodel","stream":true,"messages":[{"role":"user","content":"hello world"}]}`)
	encoded, err := Encode(plain)
	if err != nil {
		t.Fatal(err)
	}
	allowed := map[byte]bool{}
	for i := 0; i < len(customAlphabet); i++ {
		allowed[customAlphabet[i]] = true
	}
	allowed[customPad] = true

	for i := 0; i < len(encoded); i++ {
		if !allowed[encoded[i]] {
			t.Fatalf("位置 %d 出现字母表外字符 %q（编码=%q）", i, encoded[i], encoded)
		}
	}
	// 标准 base64 的 '+' '/' '=' 绝不能出现（除填充符被换成 $）。
	if strings.ContainsAny(encoded, "+/=") {
		t.Errorf("编码结果含标准 base64 字符: %q", encoded)
	}
}

func TestEncodeIsDeterministic(t *testing.T) {
	plain := []byte(`{"a":1}`)
	a, _ := Encode(plain)
	b, _ := Encode(plain)
	if a != b {
		t.Errorf("同一输入两次编码不同: %q vs %q", a, b)
	}
}

func TestDecodeRejectsForeignChars(t *testing.T) {
	// 标准 base64 字符 '+' 不在自定义字母表内。
	if _, err := Decode("abc+def"); err == nil {
		t.Error("含字母表外字符时应报错")
	}
}

// ─────────────────────────────────────────────────────────────
// 签名
// ─────────────────────────────────────────────────────────────

func TestSignRequestIsDeterministic(t *testing.T) {
	args := []string{"payload", "key", "Mon, 05 Nov 2026 00:00:00 GMT", `{"a":1}`, "/api/v2/service/pro/sse/agent_chat_generation"}
	first := SignRequest(args[0], args[1], args[2], args[3], args[4])
	second := SignRequest(args[0], args[1], args[2], args[3], args[4])
	if first != second {
		t.Error("同输入签名应确定")
	}
	if len(first) != 32 {
		t.Errorf("MD5 hex 应 32 字符，得到 %d: %q", len(first), first)
	}
}

// TestSignRequestCoversEveryPart 逐段扰动，确认每一段都参与签名。
//
// 这条防的是「少拼一段但测试仍通过」—— 少拼 path 或 body 会得到
// 长度正确的错签名，上游回 101 Signature invalid，很难定位。
func TestSignRequestCoversEveryPart(t *testing.T) {
	base := []string{"p", "k", "d", "b", "/x"}
	want := SignRequest(base[0], base[1], base[2], base[3], base[4])
	for i := range base {
		mutated := append([]string{}, base...)
		mutated[i] += "X"
		if got := SignRequest(mutated[0], mutated[1], mutated[2], mutated[3], mutated[4]); got == want {
			t.Errorf("第 %d 段未参与签名", i)
		}
	}
}

func TestSignLegacyMatchesFormula(t *testing.T) {
	date := "Mon, 05 Nov 2026 00:00:00 GMT"
	want := md5Hex("cosy&" + SecretB64 + "&" + date)
	if got := SignLegacy(date); got != want {
		t.Errorf("SignLegacy = %q, want %q", got, want)
	}
	// 密钥确实是 base64("war, war never changes")
	decoded, err := base64.StdEncoding.DecodeString(SecretB64)
	if err != nil {
		t.Fatal(err)
	}
	if string(decoded) != "war, war never changes" {
		t.Errorf("SecretB64 解出 %q", decoded)
	}
}

// ─────────────────────────────────────────────────────────────
// 会话
// ─────────────────────────────────────────────────────────────

// TestSessionBlobSizes 交叉验证 OFM WASM 的实测值。
//
// 调研时在 Node 里跑 OFM 那个 wasm，观测到 generate_runtime_auth_fields 返回
// 两个字段 `encrypt_user_info` 与 `key` 各 **172 个 base64 字符**。
// 172 字符 = 128 字节，正是 1024 位 RSA 的输出长度。
// 这里验证我们的 cosyKey 同长 —— 说明 RSA 位长与填充方式与上游一致。
func TestSessionBlobSizes(t *testing.T) {
	s, err := NewSession(Identity{
		Name: "tester", UID: "u_1", AID: "a_1",
		SecurityOauthToken: "tok", RefreshToken: "rt",
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(s.CosyKey) != 172 {
		t.Errorf("cosyKey 应 172 base64 字符（128 字节 RSA），得到 %d", len(s.CosyKey))
	}
	raw, err := base64.StdEncoding.DecodeString(s.CosyKey)
	if err != nil {
		t.Fatalf("cosyKey 不是合法 base64: %v", err)
	}
	if len(raw) != 128 {
		t.Errorf("cosyKey 解码后应 128 字节，得到 %d", len(raw))
	}
	// info 是 AES-CBC 密文，长度必须是 16 的整数倍。
	infoRaw, err := base64.StdEncoding.DecodeString(s.Info)
	if err != nil {
		t.Fatalf("info 不是合法 base64: %v", err)
	}
	if len(infoRaw)%16 != 0 {
		t.Errorf("info 密文长度 %d 不是 16 的倍数（CBC 特征）", len(infoRaw))
	}
}

func TestSessionIsFreshPerCall(t *testing.T) {
	// tempKey 每次随机 → 同一账号两次会话的 cosyKey/info 必然不同。
	// 若相同，说明 tempKey 被复用了（上游会拒绝或降级）。
	id := Identity{UID: "u", SecurityOauthToken: "t"}
	a, _ := NewSession(id)
	b, _ := NewSession(id)
	if a.CosyKey == b.CosyKey {
		t.Error("cosyKey 两次相同，tempKey 可能未随机")
	}
	if a.Info == b.Info {
		t.Error("info 两次相同，tempKey 可能未随机")
	}
}

func TestPayloadB64Shape(t *testing.T) {
	s, err := NewSession(Identity{UID: "u", SecurityOauthToken: "t"})
	if err != nil {
		t.Fatal(err)
	}
	payload, err := s.PayloadB64("")
	if err != nil {
		t.Fatal(err)
	}
	raw, err := base64.StdEncoding.DecodeString(payload)
	if err != nil {
		t.Fatalf("payload 不是合法 base64: %v", err)
	}
	for _, want := range []string{`"version":"v1"`, `"cosyVersion":"1.1.69"`, `"requestId"`, `"info"`, `"ideVersion"`} {
		if !strings.Contains(string(raw), want) {
			t.Errorf("payload 缺字段 %s: %s", want, raw)
		}
	}
}

func TestBearerFormat(t *testing.T) {
	got := Bearer("PAYLOAD", "SIG")
	if got != "Bearer COSY.PAYLOAD.SIG" {
		t.Errorf("Bearer 形态错误: %q", got)
	}
}

// ─────────────────────────────────────────────────────────────
// 指纹
// ─────────────────────────────────────────────────────────────

func TestDeriveFingerprintShape(t *testing.T) {
	fp := DeriveFingerprint("038f88b1-aaaa-bbbb-cccc-1234567890ab", "")
	if len(fp.MachineID) != 32 {
		t.Errorf("MachineID 应 32 位十六进制，得到 %d: %q", len(fp.MachineID), fp.MachineID)
	}
	if len(fp.MachineType) != 18 {
		t.Errorf("MachineType 应 18 位，得到 %d: %q", len(fp.MachineType), fp.MachineType)
	}
	if len(fp.MachineToken) != 43 {
		t.Errorf("MachineToken 应 43 字符，得到 %d: %q", len(fp.MachineToken), fp.MachineToken)
	}
	// MachineType 是 MachineID 同族派生，但两者不应相同（purpose 不同）。
	if fp.MachineID[:18] == fp.MachineType {
		t.Error("MachineType 与 MachineID 前 18 位相同，purpose 可能未参与派生")
	}
}

func TestDeriveFingerprintStable(t *testing.T) {
	uid := "u-stable"
	a := DeriveFingerprint(uid, "")
	b := DeriveFingerprint(uid, "")
	if a != b {
		t.Error("同一 uid 应派生同一指纹")
	}
}

func TestDeriveFingerprintIsolatesAccountsAndDeployments(t *testing.T) {
	a := DeriveFingerprint("uid-a", "")
	b := DeriveFingerprint("uid-b", "")
	if a.MachineID == b.MachineID {
		t.Error("不同 uid 不应派生同一指纹")
	}
	// 加盐后必须与无盐不同，否则盐没生效（且不同部署会撞同一指纹空间）。
	salted := DeriveFingerprint("uid-a", "deploy-secret")
	if salted.MachineID == a.MachineID {
		t.Error("加盐后指纹未变化")
	}
}

func TestDeriveFingerprintAllHex(t *testing.T) {
	fp := DeriveFingerprint("u", "")
	for _, s := range []string{fp.MachineID, fp.MachineType} {
		for _, r := range s {
			if !strings.ContainsRune("0123456789abcdef", r) {
				t.Fatalf("非十六进制字符 %q in %q", r, s)
			}
		}
	}
}

// ─────────────────────────────────────────────────────────────
// 时间
// ─────────────────────────────────────────────────────────────

func TestExpireTimeMillis(t *testing.T) {
	got, ok := ExpireTimeMillis("1795363323000")
	if !ok {
		t.Fatal("应解析成功")
	}
	if got.Year() < 2026 {
		t.Errorf("年份异常: %v", got)
	}
	for _, bad := range []string{"", "  ", "abc", "0", "-1"} {
		if _, ok := ExpireTimeMillis(bad); ok {
			t.Errorf("%q 不应解析成功", bad)
		}
	}
}

func TestCurrentDateFormat(t *testing.T) {
	d := CurrentDate()
	if !strings.HasSuffix(d, " GMT") {
		t.Errorf("Cosy-Date 必须以 GMT 结尾: %q", d)
	}
	// RFC1123 固定长度：Mon, 02 Jan 2006 15:04:05 GMT = 29 字符
	if len(d) != 29 {
		t.Errorf("长度应 29，得到 %d: %q", len(d), d)
	}
}
