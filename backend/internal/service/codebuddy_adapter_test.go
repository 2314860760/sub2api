package service

// CodeBuddy 适配层的纯逻辑测试。
//
// 只测不需要网络的路径：凭据映射、续期判定、usage 解析、尾部缓冲。
// 真实上游的连通性由 pkg/codebuddy/live_test.go 守卫（需 CODEBUDDY_AUTH_FILE）。

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	cbAuth "github.com/Wei-Shaw/sub2api/internal/pkg/codebuddy/auth"
)

// ---- 凭据映射 ----

func codeBuddyTestAccount(creds map[string]any) *Account {
	return &Account{
		ID:          42,
		Platform:    PlatformCodeBuddy,
		Type:        AccountTypeAPIKey,
		Credentials: creds,
	}
}

func TestGetCodeBuddyAuthMapsAllFields(t *testing.T) {
	a := codeBuddyTestAccount(map[string]any{
		"access_token":  "AT-value",
		"refresh_token": "RT-value",
		"expires_at":    "1795590185",
		"realm":         "cn",
		"uid":           "038f88b1-aaaa",
		"enterprise_id": "ent-1",
		"nickname":      "tester",
		"device_token":  "dev-tok",
		"domain":        "www.codebuddy.cn",
	})
	got := a.GetCodeBuddyAuth()
	if got == nil {
		t.Fatal("GetCodeBuddyAuth 返回 nil")
	}
	if got.AccessToken != "AT-value" || got.RefreshToken != "RT-value" {
		t.Errorf("token 映射错误: %+v", got)
	}
	if got.ExpiresAt != 1795590185 {
		t.Errorf("expires_at = %d, want 1795590185", got.ExpiresAt)
	}
	if got.UID != "038f88b1-aaaa" || got.EnterpriseID != "ent-1" || got.Nickname != "tester" {
		t.Errorf("账号字段映射错误: %+v", got)
	}
	if got.DeviceToken != "dev-tok" {
		t.Errorf("device_token = %q", got.DeviceToken)
	}
	// realm 决定上游域名，是最不能丢的字段。
	if got.Realm() != "cn" {
		t.Errorf("realm = %q, want cn", got.Realm())
	}
}

func TestGetCodeBuddyAuthRealmGlobal(t *testing.T) {
	a := codeBuddyTestAccount(map[string]any{
		"access_token": "AT",
		"realm":        "global",
		"uid":          "2e1e9d7f-bbbb",
	})
	if got := a.GetCodeBuddyAuth(); got == nil || got.Realm() != "global" {
		t.Fatalf("realm 应为 global，得到 %+v", got)
	}
}

func TestGetCodeBuddyAuthMissingAccessToken(t *testing.T) {
	for name, creds := range map[string]map[string]any{
		"nil credentials": nil,
		"empty":           {},
		"only refresh":    {"refresh_token": "RT"},
		"blank token":     {"access_token": "   "},
	} {
		t.Run(name, func(t *testing.T) {
			if got := codeBuddyTestAccount(creds).GetCodeBuddyAuth(); got != nil {
				t.Errorf("缺 access_token 应返回 nil，得到 %+v", got)
			}
		})
	}
}

func TestGetCodeBuddyAuthBadExpiresAtIsZero(t *testing.T) {
	// 无法解析的 expires_at 按 0 处理（视作已过期）→ 触发一次续期，
	// 而不是当成"永不过期"把坏数据带进上游。
	a := codeBuddyTestAccount(map[string]any{"access_token": "AT", "expires_at": "not-a-number"})
	if got := a.GetCodeBuddyAuth(); got == nil || got.ExpiresAt != 0 {
		t.Fatalf("ExpiresAt 应为 0，得到 %+v", got)
	}
}

func TestApplyCodeBuddyAuthKeepsUnrelatedKeys(t *testing.T) {
	a := codeBuddyTestAccount(map[string]any{
		"access_token":  "old",
		"model_mapping": map[string]any{"x": "y"},
	})
	next := ApplyCodeBuddyAuth(a, nil)
	if _, ok := next["model_mapping"]; !ok {
		t.Error("写回凭据不应丢掉 model_mapping 等无关键")
	}
}

// ---- 续期判定 ----

func TestCodeBuddyNeedsRefresh(t *testing.T) {
	now := time.Now()
	cases := []struct {
		name        string
		refreshTok  string
		expiresAt   int64
		wantRefresh bool
	}{
		{"无 refresh_token 永不续期", "", now.Add(time.Hour).Unix(), false},
		{"不在提前量内", "RT", now.Add(time.Hour).Unix(), false},
		{"进入提前量内", "RT", now.Add(5 * time.Minute).Unix(), true},
		{"已过期", "RT", now.Add(-time.Hour).Unix(), true},
		{"无有效期但有 refresh_token", "RT", 0, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a := codeBuddyTestAuth(tc.refreshTok, tc.expiresAt)
			if got := codeBuddyNeedsRefresh(a, codeBuddyRefreshSkew); got != tc.wantRefresh {
				t.Errorf("needsRefresh = %v, want %v", got, tc.wantRefresh)
			}
		})
	}
}

// ---- usage 解析（重复计费防护）----

func TestParseCodeBuddyUsageSubtractsCacheReadFromInput(t *testing.T) {
	// 上游把 prompt_tokens 定义为**含缓存**的总量。若不扣减，
	// 同一批 token 会既按 input 计费又按 cache read 计费——重复收一遍。
	payload := []byte(`{"usage":{
		"prompt_tokens":1000,
		"completion_tokens":200,
		"prompt_tokens_details":{"cached_tokens":800},
		"cache_read_input_tokens":800,
		"cache_creation_input_tokens":0
	}}`)
	got := parseCodeBuddyUsage(payload)
	if got.InputTokens != 200 {
		t.Errorf("InputTokens = %d, want 200（1000 含 800 命中，需扣减）", got.InputTokens)
	}
	if got.CacheReadInputTokens != 800 {
		t.Errorf("CacheReadInputTokens = %d, want 800", got.CacheReadInputTokens)
	}
	if got.OutputTokens != 200 {
		t.Errorf("OutputTokens = %d, want 200", got.OutputTokens)
	}
}

func TestParseCodeBuddyUsageNoCache(t *testing.T) {
	payload := []byte(`{"usage":{"prompt_tokens":36,"completion_tokens":11}}`)
	got := parseCodeBuddyUsage(payload)
	if got.InputTokens != 36 || got.OutputTokens != 11 || got.CacheReadInputTokens != 0 {
		t.Errorf("无缓存场景解析错误: %+v", got)
	}
}

func TestParseCodeBuddyUsageMissingUsage(t *testing.T) {
	for _, payload := range []string{`{}`, `{"usage":null}`, `{"usage":{}}`, `not json`} {
		if got := parseCodeBuddyUsage([]byte(payload)); got != (ClaudeUsage{}) {
			t.Errorf("payload=%q 应返回零值，得到 %+v", payload, got)
		}
	}
}

func TestParseCodeBuddyUsageCacheReadExceedsInputIsClamped(t *testing.T) {
	// 脏数据防护：命中量大于总量时不能算出负的 InputTokens。
	payload := []byte(`{"usage":{"prompt_tokens":10,"completion_tokens":1,
		"prompt_tokens_details":{"cached_tokens":50},"cache_read_input_tokens":50}}`)
	if got := parseCodeBuddyUsage(payload); got.InputTokens != 0 {
		t.Errorf("InputTokens 应为 0（钳到非负），得到 %d", got.InputTokens)
	}
}

// ---- 流式 usage 提取 ----

func TestParseCodeBuddyStreamUsageFindsLastFrame(t *testing.T) {
	// 还原上游真实的帧序：心跳注释帧、途中 usage:null、末帧带 usage。
	stream := strings.Join([]string{
		": heartbeat",
		``,
		`data: {"choices":[{"delta":{"content":"P"},"finish_reason":""}],"usage":null}`,
		``,
		`data: {"choices":[{"delta":{"content":"ONG"},"finish_reason":""}],"usage":null}`,
		``,
		`data: {"choices":[{"delta":{},"finish_reason":"stop"}],"usage":{"prompt_tokens":36,"completion_tokens":11,"prompt_tokens_details":{"cached_tokens":0}}}`,
		``,
		`data: [DONE]`,
		``,
	}, "\n")
	got := parseCodeBuddyStreamUsage([]byte(stream))
	if got.InputTokens != 36 || got.OutputTokens != 11 {
		t.Errorf("流式 usage 解析错误: %+v", got)
	}
}

func TestParseCodeBuddyStreamUsageTruncatedTail(t *testing.T) {
	// 尾部缓冲可能把末帧切成半个 JSON；不能因此 panic 或误报，应往前找可解析的帧。
	stream := `data: {"usage":{"prompt_tokens":10,"completion_tokens":2}}` + "\n\n" +
		`data: {"usage":{"prompt_tok`
	got := parseCodeBuddyStreamUsage([]byte(stream))
	if got.InputTokens != 10 || got.OutputTokens != 2 {
		t.Errorf("应回退到可解析的前一帧，得到 %+v", got)
	}
}

func TestTailBufferKeepsOnlyTail(t *testing.T) {
	buf := newCodeBuddyTailBuffer(8)
	buf.Write([]byte("aaaa"))
	buf.Write([]byte("bbbb"))
	buf.Write([]byte("cccc"))
	if got := string(buf.Bytes()); got != "bbbbcccc" {
		t.Errorf("尾部缓冲 = %q, want bbbbcccc", got)
	}
	if len(buf.Bytes()) != 8 {
		t.Errorf("长度 = %d, want 8", len(buf.Bytes()))
	}
}

func TestTailBufferZeroSizeDefaults(t *testing.T) {
	buf := newCodeBuddyTailBuffer(0)
	if buf.size <= 0 {
		t.Error("size<=0 应回落到默认值")
	}
}

// ---- 模型映射 ----

func TestReplaceJSONModelOnlyTouchesModel(t *testing.T) {
	body := []byte(`{"model":"cn:foo","messages":[{"role":"user","content":"hi"}],"max_tokens":8}`)
	out := replaceJSONModel(body, "foo")
	var obj map[string]any
	if err := json.Unmarshal(out, &obj); err != nil {
		t.Fatalf("输出不是合法 JSON: %v", err)
	}
	if obj["model"] != "foo" {
		t.Errorf("model = %v, want foo", obj["model"])
	}
	if obj["max_tokens"] != float64(8) {
		t.Errorf("max_tokens 被改动: %v", obj["max_tokens"])
	}
	msgs, _ := obj["messages"].([]any)
	if len(msgs) != 1 {
		t.Errorf("messages 被改动: %v", obj["messages"])
	}
}

func TestReplaceJSONModelInvalidBodyUnchanged(t *testing.T) {
	body := []byte(`not json`)
	if got := replaceJSONModel(body, "foo"); string(got) != string(body) {
		t.Error("非法 JSON 应原样返回")
	}
}

func TestBuildCodeBuddyRequestIDUnique(t *testing.T) {
	a, b := buildCodeBuddyRequestID(), buildCodeBuddyRequestID()
	if a == b {
		t.Errorf("请求 ID 应唯一: %s == %s", a, b)
	}
	if !strings.HasPrefix(a, "cb-") {
		t.Errorf("请求 ID 前缀异常: %s", a)
	}
}

// codeBuddyTestAuth 构造测试用 Auth。
//
// realm 是未导出字段，只能经上游的 Parse 写入——所以走它自己的扁平形态 JSON，
// 而不是结构体字面量。这样测试同时也钉住了"扁平形态可解析"这个前提。
func codeBuddyTestAuth(refreshToken string, expiresAt int64) *cbAuth.Auth {
	raw := map[string]any{
		"accessToken":  "AT",
		"refreshToken": refreshToken,
		"expiresAt":    expiresAt,
		"realm":        "cn",
		"uid":          "uid-test",
	}
	encoded, err := json.Marshal(raw)
	if err != nil {
		panic(err)
	}
	a, err := cbAuth.Parse(encoded)
	if err != nil {
		panic(err)
	}
	return a
}
