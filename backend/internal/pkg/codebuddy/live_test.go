package codebuddy_test

// 活体测试：验证移植进 sub2api 的 codebuddy 包能真正打通上游。
//
// 默认跳过——它需要一份真实凭据，而凭据绝不能进仓库。
// 运行方式：
//
//	CODEBUDDY_AUTH_FILE=D:\path\to\workbuddy-xxx.json \
//	  go test ./internal/pkg/codebuddy/ -run TestLiveChat -v
//
// 这个测试存在的意义是"守卫移植本身"：如果上游改了协议、或我们把指纹相关的
// 代码改坏了，这里会先红，而不是等到 sub2api 上线后才从用户报障里发现。

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/pkg/codebuddy/auth"
	"github.com/Wei-Shaw/sub2api/internal/pkg/codebuddy/upstream"
)

func TestLiveChat(t *testing.T) {
	authFile := strings.TrimSpace(os.Getenv("CODEBUDDY_AUTH_FILE"))
	if authFile == "" {
		t.Skip("CODEBUDDY_AUTH_FILE 未设置；跳过活体测试")
	}

	raw, err := os.ReadFile(authFile)
	if err != nil {
		t.Fatalf("读凭据失败: %v", err)
	}
	a, err := auth.Parse(raw)
	if err != nil {
		t.Fatalf("解析凭据失败: %v", err)
	}
	t.Logf("账号 realm=%s uid=%s…", a.Realm(), firstN(a.UID, 8))

	// 用 New()：它装好 node TLS 指纹、header 顺序与两个 http.Client。
	// 手写 struct literal 会退化成 Go 原生 TLS，JA3 明显不同、大概率被风控。
	c := upstream.New()
	c.HeaderTimeout = 120 * time.Second
	c.IdleTimeout = 300 * time.Second

	if err := c.RefreshTokenIfNeeded(a, 3*time.Minute); err != nil {
		t.Logf("续期未执行（通常表示凭据仍有效）: %v", err)
	}

	body, _ := json.Marshal(map[string]any{
		"model": "deepseek-v4.1-flash",
		"messages": []map[string]any{
			{"role": "user", "content": "Reply with exactly: PONG"},
		},
		"max_tokens": 32,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Second)
	defer cancel()

	rc, status, respBody, err := c.ChatStreamContext(ctx, a, body, "127.0.0.1", upstream.ChatMeta{
		ConversationRequestID: "codebuddy-live-test",
	}, nil)
	if err != nil {
		t.Fatalf("上游请求失败 status=%d err=%v body=%s", status, err, firstN(string(respBody), 400))
	}
	defer rc.Close()

	if status != 200 {
		t.Fatalf("status=%d want 200", status)
	}

	// 上游只回 SSE；非流式结果由 Aggregate 聚合——与 handler 的非流式分支同一路径。
	resp, err := upstream.Aggregate(rc)
	if err != nil {
		t.Fatalf("聚合失败: %v", err)
	}

	out, _ := json.Marshal(resp)
	var parsed map[string]any
	if err := json.Unmarshal(out, &parsed); err != nil {
		t.Fatalf("响应不是合法 JSON: %v", err)
	}

	choices, _ := parsed["choices"].([]any)
	if len(choices) == 0 {
		t.Fatalf("响应无 choices: %s", firstN(string(out), 500))
	}
	c0, _ := choices[0].(map[string]any)
	msg, _ := c0["message"].(map[string]any)
	content, _ := msg["content"].(string)

	if strings.TrimSpace(content) == "" {
		t.Fatalf("正文为空（可能被内容策略拦截）: %s", firstN(string(out), 500))
	}
	t.Logf("回复=%q finish=%v", content, c0["finish_reason"])

	// usage 是计费与订阅额度消费的依据，必须存在。
	usage, ok := parsed["usage"].(map[string]any)
	if !ok {
		t.Fatalf("响应缺 usage，无法计费: %s", firstN(string(out), 500))
	}
	t.Logf("usage prompt=%v completion=%v cacheRead=%v",
		usage["prompt_tokens"], usage["completion_tokens"], usage["cache_read_input_tokens"])
}

func firstN(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
