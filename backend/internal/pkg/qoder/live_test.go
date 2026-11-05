package qoder_test

// 活体测试：验证签名与 payload 能被真实上游接受。
//
// 默认跳过 —— 需要真实凭据，而凭据绝不能进仓库。
//
//	CODEBUDDY_QODER_AUTH=<path to qoder auth json> \
//	  go test ./internal/pkg/qoder/ -run TestLiveInfer -v
//
// 这个测试的价值在于：签名算错不会返回「签名错误」之外的任何提示，
// 而 payload 缺字段会返回一段看起来像上游故障的 `Execution failed`。
// 只有真的打一次才能区分「我们写对了」和「我们以为写对了」。

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/pkg/qoder"
)

func TestLiveInfer(t *testing.T) {
	authFile := strings.TrimSpace(os.Getenv("CODEBUDDY_QODER_AUTH"))
	if authFile == "" {
		t.Skip("CODEBUDDY_QODER_AUTH 未设置；跳过活体测试")
	}

	raw, err := os.ReadFile(authFile)
	if err != nil {
		t.Fatalf("读凭据失败: %v", err)
	}
	var cred struct {
		SecurityOauthToken string `json:"security_oauth_token"`
		AccessToken        string `json:"access_token"`
		RefreshToken       string `json:"refresh_token"`
		MachineID          string `json:"machine_id"`
		UID                string `json:"uid"`
		Nickname           string `json:"nickname"`
	}
	if err := json.Unmarshal(raw, &cred); err != nil {
		t.Fatalf("解析凭据失败: %v", err)
	}
	t.Logf("账号 uid=%s… nickname=%s", first(cred.UID, 8), cred.Nickname)

	c := qoder.New()
	c.DeploySalt = "ofm-sub2api-local"

	body, _ := json.Marshal(map[string]any{
		"model": "qfmodel",
		"messages": []map[string]any{
			{"role": "user", "content": "Reply with exactly: PONG"},
		},
		"stream":     true,
		"max_tokens": 32,
	})

	// 上游按 (clienttype, version, product) 决定准入与模型清单。
	// 逐个试，把第一个 200 的组合打出来 —— 这比猜快，也比只试一种更有信息量。
	variants := []struct {
		name   string
		modern bool
		realm  string
	}{
		{"旧协议 clienttype=5 / 1.0.10 / ide", false, "cn"},
		{"新协议 clienttype=10 / 1.1.69 / app", true, "cn"},
		{"新协议 + global 站点", true, "global"},
		{"旧协议 + global 站点", false, "global"},
	}

	for _, v := range variants {
		t.Run(v.name, func(t *testing.T) {
			qc := &qoder.Credential{
				SecurityOauthToken: cred.SecurityOauthToken,
				UID:                cred.UID,
				Name:               cred.Nickname,
				Realm:              v.realm,
				ModernProtocol:     v.modern,
				Fingerprint:        qoder.DeriveFingerprint(cred.UID, c.DeploySalt),
			}
			ctx, cancel := context.WithTimeout(context.Background(), 8*time.Minute)
			defer cancel()

			rc, status, err := c.ChatStream(ctx, qc, body, "qfmodel")
			if err != nil {
				t.Logf("%s → status=%d err=%v", qc.InferURL(), status, err)
				return
			}
			defer rc.Close()

			buf := make([]byte, 8192)
			n, _ := rc.Read(buf)
			head := string(buf[:n])

			if strings.Contains(head, `"error"`) {
				t.Logf("%s → 错误帧: %s", qc.InferURL(), first(head, 300))
				return
			}
			if strings.Contains(head, "data:") {
				t.Logf("✅ 成功！%s\n%s", qc.InferURL(), first(head, 600))
			} else {
				t.Logf("非 SSE 响应: %s", first(head, 300))
			}
		})
	}
}

func first(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

var _ = fmt.Sprintf
var _ = io.Discard
