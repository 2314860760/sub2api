package qoder_test

// 签名正确性的判定性测试。
//
// 用 model/list 而不是 infer 来验证签名，理由很实在：
//
//   - model/list **不消耗推理计费**，可以反复跑
//   - infer 被拒的原因有四种（签名错 / 无权益 / 当日计费耗尽 / 模型排队），
//     只看 infer 的错误无法区分是哪一种
//
// 社区实现在同一凭据上 model/list 拿到过 51 KB 目录，所以这条路径
// 通了就等于签名通了。

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/pkg/qoder"
)

func loadQoderCred(t *testing.T) (*qoder.Client, *qoder.Credential) {
	t.Helper()
	authFile := strings.TrimSpace(os.Getenv("CODEBUDDY_QODER_AUTH"))
	if authFile == "" {
		t.Skip("CODEBUDDY_QODER_AUTH 未设置")
	}
	raw, err := os.ReadFile(authFile)
	if err != nil {
		t.Fatalf("读凭据失败: %v", err)
	}
	var c struct {
		SecurityOauthToken string `json:"security_oauth_token"`
		UID                string `json:"uid"`
		Nickname           string `json:"nickname"`
	}
	if err := json.Unmarshal(raw, &c); err != nil {
		t.Fatalf("解析凭据失败: %v", err)
	}

	cl := qoder.New()
	cl.DeploySalt = "ofm-sub2api-local"
	cred := &qoder.Credential{
		SecurityOauthToken: c.SecurityOauthToken,
		UID:                c.UID,
		Name:               c.Nickname,
		Realm:              "cn",
		Fingerprint:        qoder.DeriveFingerprint(c.UID, cl.DeploySalt),
	}
	return cl, cred
}

// TestLiveModelListIsSignatureProbe 判定签名是否正确。
//
// 通过 → 签名/编码/加密全部正确，infer 的任何失败都与 crypto 无关。
// 失败 → 签名或头构造有问题，报错里会带状态码。
func TestLiveModelListIsSignatureProbe(t *testing.T) {
	cl, cred := loadQoderCred(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	models, err := cl.FetchModels(ctx, cred)
	if err != nil {
		t.Fatalf("model/list 失败（签名可能不对）: %v", err)
	}
	if len(models) == 0 {
		t.Fatal("目录为空")
	}
	t.Logf("✅ 签名验证通过：拿到 %d 个模型", len(models))

	free, busy, total := 0, 0, len(models)
	for _, m := range models {
		if m.IsFree {
			free++
		}
		if m.Status == "busy" {
			busy++
		}
	}
	t.Logf("其中免费 %d 个、busy %d 个", free, busy)

	for _, m := range models {
		if m.Key == "qfmodel" {
			t.Logf("qfmodel: status=%s price=%v free=%v maxInput=%d", m.Status, m.PriceFactor, m.IsFree, m.MaxInputTokens)
		}
	}
	if total < 5 {
		t.Errorf("模型数偏少（%d），可能只拿到了部分目录", total)
	}
}
