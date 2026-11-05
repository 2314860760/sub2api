package trae_test

// 渠道探测：逐个 function 发一次最小推理，找出该账号真正可调用的渠道。
//
// 为什么需要它：上游的模型目录接口（batch_get_detail_param）对某些账号返回
// 2001 Config detail not found（目录未下发），但推理仍然可用。
// 这时唯一可靠的判断方式是**实际调一次**。
//
//	CODEBUDDY_TRAE_AUTH=<path to trae auth json> \
//	  go test ./internal/pkg/trae/ -run TestLiveProbeChannels -v
//
// 输出是一张「function → 是否可调用」的表，可直接用于配置默认渠道。

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/pkg/trae"
)

// callableChannels 是 OFM 实测可调用的 15 个渠道（见 trae-product.ts 注释）。
var callableChannels = []string{
	"solo_agent", "solo_work_lite", "solo_agent_remote", "solo_work_remote",
	"solo_agent_lite", "solo_design_lite", "solo_design_remote", "solo_coder",
	"chat_v3", "builder_v3", "git_ai", "code_reviewer", "code_review_summary",
	"multimodal", "system_diagnosis",
}

func TestLiveProbeChannels(t *testing.T) {
	authFile := strings.TrimSpace(os.Getenv("CODEBUDDY_TRAE_AUTH"))
	if authFile == "" {
		t.Skip("CODEBUDDY_TRAE_AUTH 未设置")
	}
	raw, err := os.ReadFile(authFile)
	if err != nil {
		t.Fatalf("读凭据失败: %v", err)
	}
	var c struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		UID          string `json:"uid"`
		MachineID    string `json:"machine_id"`
		DeviceID     string `json:"device_id"`
		Nickname     string `json:"nickname"`
	}
	if err := json.Unmarshal(raw, &c); err != nil {
		t.Fatalf("解析凭据失败: %v", err)
	}

	model := os.Getenv("CODEBUDDY_TRAE_MODEL")
	if model == "" {
		model = "deepseek-v4.1-flash"
	}
	body, _ := json.Marshal(map[string]any{
		"model":      model,
		"messages":   []map[string]any{{"role": "user", "content": "hi"}},
		"max_tokens": 16,
	})

	cl := trae.New()
	cl.DeploySalt = "ofm-sub2api-local"

	// 每个渠道单独一个 client 拷贝，通过改写 payload 的 function 字段探测。
	// pkg/trae 目前把 function 写死为 DefaultFunction，所以这里直接构造请求。
	results := make(map[string]string)
	var mu sync.Mutex
	var wg sync.WaitGroup

	for _, ch := range callableChannels {
		wg.Add(1)
		go func(channel string) {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
			defer cancel()

			cred := &trae.Credential{
				AccessToken: c.AccessToken,
				UID:         c.UID,
				Nickname:    c.Nickname,
				MachineID:   trae.NormalizeHex32(c.MachineID),
				DeviceID:    trae.NormalizeHex32(c.DeviceID),
				Realm:       "cn",
			}
			err := trae.ProbeChannel(ctx, cl, cred, body, model, channel)
			mu.Lock()
			if err != nil {
				results[channel] = "✗ " + truncate(err.Error(), 90)
			} else {
				results[channel] = "✅ 可调用"
			}
			mu.Unlock()
		}(ch)
	}
	wg.Wait()

	ok := 0
	for _, ch := range callableChannels {
		t.Logf("%-22s %s", ch, results[ch])
		if strings.HasPrefix(results[ch], "✅") {
			ok++
		}
	}
	t.Logf("\n合计：%d/%d 可调用", ok, len(callableChannels))
	if ok == 0 {
		t.Error("没有任何渠道可调用 —— 检查凭据或账号权益")
	}
}

func truncate(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
