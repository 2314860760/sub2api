package service

// Qoder 凭据续期。
//
// 上游续期端点：POST {openApiBase}/api/v1/deviceToken/refresh
// body {refresh_token, machine_id}，**不需要 Bearer**。
//
// 与 CodeBuddy 一样用单飞：refresh_token 是轮换式的，并发刷新会让先刷的那次作废。

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	cbQoder "github.com/Wei-Shaw/sub2api/internal/pkg/qoder"
)

const (
	// qoderRefreshSkew 提前多久续期（毫秒）。取 10 分钟。
	qoderRefreshSkewMillis = 10 * 60 * 1000
	// qoderRefreshPath 是续期端点。
	qoderRefreshPath = "/api/v1/deviceToken/refresh"
)

// QoderTokenProvider 负责把账号凭据变成可用的 access token。
type QoderTokenProvider struct {
	accountRepo AccountRepository

	mu      sync.Mutex
	pending map[int64]*qoderRefreshCall
}

type qoderRefreshCall struct {
	done chan struct{}
	auth *cbQoder.Credential
	err  error
}

func NewQoderTokenProvider(accountRepo AccountRepository) *QoderTokenProvider {
	return &QoderTokenProvider{
		accountRepo: accountRepo,
		pending:     map[int64]*qoderRefreshCall{},
	}
}

// GetCredential 返回可用凭据；必要时先续期。
func (p *QoderTokenProvider) GetCredential(ctx context.Context, account *Account, deploySalt string) (*cbQoder.Credential, error) {
	cred := account.GetQoderCredential(deploySalt)
	if cred == nil {
		return nil, ErrQoderNoCredential
	}
	if !account.QoderNeedsRefresh(qoderRefreshSkewMillis) {
		return cred, nil
	}
	return p.refresh(ctx, account, cred)
}

// refresh 单飞续期并写回。
func (p *QoderTokenProvider) refresh(ctx context.Context, account *Account, cred *cbQoder.Credential) (*cbQoder.Credential, error) {
	p.mu.Lock()
	if call, ok := p.pending[account.ID]; ok {
		p.mu.Unlock()
		select {
		case <-call.done:
			return call.auth, call.err
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	call := &qoderRefreshCall{done: make(chan struct{})}
	p.pending[account.ID] = call
	p.mu.Unlock()

	defer func() {
		p.mu.Lock()
		delete(p.pending, account.ID)
		p.mu.Unlock()
		close(call.done)
	}()

	token, refreshToken, expireMs, err := p.doRefresh(ctx, cred)
	if err != nil {
		call.err = err
		return nil, err
	}

	updated := *cred
	updated.SecurityOauthToken = token
	if refreshToken != "" {
		updated.RefreshToken = refreshToken
	}

	if p.accountRepo != nil && account.ID > 0 {
		creds := ApplyQoderRefresh(account, token, refreshToken, expireMs)
		if err := persistAccountCredentials(ctx, p.accountRepo, account, creds); err != nil {
			slog.Warn("qoder: 续期后写回凭据失败", "account_id", account.ID, "error", err)
		}
	}
	call.auth = &updated
	return &updated, nil
}

// doRefresh 调上游续期端点。
func (p *QoderTokenProvider) doRefresh(ctx context.Context, cred *cbQoder.Credential) (string, string, int64, error) {
	base := cbQoder.BaseGlobal
	if strings.EqualFold(cred.Realm, "cn") {
		base = "https://openapi.qoder.com.cn"
	} else {
		base = "https://openapi.qoder.sh"
	}

	body, _ := json.Marshal(map[string]string{
		"refresh_token": cred.RefreshToken,
		"machine_id":    cred.Fingerprint.MachineID,
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, base+qoderRefreshPath, strings.NewReader(string(body)))
	if err != nil {
		return "", "", 0, err
	}
	req.Header.Set("content-type", "application/json")
	req.Header.Set("accept", "application/json")

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", "", 0, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))

	if resp.StatusCode != http.StatusOK {
		return "", "", 0, fmt.Errorf("qoder: refresh %d: %s", resp.StatusCode, truncateForLog(raw, 200))
	}

	var out struct {
		AccessToken  string `json:"access_token"`
		DeviceToken  string `json:"device_token"`
		Token        string `json:"token"`
		RefreshToken string `json:"refresh_token"`
		ExpiresAt    int64  `json:"expires_at"`
		ExpireTime   int64  `json:"expire_time"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return "", "", 0, fmt.Errorf("qoder: 解析 refresh 响应失败: %w", err)
	}
	token := firstNonEmptyStr(out.AccessToken, out.DeviceToken, out.Token)
	if token == "" {
		return "", "", 0, fmt.Errorf("qoder: refresh 响应无 token，需重新登录: %s", truncateForLog(raw, 200))
	}
	expireMs := out.ExpireTime
	if expireMs == 0 {
		expireMs = out.ExpiresAt
	}
	if expireMs > 0 && expireMs < 1e12 {
		// 秒级时间戳换算成毫秒，避免把 1970 年当成有效期。
		expireMs *= 1000
	}
	return token, out.RefreshToken, expireMs, nil
}

func firstNonEmptyStr(values ...string) string {
	for _, v := range values {
		if s := strings.TrimSpace(v); s != "" {
			return s
		}
	}
	return ""
}


