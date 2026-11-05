package service

// Trae 凭据续期。
//
// 上游续期端点：POST {base}/cloudide/api/v3/trae/oauth/ExchangeToken
// body {ClientID, RefreshToken, ClientSecret:"-", UserID:""}，**不带认证头**。
//
// 单飞是必需的：refresh_token 轮换式，并发刷新会让先刷的那次作废，
// 表现为随机的 401。

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	cbTrae "github.com/Wei-Shaw/sub2api/internal/pkg/trae"
)

const (
	traeRefreshSkew = 30 * time.Minute
	// traeRefreshSeconds 是给上游的 ClientSecret 占位值（官方客户端就是 "-"）。
	traeClientSecret = "-"
)

// TraeTokenProvider 负责把账号凭据变成可用的 access token。
type TraeTokenProvider struct {
	accountRepo AccountRepository

	mu      sync.Mutex
	pending map[int64]*traeRefreshCall
}

type traeRefreshCall struct {
	done chan struct{}
	auth *cbTrae.Credential
	err  error
}

func NewTraeTokenProvider(accountRepo AccountRepository) *TraeTokenProvider {
	return &TraeTokenProvider{
		accountRepo: accountRepo,
		pending:     map[int64]*traeRefreshCall{},
	}
}

// GetCredential 返回可用凭据；必要时先续期。
func (p *TraeTokenProvider) GetCredential(ctx context.Context, account *Account, deploySalt string) (*cbTrae.Credential, error) {
	cred := account.GetTraeCredential(deploySalt)
	if cred == nil {
		return nil, ErrTraeNoCredential
	}
	if !account.TraeNeedsRefresh(traeRefreshSkew) {
		return cred, nil
	}
	return p.refresh(ctx, account, cred)
}

func (p *TraeTokenProvider) refresh(ctx context.Context, account *Account, cred *cbTrae.Credential) (*cbTrae.Credential, error) {
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
	call := &traeRefreshCall{done: make(chan struct{})}
	p.pending[account.ID] = call
	p.mu.Unlock()

	defer func() {
		p.mu.Lock()
		delete(p.pending, account.ID)
		p.mu.Unlock()
		close(call.done)
	}()

	access, refresh, expiresAt, err := p.doRefresh(ctx, cred)
	if err != nil {
		call.err = err
		return nil, err
	}

	updated := *cred
	updated.AccessToken = access
	if refresh != "" {
		updated.RefreshToken = refresh
	}
	updated.ExpiresAt = expiresAt

	if p.accountRepo != nil && account.ID > 0 {
		creds := ApplyTraeRefresh(account, access, refresh, expiresAt)
		if err := persistAccountCredentials(ctx, p.accountRepo, account, creds); err != nil {
			slog.Warn("trae: 续期后写回凭据失败", "account_id", account.ID, "error", err)
		}
	}
	call.auth = &updated
	return &updated, nil
}

// doRefresh 调上游 ExchangeToken。
func (p *TraeTokenProvider) doRefresh(ctx context.Context, cred *cbTrae.Credential) (string, string, int64, error) {
	body, _ := json.Marshal(map[string]string{
		"ClientID":     firstNonEmptyStr(cred.UID, cred.EnterpriseID),
		"RefreshToken": cred.RefreshToken,
		"ClientSecret": traeClientSecret,
		"UserID":       "",
	})
	// 续期走 OAuth host，不是推理 host（两者不同域，见 pkg/trae 的常量注释）。
	url := cbTrae.OAuthHost + cbTrae.ExchangePath
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, strings.NewReader(string(body)))
	if err != nil {
		return "", "", 0, err
	}
	// 交换端点用固定 UA，不用 chat 那套指纹头。
	req.Header.Set("content-type", "application/json")
	req.Header.Set("accept", "application/json")
	req.Header.Set("user-agent", cbTrae.DefaultUserAgent)

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", "", 0, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))

	if resp.StatusCode != http.StatusOK {
		return "", "", 0, fmt.Errorf("trae: refresh %d: %s", resp.StatusCode, truncateForLog(raw, 200))
	}

	var out struct {
		AccessToken  string `json:"access_token"`
		Token        string `json:"token"`
		RefreshToken string `json:"refresh_token"`
		ExpiresAt    int64  `json:"expires_at"`
		ExpiresIn    int64  `json:"expires_in"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return "", "", 0, fmt.Errorf("trae: 解析 refresh 响应失败: %w", err)
	}
	token := firstNonEmptyStr(out.AccessToken, out.Token)
	if token == "" {
		// 200 但没有 token：会话已彻底失效，只能重新登录。
		return "", "", 0, fmt.Errorf("trae: refresh 响应无 token，需重新登录: %s", truncateForLog(raw, 200))
	}

	expiresAt := out.ExpiresAt
	if expiresAt > 1e12 {
		expiresAt /= 1000
	}
	if expiresAt == 0 && out.ExpiresIn > 0 {
		expiresAt = time.Now().Add(time.Duration(out.ExpiresIn) * time.Second).Unix()
	}
	if expiresAt == 0 {
		// 退路：从 JWT 的 exp 读。Trae 的 access_token 是 JWT。
		if exp, ok := JWTExpiry(token); ok {
			expiresAt = exp
		}
	}
	return token, out.RefreshToken, expiresAt, nil
}

// JWTExpiry 从 JWT payload 读 exp（Unix 秒）。失败返回 false。
//
// 单独导出的原因：Trae 的 access_token 是 JWT，exp 比响应里的 expires_at
// 更可靠（实测有时响应不带 expires_at，但 JWT 里一定有）。
func JWTExpiry(token string) (int64, bool) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return 0, false
	}
	payload, err := base64URLDecode(parts[1])
	if err != nil {
		return 0, false
	}
	var claims struct {
		Exp json.Number `json:"exp"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return 0, false
	}
	if claims.Exp == "" {
		return 0, false
	}
	v, err := strconv.ParseInt(claims.Exp.String(), 10, 64)
	if err != nil || v <= 0 {
		return 0, false
	}
	return v, true
}

// base64URLDecode 解 JWT 的 payload 段（无填充的 base64url）。
func base64URLDecode(s string) ([]byte, error) {
	if b, err := base64.RawURLEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	// 少数实现带填充，两种都要试。
	return base64.URLEncoding.DecodeString(s)
}