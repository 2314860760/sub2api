package service

// LobsterAI 凭据续期。
//
// 官方策略（authSessionManager.ts）：401 时被动刷新，refreshToken 轮换式。
// 所以必须单飞 —— 并发刷新会让先刷的那次作废，表现为随机 401。
//
// 业务错误在 HTTP 200 的响应体里（code != 0），所以不能只看状态码：
// 官方 TERMINAL_REFRESH_ERROR_CODES = {40100, 40101, NotMember}。

import (
	"context"
	"log/slog"
	"strings"
	"sync"
	"time"

	cbLobster "github.com/Wei-Shaw/sub2api/internal/pkg/lobsterai"
)

const (
	lobsterRefreshSkew = 10 * time.Minute
)

// LobsterTokenProvider 负责把账号凭据变成可用的 access token。
type LobsterTokenProvider struct {
	accountRepo AccountRepository
	client      *cbLobster.Client
	version     string

	mu      sync.Mutex
	pending map[int64]*lobsterRefreshCall
}

type lobsterRefreshCall struct {
	done  chan struct{}
	token string
	err   error
}

func NewLobsterTokenProvider(accountRepo AccountRepository, client *cbLobster.Client, version string) *LobsterTokenProvider {
	return &LobsterTokenProvider{
		accountRepo: accountRepo,
		client:      client,
		version:     version,
		pending:     map[int64]*lobsterRefreshCall{},
	}
}

// AccessToken 返回可用 token；必要时先续期。
func (p *LobsterTokenProvider) AccessToken(ctx context.Context, account *Account) (string, error) {
	token := account.LobsterAccessToken()
	if token == "" {
		return "", ErrLobsterNoCredential
	}
	if !account.LobsterNeedsRefresh(lobsterRefreshSkew) {
		return token, nil
	}
	return p.refresh(ctx, account)
}

func (p *LobsterTokenProvider) refresh(ctx context.Context, account *Account) (string, error) {
	p.mu.Lock()
	if call, ok := p.pending[account.ID]; ok {
		p.mu.Unlock()
		select {
		case <-call.done:
			return call.token, call.err
		case <-ctx.Done():
			return "", ctx.Err()
		}
	}
	call := &lobsterRefreshCall{done: make(chan struct{})}
	p.pending[account.ID] = call
	p.mu.Unlock()

	defer func() {
		p.mu.Lock()
		delete(p.pending, account.ID)
		p.mu.Unlock()
		close(call.done)
	}()

	refreshToken := strings.TrimSpace(account.GetCredential(lobsterCredRefreshToken))
	if refreshToken == "" {
		call.err = ErrLobsterNoCredential
		return "", call.err
	}

	kf := account.GetLobsterKeyfrom(p.version)
	tokens, err := p.client.Refresh(ctx, refreshToken, kf)
	if err != nil {
		call.err = err
		return "", err
	}

	// 官方不返回 expires_at，按固定有效期推算（官方 token 有效期 15 天量级，
	// 这里保守取 12 小时后主动再刷，避免用到临界状态）。
	expiresAt := time.Now().Add(12 * time.Hour).Unix()

	if p.accountRepo != nil && account.ID > 0 {
		creds := ApplyLobsterTokens(account, tokens, expiresAt)
		if err := persistAccountCredentials(ctx, p.accountRepo, account, creds); err != nil {
			slog.Warn("lobsterai: 续期后写回凭据失败", "account_id", account.ID, "error", err)
		}
	}
	call.token = tokens.AccessToken
	return call.token, nil
}
