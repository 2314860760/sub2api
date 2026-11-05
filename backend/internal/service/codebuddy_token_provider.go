package service

// CodeBuddy 凭据续期与缓存。
//
// 设计取向与 Antigravity 的 token provider 一致，但刻意更简单：CodeBuddy 的
// 续期端点由移植包自己覆盖（upstream.Client.RefreshTokenIfNeeded），我们只需要
//   1. 判断"要不要续"（提前量）
//   2. 单飞：同一账号并发请求不能同时刷新，否则 refresh_token 轮换会让先刷的那次失效
//   3. 刷新后写回 accounts.credentials
//
// 单飞比缓存更重要：上游的 refresh_token 是轮换式（每次刷新换新的），
// 并发刷新必然有一个请求拿着已作废的 token 去打上游，表现为随机的 401。

import (
	"context"
	"log/slog"
	"sync"
	"time"

	cbAuth "github.com/Wei-Shaw/sub2api/internal/pkg/codebuddy/auth"
	cbUpstream "github.com/Wei-Shaw/sub2api/internal/pkg/codebuddy/upstream"
)

const (
	// codeBuddyRefreshSkew 提前多久续期。取 10 分钟：覆盖一次长对话的时长，
	// 避免请求进行到一半 token 过期。
	codeBuddyRefreshSkew = 10 * time.Minute
	// codeBuddyPendingTTL 单飞窗口的兜底过期。刷新卡死时不能让后来者永远等待。
	codeBuddyPendingTTL = 2 * time.Minute
)

// CodeBuddyTokenProvider 负责把账号凭据变成可用的 access_token。
type CodeBuddyTokenProvider struct {
	accountRepo AccountRepository
	client      *cbUpstream.Client

	mu      sync.Mutex
	pending map[int64]*codeBuddyRefreshCall
}

type codeBuddyRefreshCall struct {
	done chan struct{}
	err  error
	auth *cbAuth.Auth
	at   time.Time
}

func NewCodeBuddyTokenProvider(
	accountRepo AccountRepository,
	client *cbUpstream.Client,
) *CodeBuddyTokenProvider {
	return &CodeBuddyTokenProvider{
		accountRepo: accountRepo,
		client:      client,
		pending:     map[int64]*codeBuddyRefreshCall{},
	}
}

// GetAccessToken 返回可用凭据；必要时先续期。
//
// 返回的 *auth.Auth 是**副本的语义**：调用方可以读，但不该拿它去持久化——
// 持久化走 RefreshIfNeeded 内部的写回路径，保证"写回"与"刷新"在同一次单飞里。
func (p *CodeBuddyTokenProvider) GetAccessToken(ctx context.Context, account *Account) (*cbAuth.Auth, error) {
	if account == nil {
		return nil, ErrCodeBuddyNoCredential
	}
	a := account.GetCodeBuddyAuth()
	if a == nil {
		return nil, ErrCodeBuddyNoCredential
	}
	if !codeBuddyNeedsRefresh(a, codeBuddyRefreshSkew) {
		return a, nil
	}
	return p.RefreshIfNeeded(ctx, account, a)
}

// RefreshIfNeeded 单飞续期并把结果写回账号凭据。
//
// 同一账号并发进来时只有一个真正打上游，其余等待它的结果——见文件头关于
// refresh_token 轮换的说明。
func (p *CodeBuddyTokenProvider) RefreshIfNeeded(ctx context.Context, account *Account, a *cbAuth.Auth) (*cbAuth.Auth, error) {
	if p.client == nil {
		// 没有客户端就没法续期；把现状返回，让上游去判 401，
		// 而不是在这里伪造一个错误掩盖真实原因。
		return a, nil
	}

	p.mu.Lock()
	if call, ok := p.pending[account.ID]; ok {
		p.mu.Unlock()
		select {
		case <-call.done:
			if call.err != nil {
				return nil, call.err
			}
			return call.auth, nil
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	call := &codeBuddyRefreshCall{done: make(chan struct{}), at: time.Now()}
	p.pending[account.ID] = call
	p.mu.Unlock()

	defer func() {
		p.mu.Lock()
		delete(p.pending, account.ID)
		p.mu.Unlock()
		close(call.done)
	}()

	// 在**新副本**上刷新，成功后再写回——刷新失败时账号凭据保持原样。
	//
	// 不能写 `work := *a`：auth.Auth 内含 sync.Mutex，按值复制会被 go vet 判为
	// 复制锁，且确实是数据竞争隐患。这里经上游自己的 Parse 从字段重建，
	// 得到一把全新的零值互斥锁。
	work, err := cloneCodeBuddyAuth(a)
	if err != nil {
		call.err = err
		return nil, err
	}
	if err := p.client.RefreshTokenIfNeeded(work, codeBuddyRefreshSkew); err != nil {
		call.err = err
		return nil, err
	}

	// 写回：access/refresh/expires_at 必须一起更新。
	//
	// 走 persistAccountCredentials 而不是直接调 repo.UpdateCredentials：它是凭据
	// 写入的唯一汇聚点，内含 spark 影子账号的早返保护与 updater 能力探测。
	if p.accountRepo != nil && account.ID > 0 {
		creds := ApplyCodeBuddyAuth(account, work)
		if err := persistAccountCredentials(ctx, p.accountRepo, account, creds); err != nil {
			// 写回失败不影响本次请求（内存里的 work 已是新 token），但要记下来：
			// 下次请求会重新刷新，而 refresh_token 可能已被轮换。
			slog.Warn("codebuddy: 刷新后写回凭据失败",
				"account_id", account.ID, "error", err)
		}
	}

	call.auth = work
	return work, nil
}

// codeBuddyNeedsRefresh 报告凭据是否该续期。
//
// 无 refresh_token 时永远返回 false：没有续期能力，提前续只会制造无意义的上游调用，
// 真正的过期交给 401 分支处理（那时应走"需重新登录"而不是无限重试）。
func codeBuddyNeedsRefresh(a *cbAuth.Auth, skew time.Duration) bool {
	if a == nil || a.RefreshToken == "" {
		return false
	}
	if a.ExpiresAt <= 0 {
		// 没有有效期信息：按需要续期处理（有 refresh_token 就试一次）。
		return true
	}
	return time.Now().Add(skew).After(time.Unix(a.ExpiresAt, 0))
}
