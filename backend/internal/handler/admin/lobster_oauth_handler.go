package admin

// LobsterAI 登录接口。
//
// # 为什么要做成接口而不是命令行工具
//
// 官方登录是「浏览器 OAuth + 本地回调」的交互流程：用户在浏览器里扫码/输密码，
// 登录页把 authCode 回调到本机临时端口。sub2api 是常驻服务，不能阻塞等这个流程，
// 所以拆成两步：
//
//	POST /admin/lobsterai/login/start    → 返回 authorize_url + login_id
//	（用户打开 URL 完成登录）
//	GET  /admin/lobsterai/login/poll     → 轮询；拿到 code 后自动 exchange 并存凭据
//
// # 与官方的对应关系
//
//	官方 auth.ts:566  fetchLoginUrl        → start 里取 overmind 的登录页地址
//	官方 main.ts:8218 POST /api/auth/exchange → poll 拿到 code 后调它
//	官方 callback 路径 /auth/callback       → 与官方完全一致
//
// # 为什么要按官方 1:1 还原
//
// keyfrom 归因（firstKeyfrom/latestKeyfrom/uuid/version）与回调路径都参与
// 客户端识别。第三方实现少发字段会被判定为非官方客户端 —— 这是「注册完
// 没登录就被封」这类问题的常见成因。所以这里每个字段都从官方源码抄，
// 不做"简化"。

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/Wei-Shaw/sub2api/internal/config"
	cbLobster "github.com/Wei-Shaw/sub2api/internal/pkg/lobsterai"
	"github.com/Wei-Shaw/sub2api/internal/service"
)

// lobsterLoginSession 是一次进行中的登录。
type lobsterLoginSession struct {
	ID           string
	AuthorizeURL string
	Keyfrom      cbLobster.Keyfrom
	Callback     *cbLobster.LocalCallback
	StartedAt    time.Time

	mu     sync.Mutex
	done   bool
	result *cbLobster.ExchangeResult
	err    error
}

// LobsterOAuthHandler 管理 LobsterAI 的登录流程。
type LobsterOAuthHandler struct {
	client        *cbLobster.Client
	accountRepo   service.AccountRepository
	clientVersion string

	mu       sync.Mutex
	sessions map[string]*lobsterLoginSession
}

// NewLobsterOAuthHandler 构造 LobsterAI 登录处理器。
//
// 签名带 config 而不是裸字符串：clientVersion 参与 keyfrom.version
// （官方每个鉴权请求都带），集中从配置读比在调用点传更不容易漏。
func NewLobsterOAuthHandler(
	client *cbLobster.Client,
	accountRepo service.AccountRepository,
	cfg *config.Config,
) *LobsterOAuthHandler {
	v := ""
	if cfg != nil {
		v = cfg.Gateway.LobsterClientVersion
	}
	return &LobsterOAuthHandler{
		client:        client,
		accountRepo:   accountRepo,
		clientVersion: v,
		sessions:      map[string]*lobsterLoginSession{},
	}
}

// StartLogin 开一次登录：起本地回调服务、取登录页地址、返回 authorize_url。
//
// POST /api/v1/admin/lobsterai/login/start
func (h *LobsterOAuthHandler) StartLogin(c *gin.Context) {
	var req struct {
		// FirstKeyfrom / LatestKeyfrom 允许调用方指定渠道标识；
		// 留空用官方默认值（官方首次安装两者相同）。
		FirstKeyfrom  string `json:"first_keyfrom"`
		LatestKeyfrom string `json:"latest_keyfrom"`
		// InstallationUUID 留空则服务端生成并持久化。
		InstallationUUID string `json:"installation_uuid"`
	}
	_ = c.ShouldBindJSON(&req)

	cb, err := cbLobster.StartCallbackServer()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	loginURL := h.client.FetchLoginURL(c.Request.Context())
	authorizeURL := cbLobster.BuildAuthorizeURL(loginURL, cb.RedirectURI)

	kf := cbLobster.Keyfrom{
		FirstKeyfrom:     firstNonEmpty(req.FirstKeyfrom, "client"),
		LatestKeyfrom:    firstNonEmpty(req.LatestKeyfrom, req.FirstKeyfrom, "client"),
		InstallationUUID: req.InstallationUUID,
		Version:          h.clientVersion,
	}

	id := newLoginID()
	sess := &lobsterLoginSession{
		ID:           id,
		AuthorizeURL: authorizeURL,
		Keyfrom:      kf,
		Callback:     cb,
		StartedAt:    time.Now(),
	}

	h.mu.Lock()
	h.sessions[id] = sess
	h.mu.Unlock()

	// 后台等回调；拿到 code 立刻 exchange。
	go h.awaitAndExchange(sess)

	c.JSON(http.StatusOK, gin.H{
		"login_id":      id,
		"authorize_url": authorizeURL,
		"redirect_uri":  cb.RedirectURI,
		"expires_in":    cbLobster.CallbackTimeout / 1000,
		"hint":          "在浏览器打开 authorize_url 完成登录；本接口会在回调到达后自动换取 token。",
	})
}

// PollLogin 查询登录进度。
//
// GET /api/v1/admin/lobsterai/login/poll?id=<login_id>
//
// 状态：pending（等待浏览器回调）/ done（已拿到 token）/ failed。
func (h *LobsterOAuthHandler) PollLogin(c *gin.Context) {
	id := c.Query("id")
	h.mu.Lock()
	sess, ok := h.sessions[id]
	h.mu.Unlock()
	if !ok {
		c.JSON(http.StatusNotFound, gin.H{"error": "login session not found"})
		return
	}

	sess.mu.Lock()
	done, res, errMsg := sess.done, sess.result, sess.err
	sess.mu.Unlock()

	if !done {
		// 超时后清理，避免 session 泄漏。
		if time.Since(sess.StartedAt) > time.Duration(cbLobster.CallbackTimeout)*time.Millisecond {
			h.finish(sess, nil, context.DeadlineExceeded)
			c.JSON(http.StatusOK, gin.H{"status": "failed", "error": "登录超时（5 分钟）"})
			return
		}
		// 顺手清理其他超时会话，避免内存随登录次数增长。
		h.sweepExpired()
		c.JSON(http.StatusOK, gin.H{"status": "pending"})
		return
	}

	if errMsg != nil {
		// 读取即消费：失败结果读一次后清理，避免长期占用内存。
		h.mu.Lock()
		delete(h.sessions, id)
		h.mu.Unlock()
		c.JSON(http.StatusOK, gin.H{"status": "failed", "error": errMsg.Error()})
		return
	}

	// 成功结果同样只交付一次（access_token 已经在响应里，留着没有意义且有泄漏风险）。
	h.mu.Lock()
	delete(h.sessions, id)
	h.mu.Unlock()

	// 成功：返回非敏感信息 + 可直接用于建账号的凭据骨架。
	c.JSON(http.StatusOK, gin.H{
		"status": "done",
		"user": gin.H{
			"uid":      res.User.UID,
			"nickname": res.User.Nickname,
			"phone":    res.User.Phone,
		},
		// credentials 可直接 POST /admin/accounts 的 credentials 字段。
		"credentials": gin.H{
			"access_token":      res.Tokens.AccessToken,
			"refresh_token":     res.Tokens.RefreshToken,
			"uid":               res.User.UID,
			"nickname":          res.User.Nickname,
			"phone":             res.User.Phone,
			"first_keyfrom":     sess.Keyfrom.FirstKeyfrom,
			"latest_keyfrom":    sess.Keyfrom.LatestKeyfrom,
			"installation_uuid": sess.Keyfrom.InstallationUUID,
			"client_version":    sess.Keyfrom.Version,
		},
	})
}

// awaitAndExchange 后台等回调并换 token。
func (h *LobsterOAuthHandler) awaitAndExchange(sess *lobsterLoginSession) {
	defer sess.Callback.Close()

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(cbLobster.CallbackTimeout)*time.Millisecond)
	defer cancel()

	code, err := sess.Callback.Wait(ctx)
	if err != nil {
		h.finish(sess, nil, err)
		return
	}

	// keyfrom 的 uuid 必须在 exchange 前就存在：官方在首次安装时生成并持久化，
	// 之后每个请求都带。缺了会被当成新设备。
	if sess.Keyfrom.InstallationUUID == "" {
		sess.Keyfrom.InstallationUUID = newInstallationUUID()
	}

	res, err := h.client.Exchange(ctx, code, sess.Keyfrom)
	h.finish(sess, res, err)
}

func (h *LobsterOAuthHandler) finish(sess *lobsterLoginSession, res *cbLobster.ExchangeResult, err error) {
	sess.mu.Lock()
	if sess.done {
		sess.mu.Unlock()
		return
	}
	sess.done = true
	sess.result = res
	sess.err = err
	sess.mu.Unlock()

	// ⚠️ 不在这里从 sessions 删除。
	// 登录结果是 poll 的返回值，删太早会让调用方永远读不到 ——
	// 表现为「浏览器提示登录成功，但接口一直报 session not found」。
	// 会话由 poll 在读取后清理，或由 sweep 按超时清理。
	if sess.Callback != nil {
		_ = sess.Callback.Close()
	}
}



// newLoginID 生成登录会话 id。
func newLoginID() string {
	b := make([]byte, 12)
	if _, err := rand.Read(b); err != nil {
		return fmt.Sprintf("%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(b)
}

// newInstallationUUID 生成安装标识。
//
// 官方 getOrCreateInstallationId 在首次安装时生成一次并永久保存 ——
// 它的语义是"这台设备"，变更等于换设备，会被风控关注。
func newInstallationUUID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return fmt.Sprintf("%d", time.Now().UnixNano())
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}
// sweepExpired 清理超时的登录会话。
//
// 没有这一步的话，用户打开 authorize_url 后直接关浏览器，会话会永久留在表里。
func (h *LobsterOAuthHandler) sweepExpired() {
	ttl := time.Duration(cbLobster.CallbackTimeout) * time.Millisecond
	now := time.Now()

	h.mu.Lock()
	defer h.mu.Unlock()
	for id, sess := range h.sessions {
		if now.Sub(sess.StartedAt) > ttl {
			delete(h.sessions, id)
			if sess.Callback != nil {
				_ = sess.Callback.Close()
			}
		}
	}
}