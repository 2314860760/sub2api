package lobsterai

// 本地 OAuth 回调服务：1:1 对照官方 authLocalCallbackServer.ts。
//
// # 官方流程
//
//	1. 在 127.0.0.1 起一个临时 HTTP 服务，监听 /auth/callback
//	2. 把 redirect_uri 拼成 http://127.0.0.1:<port>/auth/callback
//	3. 打开系统浏览器让用户登录，登录页会把 code 回调到该地址
//	4. 收到 code → 关闭服务 → 用它换 token
//
// # 几个容易做错的细节
//
//   - **端口必须动态分配**（listen 0）。固定端口会在多实例/端口占用时挂掉，
//     而且官方就是动态的。
//   - **只监听 127.0.0.1**，不要 0.0.0.0。回调带 code，暴露到局域网等于泄漏凭据。
//   - **5 分钟硬超时**（官方 AUTH_LOCAL_CALLBACK_TIMEOUT_MS）。用户可能直接关掉
//     浏览器，不设超时会让登录流程永久挂住。
//   - 收到 code 后要**回一个 HTML 页**给浏览器，否则用户看到空白页以为失败了。

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// CallbackResult 是回调服务收到的结果。
type CallbackResult struct {
	Code string
	Err  error
}

// LocalCallback 是运行中的回调服务。
type LocalCallback struct {
	// RedirectURI 是要传给登录页的完整回调地址。
	RedirectURI string

	server   *http.Server
	listener net.Listener
	resultCh chan CallbackResult
	once     sync.Once
}

// StartCallbackServer 在回环地址上起一个临时回调服务。
//
// 返回的 RedirectURI 需要拼进登录 URL（见 BuildAuthorizeURL）。
func StartCallbackServer() (*LocalCallback, error) {
	ln, err := net.Listen("tcp", CallbackHost+":0")
	if err != nil {
		return nil, fmt.Errorf("lobsterai: 无法监听回调端口: %w", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port

	cb := &LocalCallback{
		RedirectURI: fmt.Sprintf("http://%s:%d%s", CallbackHost, port, CallbackPath),
		listener:    ln,
		resultCh:    make(chan CallbackResult, 1),
	}

	mux := http.NewServeMux()
	mux.HandleFunc(CallbackPath, func(w http.ResponseWriter, r *http.Request) {
		code := strings.TrimSpace(r.URL.Query().Get("code"))
		if code == "" {
			// 用户取消授权时也会回调到这里，但没有 code。
			cb.deliver(CallbackResult{Err: fmt.Errorf("lobsterai: 回调未携带 code（用户可能取消了授权）")})
			writeCallbackPage(w, false, "登录未完成：没有收到授权码，请回到应用重试。")
			return
		}
		cb.deliver(CallbackResult{Code: code})
		writeCallbackPage(w, true, "登录成功，可以关闭此页面回到应用。")
	})

	cb.server = &http.Server{Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	go func() {
		_ = cb.server.Serve(ln)
	}()
	return cb, nil
}

func (c *LocalCallback) deliver(r CallbackResult) {
	c.once.Do(func() {
		c.resultCh <- r
	})
}

// Wait 等待回调，最多 CallbackTimeout。
func (c *LocalCallback) Wait(ctx context.Context) (string, error) {
	timer := time.NewTimer(time.Duration(CallbackTimeout) * time.Millisecond)
	defer timer.Stop()

	select {
	case r := <-c.resultCh:
		return r.Code, r.Err
	case <-timer.C:
		return "", fmt.Errorf("lobsterai: 等待登录回调超时（%d 分钟）", CallbackTimeout/60000)
	case <-ctx.Done():
		return "", ctx.Err()
	}
}

// Close 关闭回调服务。应当 defer 调用。
func (c *LocalCallback) Close() error {
	if c.server != nil {
		shutCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		return c.server.Shutdown(shutCtx)
	}
	return nil
}

// writeCallbackPage 给浏览器一个明确的成功/失败页。
//
// 不回页面的话浏览器停在空白，用户会以为卡住了并反复点登录，
// 而那会消耗掉一次性的 code。
func writeCallbackPage(w http.ResponseWriter, ok bool, message string) {
	w.Header().Set("content-type", "text/html; charset=utf-8")
	status := http.StatusOK
	if !ok {
		status = http.StatusBadRequest
	}
	w.WriteHeader(status)
	icon := "✅"
	if !ok {
		icon = "⚠️"
	}
	fmt.Fprintf(w, `<!doctype html><html lang="zh"><head><meta charset="utf-8">
<title>LobsterAI 登录</title>
<style>body{font-family:system-ui,-apple-system,sans-serif;display:flex;align-items:center;
justify-content:center;height:100vh;margin:0;background:#faf9f7;color:#1f1e1c}
.box{text-align:center;padding:40px 48px;background:#fff;border-radius:16px;
box-shadow:0 4px 24px rgba(0,0,0,.08)}.icon{font-size:44px;line-height:1}
p{color:#5c5a56;margin:16px 0 0}</style></head>
<body><div class="box"><div class="icon">%s</div><p>%s</p></div></body></html>`, icon, message)
}

// BuildAuthorizeURL 把回调地址拼进登录页 URL。
//
// 官方 appendLoginParams（authLocalCallbackServer.ts:101）处理的是 hash 路由
// （`#/login?…`）。Portal 用的是 hash 路由，所以 query 必须拼在 `#` 之后，
// 拼在 `?` 之前会被前端路由丢掉 —— 表现为登录页打开后没有回调地址，登录完
// 浏览器无处可去。
func BuildAuthorizeURL(loginURL, redirectURI string) string {
	params := "redirect_uri=" + urlQueryEscape(redirectURI)

	// 先找 hash；有 hash 就拼到 hash 里的 query。
	if i := strings.Index(loginURL, "#"); i >= 0 {
		head, hash := loginURL[:i], loginURL[i:]
		if q := strings.Index(hash, "?"); q >= 0 {
			return head + hash + "&" + params
		}
		return head + hash + "?" + params
	}

	// 没有 hash：按普通 query 拼。
	if q := strings.Index(loginURL, "?"); q >= 0 {
		return loginURL + "&" + params
	}
	return loginURL + "?" + params
}

func urlQueryEscape(s string) string {
	// 只做最小转义：回调地址里只有 : / 需要编码，用完整 QueryEscape 会
	// 把 `:` `//` 也编掉，服务端还原时可能不认。
	replacer := strings.NewReplacer(
		":", "%3A",
		"/", "%2F",
		"?", "%3F",
		"&", "%26",
		"=", "%3D",
		"#", "%23",
	)
	return replacer.Replace(s)
}
