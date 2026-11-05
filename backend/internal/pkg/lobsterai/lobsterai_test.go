package lobsterai

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// ─────────────────────────────────────────────────────────────
// keyfrom：官方 withKeyfromBody 的语义
// ─────────────────────────────────────────────────────────────

// TestKeyfromMergeIsFlat 钉住 keyfrom 与业务字段**同级**。
//
// 官方 withKeyfromBody = {...body, ...buildKeyfromPayload()}。
// 如果把 keyfrom 嵌套成 {"keyfrom":{...}}，服务端读不到归因字段，
// 表现为"请求成功但被当成非官方客户端"。
func TestKeyfromMergeIsFlat(t *testing.T) {
	kf := Keyfrom{
		FirstKeyfrom:     "official_site",
		LatestKeyfrom:    "client_menu",
		InstallationUUID: "uuid-123",
		UserID:           "u-1",
		Version:          "2026.10.30",
	}
	got := kf.merge(map[string]any{"authCode": "CODE"})

	for _, key := range []string{"firstKeyfrom", "latestKeyfrom", "version", "uuid", "userId", "authCode"} {
		if _, ok := got[key]; !ok {
			t.Errorf("缺字段 %q（应与业务字段同级）", key)
		}
	}
	// 不能出现嵌套对象。
	if _, ok := got["keyfrom"]; ok {
		t.Error("keyfrom 不应被嵌套")
	}
	if got["authCode"] != "CODE" {
		t.Errorf("业务字段丢失: %v", got["authCode"])
	}
}

// TestKeyfromOmitsEmptyOptional 钉住 uuid/userId 为空时**不发送**。
//
// 官方用 `...(uuid ? { uuid } : {})` 展开，空值不是发空串而是不发。
// 发空串可能被服务端当成"有 uuid 但无效"。
func TestKeyfromOmitsEmptyOptional(t *testing.T) {
	got := Keyfrom{FirstKeyfrom: "a", LatestKeyfrom: "b"}.merge(nil)
	if _, ok := got["uuid"]; ok {
		t.Error("空 uuid 不应出现")
	}
	if _, ok := got["userId"]; ok {
		t.Error("空 userId 不应出现")
	}
	if got["version"] != FallbackClientVersion {
		t.Errorf("version 应回落，得到 %v", got["version"])
	}
}

// ─────────────────────────────────────────────────────────────
// exchange / refresh 响应解析
// ─────────────────────────────────────────────────────────────

// TestExchangeParsesCamelCase 钉住字段是 camelCase。
//
// 用 access_token 会解出空值而不报错，表现是「登录成功但没 token」。
func TestExchangeParsesCamelCase(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 校验请求体形态。
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		if body["authCode"] != "CODE" {
			t.Errorf("请求缺 authCode: %v", body)
		}
		if body["firstKeyfrom"] != "fk" {
			t.Errorf("请求缺 firstKeyfrom: %v", body)
		}
		w.Header().Set("content-type", "application/json")
		w.Write([]byte(`{"code":0,"data":{
			"accessToken":"AT-1","refreshToken":"RT-1",
			"user":{"id":"1","nickname":"tester","phone":"131"},
			"quota":{"totalCreditsRemaining":100}}}`))
	}))
	defer srv.Close()

	c := New()
	c.HTTP = srv.Client()
	got, err := c.exchangeAt(t.Context(), srv.URL+ExchangePath, "CODE", Keyfrom{FirstKeyfrom: "fk", LatestKeyfrom: "lk"})
	if err != nil {
		t.Fatalf("exchange 失败: %v", err)
	}
	if got.Tokens.AccessToken != "AT-1" || got.Tokens.RefreshToken != "RT-1" {
		t.Errorf("token 解析错误: %+v", got.Tokens)
	}
	if got.User.Nickname != "tester" {
		t.Errorf("user 解析错误: %+v", got.User)
	}
}

// TestExchangeRejectsSnakeCase 确认 snake_case 会被明确报错而不是静默通过。
func TestExchangeRejectsSnakeCase(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"code":0,"data":{"access_token":"AT"}}`))
	}))
	defer srv.Close()

	c := New()
	c.HTTP = srv.Client()
	_, err := c.exchangeAt(t.Context(), srv.URL+ExchangePath, "CODE", Keyfrom{FirstKeyfrom: "fk"})
	if err == nil {
		t.Fatal("snake_case 应报错（缺 accessToken）")
	}
	if !strings.Contains(err.Error(), "accessToken") {
		t.Errorf("错误信息应指明字段名: %v", err)
	}
}

// TestBusinessErrorIn200 钉住 code != 0 会被识别。
//
// 官方把业务错误放 200 响应体里；只看 HTTP 状态会把过期当成成功。
func TestBusinessErrorIn200(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"code":40100,"message":"refresh token expired"}`))
	}))
	defer srv.Close()

	c := New()
	c.HTTP = srv.Client()
	_, err := c.postJSON(t.Context(), srv.URL+RefreshPath, map[string]any{}, "")
	if err == nil {
		t.Fatal("code!=0 应报错")
	}
	if !strings.Contains(err.Error(), "40100") {
		t.Errorf("错误应带 code: %v", err)
	}
}

// ─────────────────────────────────────────────────────────────
// 登录 URL 拼接
// ─────────────────────────────────────────────────────────────

// TestBuildAuthorizeURLHashRoute 钉住 hash 路由的拼接位置。
//
// Portal 用 hash 路由（`.../portal#/login`）。redirect_uri 必须拼在 `#` 之后，
// 拼在 `?` 之前会被前端路由丢掉 —— 登录完浏览器无处可去。
func TestBuildAuthorizeURLHashRoute(t *testing.T) {
	got := BuildAuthorizeURL("https://lobsterai.youdao.com/portal#/login", "http://127.0.0.1:5555/auth/callback")
	if !strings.HasPrefix(got, "https://lobsterai.youdao.com/portal#/login?") {
		t.Errorf("redirect_uri 应拼在 hash 之后: %s", got)
	}
	if strings.Contains(got, "portal?redirect_uri") {
		t.Errorf("不应拼在 # 之前: %s", got)
	}
	// 回调地址应被编码。
	if !strings.Contains(got, "127.0.0.1%3A5555") {
		t.Errorf("回调地址未编码: %s", got)
	}
}

func TestBuildAuthorizeURLHashWithExistingQuery(t *testing.T) {
	got := BuildAuthorizeURL("https://x/portal#/login?a=1", "http://127.0.0.1:1/cb")
	if !strings.Contains(got, "a=1&redirect_uri=") {
		t.Errorf("已有 query 时应追加: %s", got)
	}
}

func TestBuildAuthorizeURLPlainQuery(t *testing.T) {
	got := BuildAuthorizeURL("https://x/login", "http://127.0.0.1:1/cb")
	if !strings.HasPrefix(got, "https://x/login?redirect_uri=") {
		t.Errorf("无 hash 时应拼普通 query: %s", got)
	}
}

// ─────────────────────────────────────────────────────────────
// 回调服务
// ─────────────────────────────────────────────────────────────

// TestCallbackServerServesCode 端到端验证回调服务。
func TestCallbackServerServesCode(t *testing.T) {
	cb, err := StartCallbackServer()
	if err != nil {
		t.Fatalf("启动回调服务失败: %v", err)
	}
	defer cb.Close()

	if !strings.HasPrefix(cb.RedirectURI, "http://127.0.0.1:") {
		t.Errorf("回调地址应只监听回环: %s", cb.RedirectURI)
	}
	if !strings.HasSuffix(cb.RedirectURI, CallbackPath) {
		t.Errorf("路径应为 %s: %s", CallbackPath, cb.RedirectURI)
	}

	// 模拟浏览器回调。
	resp, err := http.Get(cb.RedirectURI + "?code=THECODE")
	if err != nil {
		t.Fatalf("回调请求失败: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("成功回调应返回 200，得到 %d", resp.StatusCode)
	}

	code, err := cb.Wait(t.Context())
	if err != nil {
		t.Fatalf("Wait 失败: %v", err)
	}
	if code != "THECODE" {
		t.Errorf("code = %q, want THECODE", code)
	}
}

// TestCallbackServerMissingCode 钉住无 code 时返回错误而不是挂住。
func TestCallbackServerMissingCode(t *testing.T) {
	cb, err := StartCallbackServer()
	if err != nil {
		t.Fatal(err)
	}
	defer cb.Close()

	resp, err := http.Get(cb.RedirectURI)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("无 code 应返回 400，得到 %d", resp.StatusCode)
	}

	_, waitErr := cb.Wait(t.Context())
	if waitErr == nil {
		t.Error("无 code 时 Wait 应返回错误")
	}
}

// ─────────────────────────────────────────────────────────────
// 推理：强制流式 + 流内错误
// ─────────────────────────────────────────────────────────────

// TestPrepareChatBodyForcesStream 钉住 stream 被强制为 true。
//
// 上游对 stream:false 直接 500，不做这个转换整个非流式路径都不可用。
func TestPrepareChatBodyForcesStream(t *testing.T) {
	out, err := prepareChatBody([]byte(`{"model":"m","stream":false,"messages":[]}`))
	if err != nil {
		t.Fatal(err)
	}
	var body map[string]any
	_ = json.Unmarshal(out, &body)
	if body["stream"] != true {
		t.Errorf("stream 应被强制为 true，得到 %v", body["stream"])
	}
}

func TestPrepareChatBodyDropsEmptyToolChoice(t *testing.T) {
	out, err := prepareChatBody([]byte(`{"model":"m","tool_choice":"none","tools":[{"a":1}],"messages":[]}`))
	if err != nil {
		t.Fatal(err)
	}
	var body map[string]any
	_ = json.Unmarshal(out, &body)
	if _, ok := body["tool_choice"]; ok {
		t.Error("tool_choice=none 应被删除")
	}
	if _, ok := body["tools"]; ok {
		t.Error("tool_choice=none 时 tools 应一并删除")
	}
}

// TestDetectStreamError 钉住 200 流内错误能被识别。
func TestDetectStreamError(t *testing.T) {
	cases := []struct {
		name string
		head string
		want bool
	}{
		{"event:error 帧", "event:error\ndata:{\"code\":40201,\"message\":\"insufficient credits\"}\n\n", true},
		{"data 内 error 对象", `data:{"error":{"message":"boom"}}` + "\n\n", true},
		{"正常首帧", `data:{"choices":[{"delta":{"content":"hi"}}]}` + "\n\n", false},
		{"心跳", ": heartbeat\n\n", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := detectStreamError([]byte(c.head))
			if (got != "") != c.want {
				t.Errorf("detectStreamError = %q, want error=%v", got, c.want)
			}
		})
	}
}

// TestChatStreamPropagatesStreamError 端到端：200 + 错误帧应变成 error 返回。
func TestChatStreamPropagatesStreamError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("content-type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("event:error\ndata:{\"code\":40201,\"message\":\"积分不足\"}\n\n"))
	}))
	defer srv.Close()

	c := NewChatClient()
	c.HTTP = srv.Client()

	// 用 server 地址替换常量：这里直接测 detectStreamError 已覆盖，
	// 该用例验证的是「首块窥探能把错误转成 error 返回」。
	rc, _, err := c.chatStreamAt(t.Context(), srv.URL, "AT", []byte(`{"model":"m","messages":[]}`))
	if err == nil {
		if rc != nil {
			rc.Close()
		}
		t.Fatal("流内错误应作为 error 返回")
	}
	var se *StreamError
	if !asStreamError(err, &se) {
		t.Errorf("错误类型应为 *StreamError，得到 %T", err)
	}
	if !strings.Contains(err.Error(), "40201") {
		t.Errorf("错误应带 code: %v", err)
	}
}

func asStreamError(err error, target **StreamError) bool {
	if e, ok := err.(*StreamError); ok {
		*target = e
		return true
	}
	return false
}

// ─────────────────────────────────────────────────────────────
// 端点常量对照官方源码
// ─────────────────────────────────────────────────────────────

// TestEndpointsMatchOfficialSource 钉住端点与官方源码一致。
//
// 这些值抄错不会报错，只会得到 404 或打到错误服务 —— 所以用测试锁住。
func TestEndpointsMatchOfficialSource(t *testing.T) {
	checks := map[string]string{
		"ServerBase":    "https://lobsterai-server.youdao.com",
		"ExchangePath":  "/api/auth/exchange",
		"RefreshPath":   "/api/auth/refresh",
		"LogoutPath":    "/api/auth/logout",
		"CallbackPath":  "/auth/callback",
		"CallbackHost":  "127.0.0.1",
		"ChatPath":      "/api/proxy/v1/chat/completions",
	}
	actual := map[string]string{
		"ServerBase":   ServerBase,
		"ExchangePath": ExchangePath,
		"RefreshPath":  RefreshPath,
		"LogoutPath":   LogoutPath,
		"CallbackPath": CallbackPath,
		"CallbackHost": CallbackHost,
		"ChatPath":     ChatPath,
	}
	for k, want := range checks {
		if actual[k] != want {
			t.Errorf("%s = %q, want %q", k, actual[k], want)
		}
	}
	if CallbackTimeout != 5*60*1000 {
		t.Errorf("CallbackTimeout = %d，官方是 5 分钟", CallbackTimeout)
	}
}
