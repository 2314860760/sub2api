// Package lobsterai 实现 LobsterAI（有道龙虾）的登录与鉴权。
//
// # 依据
//
// 全部协议细节来自**官方开源客户端** github.com/netease-youdao/lobsterai
// （commit da88493，2026-10-30）。这不是逆向猜测：端点、请求体、响应字段
// 都是从它的源码逐字对照过来的，对应关系写在每个函数上方。
//
// # 为什么值得单独建包
//
// 第三方实现（如 lobsterai2api）用的是 `LB2A_UPSTREAM_BASE` 环境变量 + 自己拼的
// 请求体，字段名与官方不完全一致（它用 `firstKeyfrom` 的驼峰变体、并自己加了
// `device_token` 概念）。官方实现里的 keyfrom 归因（firstKeyfrom / latestKeyfrom /
// uuid / userId / version）是与**风控**相关的字段 —— 缺了或拼错会被判定为
// 非官方客户端，这正是"注册完没登录就被封"这类问题的常见来源。
//
// 所以这里严格 1:1 还原官方请求形态，不多不少。
package lobsterai

// 端点与常量，全部对照官方源码。
const (
	// ServerBase 是业务 API 根。
	//
	// 官方 src/main/libs/endpoints.ts:31 getServerApiBaseUrl()
	// 生产固定 https://lobsterai-server.youdao.com
	ServerBase = "https://lobsterai-server.youdao.com"

	// ExchangePath 用 authCode 换 token。
	// 官方 src/main/main.ts:8218
	ExchangePath = "/api/auth/exchange"

	// RefreshPath 用 refreshToken 续期。
	// 官方 src/main/main.ts:6027
	RefreshPath = "/api/auth/refresh"

	// LogoutPath 登出。
	// 官方 src/main/main.ts:8690
	LogoutPath = "/api/auth/logout"

	// LoginURLPath 返回登录页地址（overmind 配置下发）。
	// 官方 src/main/libs/endpoints.ts:47 getLoginOvermindUrl()
	LoginURLPath = "https://api-overmind.youdao.com/openapi/get/luna/hardware/lobsterai/prod/login-url"

	// PortalLoginURL 是 overmind 不可用时的兜底登录页。
	// 官方 src/main/libs/endpoints.ts:70 getPortalLoginUrl()
	PortalLoginURL = "https://lobsterai.youdao.com/portal#/login"

	// CallbackPath 是本地回调服务监听的路径。
	// 官方 src/main/libs/authLocalCallbackServer.ts:5
	CallbackPath = "/auth/callback"
	// CallbackHost 只监听回环地址（官方同）。
	CallbackHost = "127.0.0.1"
	// CallbackTimeout 是等待回调的硬超时（官方 5 分钟）。
	CallbackTimeout = 5 * 60 * 1000 // 毫秒，与官方常量同单位

	// ChatPath 是推理端点（OpenAI 兼容）。
	// 来源：第三方实现与 OFM 一致；官方 chat 走 openclaw 引擎，此路径供网关使用。
	ChatPath = "/api/proxy/v1/chat/completions"

	// ModelsPath 是模型目录。
	ModelsPath = "/api/models/available"
	// ProfilePath 返回积分与账户摘要。
	ProfilePath = "/api/user/profile-summary"

	// ClientVersion 只用于 User-Agent。
	// 官方从 api-overmind 动态取版本号；这里保留兜底值，实际应优先动态获取。
	FallbackClientVersion = "2026.9.4"
	// ClientCapabilities 是客户端能力声明头。
	ClientCapabilities = "kimi-k3-agentic-v1"
)
