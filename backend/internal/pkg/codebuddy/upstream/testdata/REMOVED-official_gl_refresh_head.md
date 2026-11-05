# 已移除：official_gl_refresh_head.txt

原文件是上游仓库里的 HTTP 头样例夹具，含**真实的 refresh token（JWT）**。

移除理由：
- 仓库内**没有任何测试引用它**（已 grep 确认），移除不影响测试
- 交付物里不应包含真实凭据，哪怕是上游作者的历史 token

如果将来需要这个夹具，请用假 token 重建：
把 `X-Refresh-Token: eyJ...` 换成一个形如 JWT 的占位串即可，
该样例只用于验证头解析，不校验 token 内容。
