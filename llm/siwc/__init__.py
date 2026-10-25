"""Official Sign in with ChatGPT support, independent of API-key providers."""

PROVIDER = "openai_codex_auth"
ISSUER = "https://auth.openai.com"
RESOURCE = "https://api.openai.com/v1"
SCOPES = ("openid", "profile", "email", "offline_access", "resource.invoke", "chatgpt.tokens.use.direct")
INFERENCE_SCOPES = frozenset({"resource.invoke", "chatgpt.tokens.use.direct"})
