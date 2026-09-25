"""Optional API-key guard for state-changing endpoints.

When the API_KEY environment variable is set, routes that depend on
`require_api_key` need a matching `X-API-Key` header. When it is unset the
guard is a no-op, which keeps local development and the demo frictionless.

This protects a deployment from drive-by scripts. It is not user
authentication: a key compiled into a browser bundle is visible to anyone who
loads the page. A multi-analyst deployment belongs behind SSO/OIDC at the
reverse proxy.
"""
import hmac

from fastapi import Header, HTTPException, status

from config import settings


async def require_api_key(x_api_key: str = Header(default="")) -> None:
    if not settings.API_KEY:
        return
    # Constant-time comparison so the key cannot be recovered by timing.
    if not hmac.compare_digest(x_api_key.encode(), settings.API_KEY.encode()):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="missing or invalid X-API-Key",
        )
