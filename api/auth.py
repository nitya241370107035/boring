"""
SentinelLog API: Authentication & Authorization Engine.
Validates X-API-Key request headers using constant-time comparison.
"""

import os
import secrets
from fastapi import Header, HTTPException, Security

DEFAULT_KEYS = "sentinel-secret-key-1,sentinel-secret-key-agent,sentinel-secret-key-dash"


def get_allowed_keys() -> list[str]:
    raw = os.environ.get("SENTINEL_API_KEYS", DEFAULT_KEYS)
    return [k.strip() for k in raw.split(",") if k.strip()]


def verify_api_key(x_api_key: str | None = Header(None, description="Authentication API Key")) -> str:
    """
    Validates X-API-Key against configured keys using constant-time comparison
    to prevent timing side-channel attacks.
    """
    if not x_api_key:
        raise HTTPException(
            status_code=401,
            detail="Unauthorized: Missing X-API-Key header",
        )

    allowed_keys = get_allowed_keys()
    for valid_key in allowed_keys:
        if secrets.compare_digest(x_api_key, valid_key):
            return x_api_key

    raise HTTPException(
        status_code=401,
        detail="Unauthorized: Invalid X-API-Key header",
    )
