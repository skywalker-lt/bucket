import time
from collections import defaultdict

from fastapi import Request, HTTPException, status

from app import database

# --- Session dependency ---

async def get_current_session(request: Request) -> str:
    """Validate session cookie. Returns session token or raises 401."""
    token = request.cookies.get("session")
    if not token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated")
    valid = await database.validate_session(token)
    if not valid:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Session expired")
    return token


# --- Rate limiter ---

class RateLimiter:
    """Simple in-memory token bucket rate limiter."""

    def __init__(self, max_requests: int, window_seconds: int):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self._requests: dict[str, list[float]] = defaultdict(list)

    def _clean(self, key: str) -> None:
        cutoff = time.time() - self.window_seconds
        self._requests[key] = [t for t in self._requests[key] if t > cutoff]

    def check(self, key: str) -> bool:
        self._clean(key)
        if len(self._requests[key]) >= self.max_requests:
            return False
        self._requests[key].append(time.time())
        return True


auth_limiter = RateLimiter(max_requests=20, window_seconds=60)
sms_limiter = RateLimiter(max_requests=5, window_seconds=3600)


def check_auth_rate_limit(request: Request) -> None:
    client_ip = request.client.host if request.client else "unknown"
    if not auth_limiter.check(client_ip):
        raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail="Too many requests")


def check_sms_rate_limit(request: Request) -> None:
    client_ip = request.client.host if request.client else "unknown"
    if not sms_limiter.check(client_ip):
        raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail="Too many SMS requests")
