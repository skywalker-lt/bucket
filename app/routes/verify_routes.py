import time
import hashlib
import hmac
import secrets

from fastapi import APIRouter, Request, Depends, HTTPException, status

from app import auth, sms
from app.config import settings
from app.dependencies import get_current_session, check_auth_rate_limit, check_sms_rate_limit

router = APIRouter(prefix="/verify", tags=["verify"])

# Single-use download tokens: {token_hash: (file_id, expires_at)}
_download_tokens: dict[str, tuple[str, float]] = {}
_TOKEN_TTL = 60  # seconds


def _clean_tokens() -> None:
    now = time.time()
    expired = [k for k, (_, exp) in _download_tokens.items() if now > exp]
    for k in expired:
        del _download_tokens[k]


def _sign_token(token: str) -> str:
    return hmac.new(
        settings.session_secret.encode(), token.encode(), hashlib.sha256
    ).hexdigest()


def create_download_token(file_id: str) -> str:
    """Create a signed, single-use, time-limited download token for a file."""
    _clean_tokens()
    raw_token = secrets.token_urlsafe(32)
    token_hash = _sign_token(raw_token)
    _download_tokens[token_hash] = (file_id, time.time() + _TOKEN_TTL)
    return raw_token


def validate_download_token(token: str, file_id: str) -> bool:
    """Validate and consume a download token."""
    _clean_tokens()
    token_hash = _sign_token(token)
    entry = _download_tokens.pop(token_hash, None)
    if entry is None:
        return False
    stored_file_id, expires_at = entry
    if time.time() > expires_at:
        return False
    return stored_file_id == file_id


@router.post("/passkey/options")
async def verify_passkey_options(
    request: Request,
    session: str = Depends(get_current_session),
):
    """Generate WebAuthn assertion options for download verification."""
    check_auth_rate_limit(request)
    options = await auth.create_authentication_options(challenge_key="download-verify")
    return options


@router.post("/passkey/complete")
async def verify_passkey_complete(
    request: Request,
    session: str = Depends(get_current_session),
):
    """Verify passkey assertion and issue download token."""
    check_auth_rate_limit(request)
    body = await request.json()
    file_id = body.get("file_id")
    credential = body.get("credential")
    if not file_id or not credential:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Missing file_id or credential")

    success = await auth.complete_authentication(credential, challenge_key="download-verify")
    if not success:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Passkey verification failed")

    token = create_download_token(file_id)
    return {"download_token": token}


@router.post("/sms/send")
async def verify_sms_send(
    request: Request,
    session: str = Depends(get_current_session),
):
    """Send OTP via SMS for download verification."""
    check_sms_rate_limit(request)
    success, message = await sms.send_otp()
    if not success:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=message)
    return {"status": "sent"}


@router.post("/sms/check")
async def verify_sms_check(
    request: Request,
    session: str = Depends(get_current_session),
):
    """Verify SMS OTP and issue download token."""
    check_sms_rate_limit(request)
    body = await request.json()
    code = body.get("code")
    file_id = body.get("file_id")
    if not code or not file_id:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Missing code or file_id")

    success, message = await sms.check_otp(code)
    if not success:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=message)

    token = create_download_token(file_id)
    return {"download_token": token}
