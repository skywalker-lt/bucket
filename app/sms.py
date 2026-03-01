import time

from app.config import settings

# Rate limiting state
_send_timestamps: list[float] = []
_check_attempts: dict[str, int] = {}
_MAX_SENDS_PER_HOUR = 5
_MAX_CHECK_ATTEMPTS = 3


def _clean_send_timestamps() -> None:
    cutoff = time.time() - 3600
    _send_timestamps[:] = [ts for ts in _send_timestamps if ts > cutoff]


async def send_otp() -> tuple[bool, str]:
    """Send OTP via Twilio Verify. Returns (success, message)."""
    if not settings.twilio_account_sid or not settings.twilio_verify_service_sid:
        return False, "SMS not configured"

    _clean_send_timestamps()
    if len(_send_timestamps) >= _MAX_SENDS_PER_HOUR:
        return False, "Rate limit exceeded. Try again later."

    try:
        from twilio.rest import Client

        client = Client(settings.twilio_account_sid, settings.twilio_auth_token)
        verification = client.verify.v2.services(
            settings.twilio_verify_service_sid
        ).verifications.create(to=settings.owner_phone_number, channel="sms")

        _send_timestamps.append(time.time())
        sid = verification.sid
        _check_attempts[sid] = 0
        return True, sid
    except Exception as e:
        return False, str(e)


async def check_otp(code: str) -> tuple[bool, str]:
    """Check OTP via Twilio Verify. Returns (success, message)."""
    if not settings.twilio_account_sid or not settings.twilio_verify_service_sid:
        return False, "SMS not configured"

    try:
        from twilio.rest import Client

        client = Client(settings.twilio_account_sid, settings.twilio_auth_token)
        verification_check = client.verify.v2.services(
            settings.twilio_verify_service_sid
        ).verification_checks.create(
            to=settings.owner_phone_number, code=code
        )

        if verification_check.status == "approved":
            return True, "Verified"
        return False, "Invalid code"
    except Exception as e:
        return False, str(e)
