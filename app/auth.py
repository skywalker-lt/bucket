import json
import logging
import time
import os
import base64

from webauthn import (
    generate_registration_options,
    verify_registration_response,
    generate_authentication_options,
    verify_authentication_response,
)
from webauthn.helpers.structs import (
    PublicKeyCredentialDescriptor,
    UserVerificationRequirement,
    AuthenticatorSelectionCriteria,
    ResidentKeyRequirement,
)
from webauthn.helpers import options_to_json

from app.config import settings
from app import database

logger = logging.getLogger(__name__)

# In-memory challenge store with TTL (5 minutes)
_challenges: dict[str, tuple[bytes, float]] = {}
_CHALLENGE_TTL = 300


def _clean_challenges() -> None:
    now = time.time()
    expired = [k for k, (_, ts) in _challenges.items() if now - ts > _CHALLENGE_TTL]
    for k in expired:
        del _challenges[k]


def store_challenge(key: str, challenge: bytes) -> None:
    _clean_challenges()
    _challenges[key] = (challenge, time.time())


def get_challenge(key: str) -> bytes | None:
    _clean_challenges()
    entry = _challenges.pop(key, None)
    if entry is None:
        return None
    return entry[0]


async def create_registration_options() -> dict:
    user_id = os.urandom(32)
    options = generate_registration_options(
        rp_id=settings.rp_id,
        rp_name=settings.rp_name,
        user_id=user_id,
        user_name="vault-owner",
        user_display_name="Vault Owner",
        authenticator_selection=AuthenticatorSelectionCriteria(
            resident_key=ResidentKeyRequirement.PREFERRED,
            user_verification=UserVerificationRequirement.PREFERRED,
        ),
    )
    store_challenge("registration", options.challenge)
    # Use the library's serializer for guaranteed correct format
    return json.loads(options_to_json(options))


async def complete_registration(credential: dict) -> bool:
    challenge = get_challenge("registration")
    if challenge is None:
        logger.error("Registration failed: no challenge found")
        return False
    try:
        verification = verify_registration_response(
            credential=credential,
            expected_challenge=challenge,
            expected_rp_id=settings.rp_id,
            expected_origin=settings.rp_origin,
        )
        cred_id_b64 = base64.urlsafe_b64encode(
            verification.credential_id
        ).rstrip(b"=").decode()
        await database.store_credential(
            credential_id=cred_id_b64,
            public_key=verification.credential_public_key,
            sign_count=verification.sign_count,
        )
        return True
    except Exception as e:
        logger.error("Registration verification failed: %s", e)
        return False


async def create_authentication_options(challenge_key: str = "authentication") -> dict:
    creds = await database.get_all_credentials()
    allow_credentials = []
    for c in creds:
        raw = base64.urlsafe_b64decode(c["credential_id"] + "==")
        allow_credentials.append(
            PublicKeyCredentialDescriptor(id=raw)
        )

    options = generate_authentication_options(
        rp_id=settings.rp_id,
        allow_credentials=allow_credentials,
        user_verification=UserVerificationRequirement.PREFERRED,
    )
    store_challenge(challenge_key, options.challenge)
    # Use the library's serializer for guaranteed correct format
    return json.loads(options_to_json(options))


async def complete_authentication(credential: dict, challenge_key: str = "authentication") -> bool:
    challenge = get_challenge(challenge_key)
    if challenge is None:
        logger.error("Authentication failed: no challenge found")
        return False

    raw_id_b64 = credential.get("rawId") or credential.get("id", "")
    padding = 4 - len(raw_id_b64) % 4
    if padding != 4:
        raw_id_b64 += "=" * padding
    try:
        raw_id = base64.urlsafe_b64decode(raw_id_b64)
    except Exception:
        logger.error("Authentication failed: invalid rawId")
        return False

    cred_id_b64 = base64.urlsafe_b64encode(raw_id).rstrip(b"=").decode()
    stored = await database.get_credential_by_id(cred_id_b64)
    if not stored:
        logger.error("Authentication failed: credential not found for id %s", cred_id_b64)
        return False

    try:
        verification = verify_authentication_response(
            credential=credential,
            expected_challenge=challenge,
            expected_rp_id=settings.rp_id,
            expected_origin=settings.rp_origin,
            credential_public_key=stored["public_key"],
            credential_current_sign_count=stored["sign_count"],
        )
        await database.update_sign_count(cred_id_b64, verification.new_sign_count)
        return True
    except Exception as e:
        logger.error("Authentication verification failed: %s", e)
        return False
