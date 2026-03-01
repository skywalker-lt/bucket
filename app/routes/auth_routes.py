from fastapi import APIRouter, Request, Response, Depends, HTTPException, status

from app import auth, database
from app.dependencies import get_current_session, check_auth_rate_limit

router = APIRouter(prefix="/auth", tags=["auth"])


@router.post("/register/options")
async def register_options(request: Request):
    """Generate WebAuthn registration options. Only allowed if no credentials exist."""
    check_auth_rate_limit(request)
    count = await database.credential_count()
    if count > 0:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Registration is closed. A passkey is already registered.",
        )
    options = await auth.create_registration_options()
    return options


@router.post("/register/verify")
async def register_verify(request: Request, response: Response):
    """Verify WebAuthn registration and create session."""
    check_auth_rate_limit(request)
    count = await database.credential_count()
    if count > 0:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Registration is closed.",
        )
    credential = await request.json()
    success = await auth.complete_registration(credential)
    if not success:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Registration failed")
    token = await database.create_session()
    response.set_cookie(
        key="session",
        value=token,
        httponly=True,
        secure=True,
        samesite="strict",
        max_age=86400,
    )
    return {"status": "ok"}


@router.post("/login/options")
async def login_options(request: Request):
    """Generate WebAuthn authentication options."""
    check_auth_rate_limit(request)
    count = await database.credential_count()
    if count == 0:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="No passkey registered. Please register first.",
        )
    options = await auth.create_authentication_options()
    return options


@router.post("/login/verify")
async def login_verify(request: Request, response: Response):
    """Verify WebAuthn authentication and create session."""
    check_auth_rate_limit(request)
    credential = await request.json()
    success = await auth.complete_authentication(credential)
    if not success:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Authentication failed")
    token = await database.create_session()
    response.set_cookie(
        key="session",
        value=token,
        httponly=True,
        secure=True,
        samesite="strict",
        max_age=86400,
    )
    return {"status": "ok"}


@router.post("/logout")
async def logout(response: Response, session: str = Depends(get_current_session)):
    """Delete session and clear cookie."""
    await database.delete_session(session)
    response.delete_cookie("session")
    return {"status": "ok"}
