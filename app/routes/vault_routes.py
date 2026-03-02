import os
import uuid
import shutil
import logging

from fastapi import APIRouter, Request, Depends, UploadFile, File, Form, HTTPException, status
from fastapi.responses import HTMLResponse, Response
from starlette.responses import StreamingResponse

from app import database, crypto
from app.config import settings
from app.dependencies import get_current_session

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/vault", tags=["vault"])

CHUNK_DIR = os.path.join(settings.storage_path, "_chunks")


@router.get("", response_class=HTMLResponse)
async def vault_page(request: Request, session: str = Depends(get_current_session)):
    """Render the vault file list."""
    files = await database.list_files()
    sms_configured = bool(settings.twilio_account_sid and settings.twilio_verify_service_sid)
    templates = request.app.state.templates
    return templates.TemplateResponse("vault.html", {
        "request": request,
        "files": files,
        "sms_configured": sms_configured,
    })


@router.post("/upload/start")
async def upload_start(
    request: Request,
    session: str = Depends(get_current_session),
):
    """Start a chunked upload. Returns an upload_id."""
    body = await request.json()
    filename = body.get("filename", "")
    total_size = body.get("total_size", 0)
    total_chunks = body.get("total_chunks", 0)

    if not filename or total_chunks < 1:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Missing filename or total_chunks")

    upload_id = uuid.uuid4().hex
    upload_dir = os.path.join(CHUNK_DIR, upload_id)
    os.makedirs(upload_dir, exist_ok=True)

    # Write metadata
    import json
    meta = {"filename": filename, "total_size": total_size, "total_chunks": total_chunks}
    with open(os.path.join(upload_dir, "_meta.json"), "w") as f:
        json.dump(meta, f)

    return {"upload_id": upload_id}


@router.post("/upload/chunk")
async def upload_chunk(
    request: Request,
    upload_id: str = Form(...),
    chunk_index: int = Form(...),
    file: UploadFile = File(...),
    session: str = Depends(get_current_session),
):
    """Upload a single chunk."""
    upload_dir = os.path.join(CHUNK_DIR, upload_id)
    if not os.path.isdir(upload_dir):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Unknown upload_id")

    chunk_path = os.path.join(upload_dir, f"chunk_{chunk_index:06d}")
    contents = await file.read()
    with open(chunk_path, "wb") as f:
        f.write(contents)

    return {"status": "ok", "chunk_index": chunk_index}


@router.post("/upload/complete")
async def upload_complete(
    request: Request,
    session: str = Depends(get_current_session),
):
    """Reassemble chunks, encrypt, and store the file."""
    import json

    body = await request.json()
    upload_id = body.get("upload_id", "")
    upload_dir = os.path.join(CHUNK_DIR, upload_id)

    if not os.path.isdir(upload_dir):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Unknown upload_id")

    meta_path = os.path.join(upload_dir, "_meta.json")
    with open(meta_path) as f:
        meta = json.load(f)

    total_chunks = meta["total_chunks"]
    filename = meta["filename"]

    # Verify all chunks exist
    for i in range(total_chunks):
        chunk_path = os.path.join(upload_dir, f"chunk_{i:06d}")
        if not os.path.exists(chunk_path):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Missing chunk {i}",
            )

    # Reassemble into a single bytes buffer, then encrypt
    parts = []
    total_size = 0
    for i in range(total_chunks):
        chunk_path = os.path.join(upload_dir, f"chunk_{i:06d}")
        with open(chunk_path, "rb") as f:
            data = f.read()
        parts.append(data)
        total_size += len(data)

    plaintext = b"".join(parts)
    parts = None  # free memory

    nonce, ciphertext = crypto.encrypt_file(plaintext)
    plaintext = None  # free memory

    stored_name = uuid.uuid4().hex
    os.makedirs(settings.storage_path, exist_ok=True)
    filepath = os.path.join(settings.storage_path, stored_name)
    with open(filepath, "wb") as f:
        f.write(ciphertext)

    await database.create_file(
        original_name=filename,
        stored_name=stored_name,
        size=total_size,
        nonce_hex=nonce.hex(),
    )

    # Clean up chunks
    shutil.rmtree(upload_dir, ignore_errors=True)

    return {"status": "ok"}


@router.post("/delete/{file_id}")
async def delete_file(
    file_id: str,
    session: str = Depends(get_current_session),
):
    """Delete a file from disk and database."""
    file_meta = await database.get_file(file_id)
    if not file_meta:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="File not found")

    filepath = os.path.join(settings.storage_path, file_meta["stored_name"])
    if os.path.exists(filepath):
        os.remove(filepath)

    await database.delete_file(file_id)
    return {"status": "ok"}


@router.post("/upload")
async def upload_file(
    request: Request,
    file: UploadFile = File(...),
    session: str = Depends(get_current_session),
):
    """Simple single-request upload for small files."""
    contents = await file.read()
    if len(contents) > settings.max_upload_size:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail="File too large",
        )
    if not file.filename:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="No filename")

    nonce, ciphertext = crypto.encrypt_file(contents)
    stored_name = uuid.uuid4().hex
    storage_dir = settings.storage_path
    os.makedirs(storage_dir, exist_ok=True)
    filepath = os.path.join(storage_dir, stored_name)
    with open(filepath, "wb") as f:
        f.write(ciphertext)

    await database.create_file(
        original_name=file.filename,
        stored_name=stored_name,
        size=len(contents),
        nonce_hex=nonce.hex(),
    )
    return {"status": "ok"}


@router.get("/download/{file_id}")
async def download_file(
    file_id: str,
    token: str,
    session: str = Depends(get_current_session),
):
    """Download a file after verifying the download token."""
    from app.routes.verify_routes import validate_download_token

    if not validate_download_token(token, file_id):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Invalid or expired download token")

    file_meta = await database.get_file(file_id)
    if not file_meta:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="File not found")

    filepath = os.path.join(settings.storage_path, file_meta["stored_name"])
    if not os.path.exists(filepath):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="File data missing")

    with open(filepath, "rb") as f:
        ciphertext = f.read()

    nonce = bytes.fromhex(file_meta["nonce_hex"])
    plaintext = crypto.decrypt_file(nonce, ciphertext)

    return Response(
        content=plaintext,
        media_type="application/octet-stream",
        headers={
            "Content-Disposition": f'attachment; filename="{file_meta["original_name"]}"',
            "X-Content-Type-Options": "nosniff",
            "Content-Security-Policy": "default-src 'none'",
        },
    )
