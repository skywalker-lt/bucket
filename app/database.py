import os
import uuid
from datetime import datetime, timedelta, timezone

import aiosqlite

from app.config import settings

_db_path: str = ""

SCHEMA = """
CREATE TABLE IF NOT EXISTS files (
    id TEXT PRIMARY KEY,
    original_name TEXT NOT NULL,
    stored_name TEXT NOT NULL,
    size INTEGER NOT NULL,
    nonce_hex TEXT NOT NULL,
    uploaded_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS webauthn_credentials (
    id TEXT PRIMARY KEY,
    credential_id TEXT NOT NULL UNIQUE,
    public_key BLOB NOT NULL,
    sign_count INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS sessions (
    token TEXT PRIMARY KEY,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL
);
"""


async def init_db() -> None:
    global _db_path
    _db_path = settings.database_path
    os.makedirs(os.path.dirname(_db_path), exist_ok=True)
    async with aiosqlite.connect(_db_path) as db:
        await db.executescript(SCHEMA)
        await db.commit()


async def get_db() -> aiosqlite.Connection:
    return await aiosqlite.connect(_db_path)


# --- Files ---

async def create_file(original_name: str, stored_name: str, size: int, nonce_hex: str) -> str:
    file_id = uuid.uuid4().hex
    now = datetime.now(timezone.utc).isoformat()
    async with aiosqlite.connect(_db_path) as db:
        await db.execute(
            "INSERT INTO files (id, original_name, stored_name, size, nonce_hex, uploaded_at) VALUES (?, ?, ?, ?, ?, ?)",
            (file_id, original_name, stored_name, size, nonce_hex, now),
        )
        await db.commit()
    return file_id


async def list_files() -> list[dict]:
    async with aiosqlite.connect(_db_path) as db:
        db.row_factory = aiosqlite.Row
        cursor = await db.execute("SELECT id, original_name, size, uploaded_at FROM files ORDER BY uploaded_at DESC")
        rows = await cursor.fetchall()
        return [dict(row) for row in rows]


async def get_file(file_id: str) -> dict | None:
    async with aiosqlite.connect(_db_path) as db:
        db.row_factory = aiosqlite.Row
        cursor = await db.execute("SELECT * FROM files WHERE id = ?", (file_id,))
        row = await cursor.fetchone()
        return dict(row) if row else None


async def delete_file(file_id: str) -> dict | None:
    async with aiosqlite.connect(_db_path) as db:
        db.row_factory = aiosqlite.Row
        cursor = await db.execute("SELECT * FROM files WHERE id = ?", (file_id,))
        row = await cursor.fetchone()
        if not row:
            return None
        record = dict(row)
        await db.execute("DELETE FROM files WHERE id = ?", (file_id,))
        await db.commit()
        return record


# --- WebAuthn Credentials ---

async def store_credential(credential_id: str, public_key: bytes, sign_count: int) -> str:
    cred_id = uuid.uuid4().hex
    now = datetime.now(timezone.utc).isoformat()
    async with aiosqlite.connect(_db_path) as db:
        await db.execute(
            "INSERT INTO webauthn_credentials (id, credential_id, public_key, sign_count, created_at) VALUES (?, ?, ?, ?, ?)",
            (cred_id, credential_id, public_key, sign_count, now),
        )
        await db.commit()
    return cred_id


async def get_credential_by_id(credential_id: str) -> dict | None:
    async with aiosqlite.connect(_db_path) as db:
        db.row_factory = aiosqlite.Row
        cursor = await db.execute("SELECT * FROM webauthn_credentials WHERE credential_id = ?", (credential_id,))
        row = await cursor.fetchone()
        return dict(row) if row else None


async def get_all_credentials() -> list[dict]:
    async with aiosqlite.connect(_db_path) as db:
        db.row_factory = aiosqlite.Row
        cursor = await db.execute("SELECT * FROM webauthn_credentials")
        rows = await cursor.fetchall()
        return [dict(row) for row in rows]


async def update_sign_count(credential_id: str, new_count: int) -> None:
    async with aiosqlite.connect(_db_path) as db:
        await db.execute(
            "UPDATE webauthn_credentials SET sign_count = ? WHERE credential_id = ?",
            (new_count, credential_id),
        )
        await db.commit()


async def credential_count() -> int:
    async with aiosqlite.connect(_db_path) as db:
        cursor = await db.execute("SELECT COUNT(*) FROM webauthn_credentials")
        row = await cursor.fetchone()
        return row[0]


# --- Sessions ---

async def create_session() -> str:
    token = uuid.uuid4().hex
    now = datetime.now(timezone.utc)
    expires = now + timedelta(hours=24)
    async with aiosqlite.connect(_db_path) as db:
        await db.execute(
            "INSERT INTO sessions (token, created_at, expires_at) VALUES (?, ?, ?)",
            (token, now.isoformat(), expires.isoformat()),
        )
        await db.commit()
    return token


async def validate_session(token: str) -> bool:
    async with aiosqlite.connect(_db_path) as db:
        cursor = await db.execute("SELECT expires_at FROM sessions WHERE token = ?", (token,))
        row = await cursor.fetchone()
        if not row:
            return False
        expires = datetime.fromisoformat(row[0])
        if expires.tzinfo is None:
            expires = expires.replace(tzinfo=timezone.utc)
        return datetime.now(timezone.utc) < expires


async def delete_session(token: str) -> None:
    async with aiosqlite.connect(_db_path) as db:
        await db.execute("DELETE FROM sessions WHERE token = ?", (token,))
        await db.commit()
