"""End-to-end test for CatVault upload and download flow."""
import os
import sys
import hashlib
import time
import json
import hmac
import struct

# Run inside the Docker container where the app is running

def compute_sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def test_full_flow():
    """Test: create file -> upload (chunked) -> verify on disk is encrypted -> download -> verify matches original."""
    import httpx

    BASE = "http://localhost:8000"
    client = httpx.Client(base_url=BASE, follow_redirects=False)

    # Step 1: Check app is running
    resp = client.get("/")
    assert resp.status_code in (200, 302), f"App not responding: {resp.status_code}"
    print("[PASS] App is running")

    # Step 2: Create a fake session directly in the database
    import asyncio
    sys.path.insert(0, "/app")

    from app import database, crypto
    from app.config import settings

    async def setup():
        await database.init_db()
        crypto.derive_key()

        # Create a session token (create_session generates its own)
        token = await database.create_session()
        return token

    token = asyncio.run(setup())
    print(f"[PASS] Created test session")

    # Set session cookie
    client.cookies.set("session", token)

    # Step 3: Verify we can access the vault
    resp = client.get("/vault")
    assert resp.status_code == 200, f"Cannot access vault: {resp.status_code}"
    print("[PASS] Vault page accessible with session")

    # Step 4: Create test file with random data
    test_data = os.urandom(256 * 1024)  # 256 KB random file
    original_hash = compute_sha256(test_data)
    print(f"[INFO] Test file: 256 KB, SHA-256: {original_hash[:16]}...")

    # Step 5: Upload via single-request endpoint (small file)
    import io
    resp = client.post(
        "/vault/upload",
        files={"file": ("test_e2e_file.bin", io.BytesIO(test_data), "application/octet-stream")},
    )
    assert resp.status_code == 200, f"Upload failed: {resp.status_code} {resp.text}"
    upload_result = resp.json()
    assert upload_result.get("status") == "ok", f"Upload not ok: {upload_result}"
    print("[PASS] File uploaded successfully")

    # Step 6: Check vault page shows the file
    resp = client.get("/vault")
    assert resp.status_code == 200
    assert "test_e2e_file.bin" in resp.text, "File not shown in vault"
    print("[PASS] File appears in vault listing")

    # Step 7: Get the file ID from database
    async def get_file_info():
        files = await database.list_files()
        for f in files:
            if f["original_name"] == "test_e2e_file.bin":
                # list_files only returns id, original_name, size, uploaded_at
                # Use get_file for full info
                return await database.get_file(f["id"])
        return None

    file_info = asyncio.run(get_file_info())
    assert file_info is not None, "File not found in database"
    file_id = file_info["id"]
    stored_name = file_info["stored_name"]
    nonce_hex = file_info["nonce_hex"]
    print(f"[PASS] File in DB: id={file_id}, stored_name={stored_name}")

    # Step 8: Verify encrypted file on disk is NOT the same as original
    encrypted_path = os.path.join(settings.storage_path, stored_name)
    assert os.path.exists(encrypted_path), f"Encrypted file not on disk: {encrypted_path}"
    with open(encrypted_path, "rb") as f:
        encrypted_data = f.read()
    disk_hash = compute_sha256(encrypted_data)
    assert disk_hash != original_hash, "FAIL: File on disk matches original (not encrypted)"
    print("[PASS] File on disk is encrypted (different hash from original)")

    # Step 9: Verify we can decrypt the file correctly
    nonce = bytes.fromhex(nonce_hex)
    decrypted = crypto.decrypt_file(nonce, encrypted_data)
    decrypted_hash = compute_sha256(decrypted)
    assert decrypted_hash == original_hash, f"Decrypted hash mismatch: {decrypted_hash} vs {original_hash}"
    print("[PASS] Decrypted file matches original (AES-256-GCM round-trip)")

    # Step 10: Create a download token and test download endpoint
    from app.routes.verify_routes import create_download_token, _download_tokens
    dl_token = create_download_token(file_id)
    print(f"[INFO] Download token created: {dl_token[:16]}...")

    resp = client.get(f"/vault/download/{file_id}", params={"token": dl_token})
    assert resp.status_code == 200, f"Download failed: {resp.status_code} {resp.text}"
    downloaded_hash = compute_sha256(resp.content)
    assert downloaded_hash == original_hash, f"Downloaded hash mismatch: {downloaded_hash} vs {original_hash}"
    print("[PASS] Downloaded file matches original")

    # Step 11: Verify token is single-use (reuse should fail)
    resp2 = client.get(f"/vault/download/{file_id}", params={"token": dl_token})
    assert resp2.status_code == 403, f"Token reuse should be rejected, got: {resp2.status_code}"
    print("[PASS] Download token is single-use (reuse rejected)")

    # Step 12: Verify expired token is rejected
    expired_token = create_download_token(file_id)
    # Manually expire it by modifying the expiry in the store
    from app.routes.verify_routes import _sign_token
    token_hash = _sign_token(expired_token)
    if token_hash in _download_tokens:
        fid, _ = _download_tokens[token_hash]
        _download_tokens[token_hash] = (fid, time.time() - 10)
    resp3 = client.get(f"/vault/download/{file_id}", params={"token": expired_token})
    assert resp3.status_code == 403, f"Expired token should be rejected, got: {resp3.status_code}"
    print("[PASS] Expired download tokens are rejected")

    # Step 13: Verify token bound to wrong file is rejected
    wrong_file_token = create_download_token(99999)
    resp4 = client.get(f"/vault/download/{file_id}", params={"token": wrong_file_token})
    assert resp4.status_code == 403, f"Wrong-file token should be rejected, got: {resp4.status_code}"
    print("[PASS] Download token bound to specific file (wrong file rejected)")

    # Step 14: Test chunked upload flow
    chunk_data = os.urandom(512 * 1024)  # 512 KB
    chunk_hash = compute_sha256(chunk_data)

    # Start chunked upload
    resp = client.post("/vault/upload/start", json={
        "filename": "chunked_test.bin",
        "total_size": len(chunk_data),
        "total_chunks": 1,
    })
    assert resp.status_code == 200, f"Chunk start failed: {resp.status_code} {resp.text}"
    upload_id = resp.json()["upload_id"]
    print(f"[PASS] Chunked upload started: {upload_id}")

    # Upload the single chunk
    resp = client.post("/vault/upload/chunk", data={
        "upload_id": upload_id,
        "chunk_index": 0,
    }, files={
        "file": ("chunk_0", io.BytesIO(chunk_data), "application/octet-stream"),
    })
    assert resp.status_code == 200, f"Chunk upload failed: {resp.status_code} {resp.text}"
    print("[PASS] Chunk uploaded")

    # Complete the upload
    resp = client.post("/vault/upload/complete", json={"upload_id": upload_id})
    assert resp.status_code == 200, f"Chunk complete failed: {resp.status_code} {resp.text}"
    print("[PASS] Chunked upload completed")

    # Verify chunked file in vault
    resp = client.get("/vault")
    assert "chunked_test.bin" in resp.text, "Chunked file not in vault"
    print("[PASS] Chunked file appears in vault")

    # Get chunked file info and verify download
    async def get_chunked_file():
        files = await database.list_files()
        for f in files:
            if f["original_name"] == "chunked_test.bin":
                return await database.get_file(f["id"])
        return None

    chunked_info = asyncio.run(get_chunked_file())
    assert chunked_info is not None
    chunked_id = chunked_info["id"]

    dl_token2 = create_download_token(chunked_id)
    resp = client.get(f"/vault/download/{chunked_id}", params={"token": dl_token2})
    assert resp.status_code == 200, f"Chunked download failed: {resp.status_code}"
    assert compute_sha256(resp.content) == chunk_hash, "Chunked file hash mismatch"
    print("[PASS] Chunked upload -> download round-trip verified")

    # Cleanup
    async def cleanup():
        db = await database.get_db()
        await db.execute("DELETE FROM files WHERE original_name IN ('test_e2e_file.bin', 'chunked_test.bin')")
        await db.commit()
        await db.close()
    asyncio.run(cleanup())

    # Remove test files from disk
    for info in [file_info, chunked_info]:
        path = os.path.join(settings.storage_path, info["stored_name"])
        if os.path.exists(path):
            os.remove(path)

    print("\n" + "=" * 50)
    print("ALL E2E TESTS PASSED")
    print("=" * 50)


if __name__ == "__main__":
    test_full_flow()
