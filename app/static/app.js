// Utility: show status message
function showStatus(elemId, message, type) {
    var el = document.getElementById(elemId);
    if (!el) return;
    el.textContent = message;
    el.className = 'status-msg ' + type;
}

function hideStatus(elemId) {
    var el = document.getElementById(elemId);
    if (!el) return;
    el.className = 'status-msg hidden';
}

// Base64URL helpers
function bufferToBase64url(buffer) {
    var bytes = new Uint8Array(buffer);
    var str = '';
    for (var i = 0; i < bytes.length; i++) str += String.fromCharCode(bytes[i]);
    return btoa(str).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function base64urlToBuffer(base64url) {
    var base64 = base64url.replace(/-/g, '+').replace(/_/g, '/');
    var pad = base64.length % 4;
    if (pad) base64 += '='.repeat(4 - pad);
    var binary = atob(base64);
    var bytes = new Uint8Array(binary.length);
    for (var i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
    return bytes.buffer;
}

// --- WebAuthn Registration ---
async function registerPasskey() {
    var btn = document.getElementById('btn-register');
    btn.disabled = true;
    hideStatus('status-msg');
    try {
        var resp = await fetch('/auth/register/options', { method: 'POST' });
        if (!resp.ok) {
            var err = await resp.json();
            throw new Error(err.detail || 'Failed to get registration options');
        }
        var opts = await resp.json();

        // The server returns flat options (from py-webauthn options_to_json).
        // Build the publicKey object for navigator.credentials.create().
        var publicKey = {
            rp: opts.rp,
            user: {
                id: base64urlToBuffer(opts.user.id),
                name: opts.user.name,
                displayName: opts.user.displayName
            },
            challenge: base64urlToBuffer(opts.challenge),
            pubKeyCredParams: opts.pubKeyCredParams,
            timeout: opts.timeout || 60000,
            attestation: opts.attestation || 'none',
            authenticatorSelection: opts.authenticatorSelection || {}
        };

        if (opts.excludeCredentials) {
            publicKey.excludeCredentials = opts.excludeCredentials.map(function(c) {
                return { type: c.type, id: base64urlToBuffer(c.id) };
            });
        }

        var credential = await navigator.credentials.create({ publicKey: publicKey });

        var body = {
            id: credential.id,
            rawId: bufferToBase64url(credential.rawId),
            type: credential.type,
            response: {
                attestationObject: bufferToBase64url(credential.response.attestationObject),
                clientDataJSON: bufferToBase64url(credential.response.clientDataJSON)
            }
        };

        var verifyResp = await fetch('/auth/register/verify', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(body)
        });

        if (!verifyResp.ok) {
            var verifyErr = await verifyResp.json();
            throw new Error(verifyErr.detail || 'Registration failed');
        }

        window.location.href = '/vault';
    } catch (e) {
        console.error('Registration error:', e);
        showStatus('status-msg', 'Registration error: ' + (e.message || e), 'error');
        btn.disabled = false;
    }
}

// --- WebAuthn Login ---
async function loginPasskey() {
    var btn = document.getElementById('btn-login');
    btn.disabled = true;
    hideStatus('status-msg');
    try {
        var resp = await fetch('/auth/login/options', { method: 'POST' });
        if (!resp.ok) {
            var err = await resp.json();
            throw new Error(err.detail || 'Failed to get login options');
        }
        var opts = await resp.json();

        var publicKey = {
            rpId: opts.rpId,
            challenge: base64urlToBuffer(opts.challenge),
            timeout: opts.timeout || 60000,
            userVerification: opts.userVerification || 'preferred'
        };

        if (opts.allowCredentials) {
            publicKey.allowCredentials = opts.allowCredentials.map(function(c) {
                return { type: c.type, id: base64urlToBuffer(c.id) };
            });
        }

        var assertion = await navigator.credentials.get({ publicKey: publicKey });

        var body = {
            id: assertion.id,
            rawId: bufferToBase64url(assertion.rawId),
            type: assertion.type,
            response: {
                authenticatorData: bufferToBase64url(assertion.response.authenticatorData),
                clientDataJSON: bufferToBase64url(assertion.response.clientDataJSON),
                signature: bufferToBase64url(assertion.response.signature),
                userHandle: assertion.response.userHandle
                    ? bufferToBase64url(assertion.response.userHandle)
                    : null
            }
        };

        var verifyResp = await fetch('/auth/login/verify', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(body)
        });

        if (!verifyResp.ok) {
            var verifyErr = await verifyResp.json();
            throw new Error(verifyErr.detail || 'Login failed');
        }

        window.location.href = '/vault';
    } catch (e) {
        console.error('Login error:', e);
        showStatus('status-msg', 'Login error: ' + (e.message || e), 'error');
        btn.disabled = false;
    }
}

// --- Logout ---
async function logout() {
    await fetch('/auth/logout', { method: 'POST' });
    window.location.href = '/';
}

// --- File Upload ---
var CHUNK_SIZE = 50 * 1024 * 1024; // 50 MB per chunk

function formatBytes(bytes) {
    if (bytes === 0) return '0 B';
    var units = ['B', 'KB', 'MB', 'GB'];
    var i = Math.floor(Math.log(bytes) / Math.log(1024));
    return (bytes / Math.pow(1024, i)).toFixed(1) + ' ' + units[i];
}

function showProgress(loaded, total, chunkInfo) {
    var bar = document.getElementById('upload-progress');
    var text = document.getElementById('upload-progress-text');
    var fill = document.getElementById('upload-progress-fill');
    if (!bar) return;
    bar.classList.remove('hidden');
    var pct = total > 0 ? Math.round((loaded / total) * 100) : 0;
    fill.style.width = pct + '%';
    var info = formatBytes(loaded) + ' / ' + formatBytes(total) + '  (' + pct + '%)';
    if (chunkInfo) info += '  —  ' + chunkInfo;
    text.textContent = info;
}

function hideProgress() {
    var bar = document.getElementById('upload-progress');
    if (bar) bar.classList.add('hidden');
}

function uploadChunkXHR(url, formData, onProgress) {
    return new Promise(function(resolve, reject) {
        var xhr = new XMLHttpRequest();
        xhr.upload.addEventListener('progress', function(e) {
            if (e.lengthComputable && onProgress) onProgress(e.loaded, e.total);
        });
        xhr.addEventListener('load', function() {
            if (xhr.status >= 200 && xhr.status < 300) {
                resolve(JSON.parse(xhr.responseText));
            } else {
                var msg = 'Upload failed';
                try { msg = JSON.parse(xhr.responseText).detail || msg; } catch(e) {}
                reject(new Error(msg));
            }
        });
        xhr.addEventListener('error', function() { reject(new Error('Network error')); });
        xhr.open('POST', url);
        xhr.send(formData);
    });
}

async function uploadFile(event) {
    event.preventDefault();
    hideStatus('status-msg');
    var fileInput = document.getElementById('file-input');
    if (!fileInput.files.length) return;

    var file = fileInput.files[0];
    var submitBtn = document.querySelector('#upload-form button[type="submit"]');
    var originalText = submitBtn.textContent;
    submitBtn.disabled = true;
    submitBtn.textContent = 'Uploading...';

    var totalSize = file.size;
    var totalChunks = Math.ceil(totalSize / CHUNK_SIZE);

    try {
        // Step 1: Start upload
        showProgress(0, totalSize, 'Starting...');
        var startResp = await fetch('/vault/upload/start', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                filename: file.name,
                total_size: totalSize,
                total_chunks: totalChunks
            })
        });
        if (!startResp.ok) {
            var err = await startResp.json();
            throw new Error(err.detail || 'Failed to start upload');
        }
        var startData = await startResp.json();
        var uploadId = startData.upload_id;

        // Step 2: Upload chunks
        var totalUploaded = 0;
        for (var i = 0; i < totalChunks; i++) {
            var start = i * CHUNK_SIZE;
            var end = Math.min(start + CHUNK_SIZE, totalSize);
            var chunk = file.slice(start, end);
            var chunkSize = end - start;

            var formData = new FormData();
            formData.append('upload_id', uploadId);
            formData.append('chunk_index', i.toString());
            formData.append('file', chunk, 'chunk');

            var chunkLabel = 'Chunk ' + (i + 1) + '/' + totalChunks;
            var baseUploaded = totalUploaded;

            await uploadChunkXHR('/vault/upload/chunk', formData, function(loaded, total) {
                showProgress(baseUploaded + loaded, totalSize, chunkLabel);
            });

            totalUploaded += chunkSize;
            showProgress(totalUploaded, totalSize, chunkLabel + ' done');
        }

        // Step 3: Finalize
        showProgress(totalSize, totalSize, 'Encrypting and saving...');
        var completeResp = await fetch('/vault/upload/complete', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ upload_id: uploadId })
        });
        if (!completeResp.ok) {
            var completeErr = await completeResp.json();
            throw new Error(completeErr.detail || 'Failed to finalize upload');
        }

        showProgress(totalSize, totalSize, 'Complete!');
        showStatus('status-msg', 'Upload complete!', 'success');
        setTimeout(function() { window.location.reload(); }, 500);
    } catch (e) {
        showStatus('status-msg', e.message, 'error');
        submitBtn.disabled = false;
        submitBtn.textContent = originalText;
        hideProgress();
    }
}

// --- Download Verification ---
var _pendingFileId = null;

function requestDownload(fileId) {
    _pendingFileId = fileId;
    hideStatus('verify-status');
    document.getElementById('verify-modal').classList.remove('hidden');

    var smsSection = document.getElementById('sms-section');
    var configEl = document.getElementById('vault-config');
    var smsConfigured = configEl && configEl.getAttribute('data-sms-configured') === 'true';
    if (smsConfigured) {
        smsSection.classList.remove('hidden');
    } else {
        smsSection.classList.add('hidden');
    }

    document.getElementById('sms-input-group').classList.add('hidden');
    document.getElementById('sms-code').value = '';
}

function closeModal() {
    document.getElementById('verify-modal').classList.add('hidden');
    _pendingFileId = null;
}

async function verifyWithPasskey() {
    hideStatus('verify-status');
    if (!_pendingFileId) {
        showStatus('verify-status', 'No file selected for download.', 'error');
        return;
    }
    try {
        var resp = await fetch('/verify/passkey/options', { method: 'POST' });
        if (!resp.ok) throw new Error('Failed to get verification options');
        var opts = await resp.json();

        var publicKey = {
            rpId: opts.rpId,
            challenge: base64urlToBuffer(opts.challenge),
            timeout: opts.timeout || 60000,
            userVerification: opts.userVerification || 'preferred'
        };

        if (opts.allowCredentials) {
            publicKey.allowCredentials = opts.allowCredentials.map(function(c) {
                return { type: c.type, id: base64urlToBuffer(c.id) };
            });
        }

        var assertion = await navigator.credentials.get({ publicKey: publicKey });

        var credential = {
            id: assertion.id,
            rawId: bufferToBase64url(assertion.rawId),
            type: assertion.type,
            response: {
                authenticatorData: bufferToBase64url(assertion.response.authenticatorData),
                clientDataJSON: bufferToBase64url(assertion.response.clientDataJSON),
                signature: bufferToBase64url(assertion.response.signature),
                userHandle: assertion.response.userHandle
                    ? bufferToBase64url(assertion.response.userHandle)
                    : null
            }
        };

        var verifyResp = await fetch('/verify/passkey/complete', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ file_id: _pendingFileId, credential: credential })
        });

        if (!verifyResp.ok) {
            var err = await verifyResp.json();
            throw new Error(err.detail || 'Verification failed');
        }

        var data = await verifyResp.json();
        triggerDownload(_pendingFileId, data.download_token);
        closeModal();
    } catch (e) {
        showStatus('verify-status', e.message, 'error');
    }
}

async function sendSmsOtp() {
    hideStatus('verify-status');
    var btn = document.getElementById('btn-send-sms');
    btn.disabled = true;
    try {
        var resp = await fetch('/verify/sms/send', { method: 'POST' });
        if (!resp.ok) {
            var err = await resp.json();
            throw new Error(err.detail || 'Failed to send SMS');
        }
        document.getElementById('sms-input-group').classList.remove('hidden');
        showStatus('verify-status', 'Code sent to your phone.', 'success');
    } catch (e) {
        showStatus('verify-status', e.message, 'error');
    } finally {
        btn.disabled = false;
    }
}

async function verifySmsCode() {
    hideStatus('verify-status');
    var code = document.getElementById('sms-code').value.trim();
    if (!code) return;

    try {
        var resp = await fetch('/verify/sms/check', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ code: code, file_id: _pendingFileId })
        });
        if (!resp.ok) {
            var err = await resp.json();
            throw new Error(err.detail || 'Verification failed');
        }
        var data = await resp.json();
        triggerDownload(_pendingFileId, data.download_token);
        closeModal();
    } catch (e) {
        showStatus('verify-status', e.message, 'error');
    }
}

function triggerDownload(fileId, token) {
    var url = '/vault/download/' + encodeURIComponent(fileId) + '?token=' + encodeURIComponent(token);
    var a = document.createElement('a');
    a.href = url;
    a.style.display = 'none';
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
}

// --- Delete File ---
async function deleteFile(fileId) {
    if (!window.confirm('Are you sure you want to delete this file? This cannot be undone.')) {
        return;
    }
    try {
        var resp = await fetch('/vault/delete/' + encodeURIComponent(fileId), { method: 'POST' });
        if (!resp.ok) {
            var err = await resp.json();
            throw new Error(err.detail || 'Delete failed');
        }
        window.location.reload();
    } catch (e) {
        showStatus('status-msg', 'Delete error: ' + e.message, 'error');
    }
}

// --- Event delegation: single click handler on document ---
document.addEventListener('click', function(e) {
    var target = e.target;

    // Helper: check if click target is or is inside an element with given selector
    function match(selector) {
        return target.closest(selector);
    }

    if (match('#btn-register'))       return registerPasskey();
    if (match('#btn-login'))          return loginPasskey();
    if (match('#btn-logout'))         return logout();
    if (match('#btn-verify-passkey')) return verifyWithPasskey();
    if (match('#btn-send-sms'))       return sendSmsOtp();
    if (match('#btn-verify-sms'))     return verifySmsCode();
    if (match('#btn-cancel-modal'))   return closeModal();
    if (match('#modal-backdrop'))     return closeModal();
    if (match('.modal-backdrop'))     return closeModal();

    var dlBtn = match('.btn-download');
    if (dlBtn) {
        var fileId = dlBtn.getAttribute('data-file-id');
        if (fileId) requestDownload(fileId);
        return;
    }

    var delBtn = match('.btn-delete');
    if (delBtn) {
        var fileId = delBtn.getAttribute('data-file-id');
        if (fileId) deleteFile(fileId);
    }
});

// Upload form submit
document.addEventListener('submit', function(e) {
    if (e.target && e.target.id === 'upload-form') {
        uploadFile(e);
    }
});

// Escape key closes modal
document.addEventListener('keydown', function(e) {
    if (e.key === 'Escape') closeModal();
});
