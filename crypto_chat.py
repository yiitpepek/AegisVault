"""
Cryptographic Chat & Secure Armored Messenger
Capabilities:
- End-to-End Encrypted Messaging (E2EE)
- AES-256-GCM + scrypt Armored Envelope Format (AEGIS-MSG-v1)
- Authenticated Data Integrity (Tamper-Proof GHASH Tag)
- Enforced Epoch Freshness & Nonce Anti-Replay Protection (V-16)
"""

import os
import time
import secrets
import hashlib
import json
from collections import deque
from datetime import datetime
from typing import Dict, Any, Optional
from military_vault import MilitaryVault, VaultSecurityError

MSG_PREFIX = "AEGIS-MSG-v1"
MAX_MESSAGE_AGE_SECONDS = 86400.0  # 24-hour default freshness window (V-16)
MAX_FUTURE_SKEW_SECONDS = 300.0    # 5-minute maximum clock skew tolerance

# In-memory + persistent consumed nonce cache to block token/stego/QR replay attacks (V-16)
_CONSUMED_NONCES: deque = deque(maxlen=4096)


def _get_nonce_cache_file() -> str:
    try:
        from vault_storage import _get_user_secret_dir
        return os.path.join(_get_user_secret_dir(), ".msg_replay_nonces.json")
    except Exception:
        return ".msg_replay_nonces.json"


def _is_nonce_replayed(nonce_id: str) -> bool:
    if nonce_id in _CONSUMED_NONCES:
        return True
    cache_path = _get_nonce_cache_file()
    if os.path.exists(cache_path):
        try:
            with open(cache_path, "r", encoding="utf-8") as f:
                stored = json.load(f)
            if isinstance(stored, list) and nonce_id in stored:
                _CONSUMED_NONCES.append(nonce_id)
                return True
        except Exception:
            pass
    return False


def _record_consumed_nonce(nonce_id: str) -> None:
    _CONSUMED_NONCES.append(nonce_id)
    cache_path = _get_nonce_cache_file()
    try:
        stored = list(_CONSUMED_NONCES)[-1024:]
        with open(cache_path, "w", encoding="utf-8") as f:
            json.dump(stored, f)
    except Exception:
        pass


def encrypt_message(
    plaintext: str,
    shared_passkey: str,
    metadata: Optional[Dict[str, Any]] = None
) -> str:
    """
    Encrypts a plaintext message using AES-256-GCM and a shared passkey.
    Includes a 128-bit CSPRNG nonce, epoch timestamp, and optional authenticated metadata.
    """
    if not plaintext.strip():
        raise ValueError("Message body cannot be empty.")
    if not shared_passkey.strip():
        raise ValueError("Shared passkey cannot be empty.")

    envelope: Dict[str, Any] = {
        "text": plaintext.strip(),
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "nonce": secrets.token_hex(16),
        "epoch": time.time()
    }
    if metadata and isinstance(metadata, dict):
        envelope["meta"] = metadata

    raw_payload = json.dumps(envelope, ensure_ascii=False)
    encrypted_armored = MilitaryVault.encrypt(raw_payload, shared_passkey)

    return f"{MSG_PREFIX}:{encrypted_armored}"


def decrypt_message(
    token: str,
    shared_passkey: str,
    max_age_seconds: float = MAX_MESSAGE_AGE_SECONDS,
    enforce_replay_cache: bool = True
) -> Dict[str, Any]:
    """
    Decrypts an armored message token, verifies AES-256-GCM cryptographic integrity,
    and enforces timestamp freshness and single-use nonce anti-replay checks (V-16).
    """
    token = token.strip()
    if not token.startswith(MSG_PREFIX + ":"):
        raise ValueError("Invalid message format! Must start with 'AEGIS-MSG-v1:'.")

    armored_content = token[len(MSG_PREFIX) + 1:]
    decrypted_bytes = MilitaryVault.decrypt(armored_content, shared_passkey)
    raw_payload = decrypted_bytes.decode("utf-8")
    payload = json.loads(raw_payload)

    if not isinstance(payload, dict):
        raise VaultSecurityError("Invalid message envelope structure.")

    # V-16: Validate timestamp freshness
    msg_epoch = payload.get("epoch")
    if not isinstance(msg_epoch, (int, float)):
        raise VaultSecurityError("Message envelope is missing a valid epoch timestamp!")

    now = time.time()
    if (now - float(msg_epoch)) > max_age_seconds:
        raise VaultSecurityError(
            f"Stale or expired message rejected (age {(now - float(msg_epoch)):.0f}s exceeds {max_age_seconds:.0f}s limit)!"
        )
    if (float(msg_epoch) - now) > MAX_FUTURE_SKEW_SECONDS:
        raise VaultSecurityError("Future-dated message token rejected (clock skew violation)!")

    # V-16: Validate and consume unique 128-bit nonce to block replay across P2P, Stego, and QR
    msg_nonce = payload.get("nonce")
    if not isinstance(msg_nonce, str) or len(msg_nonce) < 16:
        raise VaultSecurityError("Message envelope is missing a valid 128-bit nonce!")

    if enforce_replay_cache:
        nonce_fingerprint = hashlib.sha256(f"{msg_nonce}:{armored_content[:48]}".encode("utf-8")).hexdigest()
        if _is_nonce_replayed(nonce_fingerprint):
            raise VaultSecurityError("Replay attack blocked: this message token has already been decrypted/consumed!")
        _record_consumed_nonce(nonce_fingerprint)

    return payload

