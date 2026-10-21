import base64
import hashlib
import hmac
import json
import secrets
from typing import Any

from app.config import settings


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def sha256_hex(value: bytes | str) -> str:
    data = value.encode("utf-8") if isinstance(value, str) else value
    return hashlib.sha256(data).hexdigest()


def device_secret() -> str:
    return secrets.token_urlsafe(32)


def secret_hash(secret: str) -> str:
    return hmac.new(settings.secret_pepper.encode(), secret.encode(), hashlib.sha256).hexdigest()


def fingerprint_hash(fingerprint: dict[str, Any] | str) -> str:
    if isinstance(fingerprint, str):
        return sha256_hex(fingerprint)
    return sha256_hex(canonical_json(fingerprint))


def body_hash(body: bytes) -> str:
    return sha256_hex(body)


def signature_payload(timestamp: str, method: str, path: str, body_digest: str) -> str:
    return f"{timestamp}{method.upper()}{path}{body_digest}"


def hmac_signature(key: str, timestamp: str, method: str, path: str, body_digest: str) -> str:
    return hmac.new(key.encode(), signature_payload(timestamp, method, path, body_digest).encode(), hashlib.sha256).hexdigest()


def constant_time_equal(left: str, right: str) -> bool:
    return hmac.compare_digest(left.encode(), right.encode())


def wasm_encrypt_seed(secret: str) -> str:
    """
    Simulated WASM envelope: a browser-side module unwraps this envelope before
    signing. It is deliberately reversible for a local prototype and must be
    replaced with native attestation/KMS/session-key hardening in production.
    """
    nonce = secrets.token_hex(12)
    mask = hashlib.sha256(f"{settings.wasm_envelope_key}:{nonce}".encode()).digest()
    raw = secret.encode()
    cipher = bytes(byte ^ mask[index % len(mask)] for index, byte in enumerate(raw))
    envelope = {"v": 1, "alg": "xor-demo-wasm-envelope", "nonce": nonce, "ciphertext": base64.urlsafe_b64encode(cipher).decode()}
    return base64.urlsafe_b64encode(canonical_json(envelope).encode()).decode()


def wasm_decrypt_seed(encrypted_seed: str) -> str:
    envelope = json.loads(base64.urlsafe_b64decode(encrypted_seed.encode()).decode())
    mask = hashlib.sha256(f"{settings.wasm_envelope_key}:{envelope['nonce']}".encode()).digest()
    cipher = base64.urlsafe_b64decode(envelope["ciphertext"].encode())
    return bytes(byte ^ mask[index % len(mask)] for index, byte in enumerate(cipher)).decode()


def fingerprint_drift(stored: str, incoming: str) -> float:
    if constant_time_equal(stored, incoming):
        return 0.0
    matches = sum(1 for left, right in zip(stored, incoming) if left == right)
    return round((1 - (matches / max(len(stored), 1))) * 100, 2)
