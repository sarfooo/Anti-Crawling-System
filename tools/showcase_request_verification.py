#!/usr/bin/env python3
import argparse
import base64
import hashlib
import hmac
import json
import time
import urllib.error
import urllib.request


def section(title: str) -> None:
    print(f"\n{'=' * 78}\n{title}\n{'=' * 78}")


def pretty(value: object) -> str:
    return json.dumps(value, indent=2, sort_keys=True)


def mask(value: str, visible: int = 14) -> str:
    if len(value) <= visible * 2:
        return value
    return f"{value[:visible]}...{value[-visible:]}"


def canonical_json(value: dict) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def call(url: str, method: str = "GET", headers: dict[str, str] | None = None, body: bytes | None = None) -> tuple[int, str]:
    request = urllib.request.Request(url, data=body, headers=headers or {}, method=method)
    try:
        with urllib.request.urlopen(request, timeout=8) as response:
            return response.status, response.read().decode()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode()
    except urllib.error.URLError as exc:
        return 0, str(exc)


def unwrap_seed(encrypted_seed: str, envelope_key: str) -> str:
    envelope = json.loads(base64.urlsafe_b64decode(encrypted_seed.encode()).decode())
    mask_bytes = hashlib.sha256(f"{envelope_key}:{envelope['nonce']}".encode()).digest()
    cipher = base64.urlsafe_b64decode(envelope["ciphertext"].encode())
    return bytes(byte ^ mask_bytes[index % len(mask_bytes)] for index, byte in enumerate(cipher)).decode()


def hmac_hex(key: str, message: str) -> str:
    return hmac.new(key.encode(), message.encode(), hashlib.sha256).hexdigest()


def register_device(base_url: str, envelope_key: str, fingerprint: dict) -> tuple[str, str]:
    body = json.dumps({"fingerprint": fingerprint}).encode()
    code, payload = call(
        f"{base_url}/api/device/register",
        "POST",
        {"Content-Type": "application/json"},
        body,
    )
    if code != 200:
        raise SystemExit(f"Registration failed: status={code} body={payload}")
    data = json.loads(payload)
    return data["device_id"], unwrap_seed(data["encrypted_seed"], envelope_key)


def build_signed_request(
    *,
    device_id: str,
    raw_secret: str,
    fingerprint: dict,
    pepper: str,
    timestamp: int,
    method: str = "GET",
    path: str = "/api/protected",
    body: bytes = b"",
) -> tuple[dict[str, str], dict[str, str]]:
    body_hash = hashlib.sha256(body).hexdigest()
    verifier = hmac_hex(pepper, raw_secret)
    signature_payload = f"{timestamp}{method}{path}{body_hash}"
    signature = hmac_hex(verifier, signature_payload)
    headers = {
        "User-Agent": "request-verification-showcase",
        "X-Device-ID": device_id,
        "X-Timestamp": str(timestamp),
        "X-Fingerprint": canonical_json(fingerprint),
        "X-Signature": signature,
    }
    internals = {
        "body_hash": body_hash,
        "server_stored_secret_hash_or_verifier": verifier,
        "signature_payload": signature_payload,
        "signature": signature,
    }
    return headers, internals


def main() -> None:
    parser = argparse.ArgumentParser(description="Presentation demo for protected request signature verification")
    parser.add_argument("--base-url", default="http://localhost:8000")
    parser.add_argument("--pepper", default="change-this-pepper-outside-dev")
    parser.add_argument("--envelope-key", default="local-dev-wasm-envelope-key")
    args = parser.parse_args()

    base_url = args.base_url.rstrip("/")
    fingerprint = {
        "browser": "Chrome demo profile",
        "platform": "macOS",
        "screen": "1440x900x24",
        "timezone": "America/New_York",
    }

    section("Setup: register a device so it has a device ID and signing seed")
    device_id, raw_secret = register_device(base_url, args.envelope_key, fingerprint)
    print(pretty({"device_id": device_id, "client_seed_inside_runtime": mask(raw_secret)}))

    section("1. Protected request includes device ID, timestamp, fingerprint, and signature")
    timestamp = int(time.time())
    headers, internals = build_signed_request(
        device_id=device_id,
        raw_secret=raw_secret,
        fingerprint=fingerprint,
        pepper=args.pepper,
        timestamp=timestamp,
    )
    print(
        pretty(
            {
                "X-Device-ID": headers["X-Device-ID"],
                "X-Timestamp": headers["X-Timestamp"],
                "X-Fingerprint": headers["X-Fingerprint"],
                "X-Signature": mask(headers["X-Signature"]),
            }
        )
    )

    section("2. Signature is HMAC over timestamp + method + path + body hash")
    print(
        pretty(
            {
                "method": "GET",
                "path": "/api/protected",
                "body_hash": internals["body_hash"],
                "signature_payload": internals["signature_payload"],
                "hmac_signature": mask(internals["signature"]),
            }
        )
    )

    section("3. Server recalculates signature and allows valid request")
    code, payload = call(f"{base_url}/api/protected", headers=headers)
    print(pretty({"status": code, "response": json.loads(payload)}))

    section("4. Redis replay protection rejects the same signed request twice")
    replay_headers, replay_internals = build_signed_request(
        device_id=device_id,
        raw_secret=raw_secret,
        fingerprint=fingerprint,
        pepper=args.pepper,
        timestamp=int(time.time()) + 2,
    )
    first_code, first_payload = call(f"{base_url}/api/protected", headers=replay_headers)
    second_code, second_payload = call(f"{base_url}/api/protected", headers=replay_headers)
    redis_key_shape = f"replay:{device_id}:{replay_headers['X-Timestamp']}:{mask(replay_internals['signature'])}"
    print(
        pretty(
            {
                "redis_key_shape": redis_key_shape,
                "first_request": {"status": first_code, "response": json.loads(first_payload)},
                "second_request_replay": {"status": second_code, "response": json.loads(second_payload)},
            }
        )
    )

    section("5. Tampered signature is rejected before protected data is served")
    tampered_headers = dict(headers)
    tampered_headers["X-Timestamp"] = str(timestamp + 4)
    tampered_headers["X-Signature"] = "0" * 64
    code, payload = call(f"{base_url}/api/protected", headers=tampered_headers)
    print(pretty({"status": code, "response": json.loads(payload)}))

    section("6. Timestamp check blocks old requests outside the 30 second window")
    stale_headers, stale_internals = build_signed_request(
        device_id=device_id,
        raw_secret=raw_secret,
        fingerprint=fingerprint,
        pepper=args.pepper,
        timestamp=int(time.time()) - 120,
    )
    code, payload = call(f"{base_url}/api/protected", headers=stale_headers)
    print(
        pretty(
            {
                "stale_timestamp": stale_headers["X-Timestamp"],
                "stale_signature": mask(stale_internals["signature"]),
                "status": code,
                "response": json.loads(payload),
            }
        )
    )


if __name__ == "__main__":
    main()
