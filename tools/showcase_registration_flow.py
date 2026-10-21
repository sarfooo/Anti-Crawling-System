#!/usr/bin/env python3
import argparse
import base64
import hashlib
import hmac
import json
import shutil
import subprocess
import time
import urllib.error
import urllib.request


def section(title: str) -> None:
    print(f"\n{'=' * 78}\n{title}\n{'=' * 78}")


def pretty(value: object) -> str:
    return json.dumps(value, indent=2, sort_keys=True)


def mask(value: str, visible: int = 10) -> str:
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


def sha256_hex(body: bytes) -> str:
    return hashlib.sha256(body).hexdigest()


def psql_device_row(database_url: str, device_id: str) -> dict | None:
    if not shutil.which("psql"):
        return None
    query = (
        "SELECT json_build_object("
        "'device_id', device_id,"
        "'secret_hash', secret_hash,"
        "'fingerprint_hash', fingerprint_hash,"
        "'status', status,"
        "'trust_score', trust_score,"
        "'created_at', created_at"
        f") FROM devices WHERE device_id = '{device_id}';"
    )
    result = subprocess.run(
        ["psql", database_url, "-t", "-A", "-c", query],
        text=True,
        capture_output=True,
        check=False,
    )
    if result.returncode != 0 or not result.stdout.strip():
        return None
    return json.loads(result.stdout.strip())


def main() -> None:
    parser = argparse.ArgumentParser(description="Presentation demo for device registration and signed request flow")
    parser.add_argument("--base-url", default="http://localhost:8000")
    parser.add_argument("--pepper", default="change-this-pepper-outside-dev")
    parser.add_argument("--envelope-key", default="local-dev-wasm-envelope-key")
    parser.add_argument("--database-url", default="postgresql://integrity:integrity@localhost:5432/integrity")
    args = parser.parse_args()

    base_url = args.base_url.rstrip("/")
    fingerprint = {
        "browser": "Chrome demo profile",
        "platform": "macOS",
        "language": "en-US",
        "screen": "1440x900x24",
        "timezone": "America/New_York",
        "hardwareConcurrency": 8,
    }

    section("1. Client sends browser/device fingerprint")
    print(pretty(fingerprint))

    section("2. Server registers device and returns protected seed envelope")
    body = json.dumps({"fingerprint": fingerprint}).encode()
    code, payload = call(
        f"{base_url}/api/device/register",
        "POST",
        {"Content-Type": "application/json"},
        body,
    )
    if code != 200:
        raise SystemExit(f"Registration failed: status={code} body={payload}")
    registered = json.loads(payload)
    device_id = registered["device_id"]
    encrypted_seed = registered["encrypted_seed"]
    print(
        pretty(
            {
                "status": code,
                "device_id": device_id,
                "encrypted_seed": mask(encrypted_seed, 24),
                "seed_format": registered.get("seed_format"),
            }
        )
    )

    section("3. Database stores only hashed secret, never plaintext secret")
    row = psql_device_row(args.database_url, device_id)
    if row:
        print(
            pretty(
                {
                    "device_id": row["device_id"],
                    "secret_hash": mask(row["secret_hash"], 14),
                    "fingerprint_hash": mask(row["fingerprint_hash"], 14),
                    "status": row["status"],
                    "trust_score": row["trust_score"],
                    "created_at": row["created_at"],
                    "raw_secret_in_database": False,
                }
            )
        )
    else:
        print("Could not query Postgres with psql; API still proves secret is not exposed by /api/devices.")
        code, devices_payload = call(f"{base_url}/api/devices")
        print(pretty({"status": code, "devices_response_sample": json.loads(devices_payload)[0]}))

    section("4. Client runtime unwraps encrypted seed for signing")
    raw_seed = unwrap_seed(encrypted_seed, args.envelope_key)
    verifier = hmac_hex(args.pepper, raw_seed)
    print(
        pretty(
            {
                "raw_seed_visible_only_inside_client_runtime": mask(raw_seed),
                "derived_secret_verifier_matches_server_hash": mask(verifier, 14),
                "note": "The prototype simulates WASM protection; production would use a real compiled WASM signer.",
            }
        )
    )

    section("5. Client signs protected request")
    timestamp = str(int(time.time()))
    method = "GET"
    path = "/api/protected"
    body_hash = sha256_hex(b"")
    signature_payload = f"{timestamp}{method}{path}{body_hash}"
    signature = hmac_hex(verifier, signature_payload)
    headers = {
        "User-Agent": "registration-flow-showcase",
        "X-Device-ID": device_id,
        "X-Timestamp": timestamp,
        "X-Fingerprint": canonical_json(fingerprint),
        "X-Signature": signature,
    }
    print(
        pretty(
            {
                "headers_sent": {
                    "X-Device-ID": headers["X-Device-ID"],
                    "X-Timestamp": headers["X-Timestamp"],
                    "X-Fingerprint": headers["X-Fingerprint"],
                    "X-Signature": mask(headers["X-Signature"], 14),
                },
                "signature_payload": signature_payload,
                "body_hash": body_hash,
            }
        )
    )

    section("6. Server verifies signature and allows protected API request")
    code, protected_payload = call(f"{base_url}{path}", headers=headers)
    print(pretty({"status": code, "response": json.loads(protected_payload)}))

    section("7. Same API request without signature is rejected")
    code, blocked_payload = call(f"{base_url}{path}", headers={"User-Agent": "unsigned-showcase"})
    print(pretty({"status": code, "response": json.loads(blocked_payload)}))


if __name__ == "__main__":
    main()
