#!/usr/bin/env python3
import argparse
import base64
import hashlib
import hmac
import json
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed


def section(title: str) -> None:
    print(f"\n{'=' * 78}\n{title}\n{'=' * 78}")


def pretty(value: object) -> str:
    return json.dumps(value, indent=2, sort_keys=True)


def mask(value: str, visible: int = 12) -> str:
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
    code, payload = call(f"{base_url}/api/device/register", "POST", {"Content-Type": "application/json"}, body)
    if code != 200:
        raise SystemExit(f"Registration failed: status={code} body={payload}")
    data = json.loads(payload)
    return data["device_id"], unwrap_seed(data["encrypted_seed"], envelope_key)


def signed_headers(device_id: str, secret: str, fingerprint: dict, pepper: str, timestamp: int | None = None) -> dict[str, str]:
    timestamp = timestamp or int(time.time())
    body_hash = hashlib.sha256(b"").hexdigest()
    verifier = hmac_hex(pepper, secret)
    signature = hmac_hex(verifier, f"{timestamp}GET/api/protected{body_hash}")
    return {
        "User-Agent": fingerprint.get("browser", "risk-engine-showcase"),
        "X-Device-ID": device_id,
        "X-Timestamp": str(timestamp),
        "X-Fingerprint": canonical_json(fingerprint),
        "X-Signature": signature,
    }


def latest_event(base_url: str, device_id: str) -> dict:
    code, payload = call(f"{base_url}/api/events?limit=50")
    if code != 200:
        raise RuntimeError(f"events failed: {code} {payload}")
    for event in json.loads(payload):
        if event.get("device_id") == device_id:
            return event
    raise RuntimeError(f"no event found for device {device_id}")


def print_event(label: str, status: int, payload: str, event: dict) -> None:
    print(
        pretty(
            {
                "case": label,
                "api_status": status,
                "api_response": json.loads(payload),
                "logged_decision": event["decision"],
                "risk_score": event["risk_score"],
                "reason": event["reason"],
                "signature_valid": event["signature_valid"],
                "headers_logged": {
                    "x-device-id": event["headers"].get("x-device-id"),
                    "x-fingerprint": event["headers"].get("x-fingerprint"),
                    "x-signature": mask(event["headers"].get("x-signature", "")),
                    "x-timestamp": event["headers"].get("x-timestamp"),
                },
            }
        )
    )


def main() -> None:
    parser = argparse.ArgumentParser(description="Presentation demo for fingerprint drift, Redis rate tracking, and risk decisions")
    parser.add_argument("--base-url", default="http://localhost:8000")
    parser.add_argument("--pepper", default="change-this-pepper-outside-dev")
    parser.add_argument("--envelope-key", default="local-dev-wasm-envelope-key")
    parser.add_argument("--burst-requests", type=int, default=16)
    parser.add_argument("--threads", type=int, default=8)
    args = parser.parse_args()

    base_url = args.base_url.rstrip("/")
    fingerprint = {
        "browser": "Chrome demo profile",
        "platform": "macOS",
        "screen": "1440x900x24",
        "timezone": "America/New_York",
        "language": "en-US",
    }

    section("Setup: register clean device fingerprint")
    device_id, secret = register_device(base_url, args.envelope_key, fingerprint)
    print(pretty({"device_id": device_id, "registered_fingerprint": fingerprint}))

    section("1. Clean fingerprint produces low risk and allow decision")
    code, payload = call(f"{base_url}/api/protected", headers=signed_headers(device_id, secret, fingerprint, args.pepper, int(time.time())))
    print_event("clean request", code, payload, latest_event(base_url, device_id))

    section("2. Small fingerprint change is tolerated but adds minor drift risk")
    small_drift = dict(fingerprint)
    small_drift["screen"] = "1440x901x24"
    code, payload = call(f"{base_url}/api/protected", headers=signed_headers(device_id, secret, small_drift, args.pepper, int(time.time()) + 1))
    print_event("small fingerprint drift", code, payload, latest_event(base_url, device_id))

    section("3. Large fingerprint change increases score and can challenge/throttle/ban")
    large_drift = {
        "browser": "HeadlessBot",
        "platform": "linux-container",
        "screen": "1x1x1",
        "timezone": "UTC",
        "language": "zz-ZZ",
        "canvas": "spoofed",
    }
    code, payload = call(f"{base_url}/api/protected", headers=signed_headers(device_id, secret, large_drift, args.pepper, int(time.time()) + 2))
    print_event("large fingerprint drift", code, payload, latest_event(base_url, device_id))

    section("4. Redis tracks request frequency and burst traffic")
    burst_results: list[dict] = []

    def burst_once(index: int) -> dict:
        headers = signed_headers(device_id, secret, fingerprint, args.pepper, int(time.time()) + 10 + index)
        status, response = call(f"{base_url}/api/protected", headers=headers)
        event = latest_event(base_url, device_id)
        return {
            "request": index + 1,
            "status": status,
            "decision": event["decision"],
            "risk_score": event["risk_score"],
            "reason": event["reason"],
            "response": json.loads(response),
        }

    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        futures = [executor.submit(burst_once, index) for index in range(args.burst_requests)]
        for future in as_completed(futures):
            burst_results.append(future.result())

    burst_results.sort(key=lambda item: item["request"])
    print(pretty({"burst_request_count": args.burst_requests, "sample_results": burst_results[: min(8, len(burst_results))]}))

    section("5. Final action ladder is score based")
    print(
        pretty(
            {
                "score_0_to_34": "allow -> HTTP 200",
                "score_35_to_54": "challenge -> HTTP 429 soft challenge",
                "score_55_to_84": "throttle -> HTTP 429",
                "score_85_to_100": "ban -> HTTP 403",
                "signals_used": [
                    "fingerprint drift",
                    "adaptive rate limit",
                    "burst traffic",
                    "identical timing intervals",
                    "repeated failed signatures",
                    "same IP using many device IDs",
                    "replay attempts",
                    "stale timestamps",
                ],
            }
        )
    )

    section("6. Metrics show allowed, challenged, blocked, and score distribution")
    code, payload = call(f"{base_url}/api/metrics")
    print(pretty({"status": code, "metrics": json.loads(payload)}))


if __name__ == "__main__":
    main()
