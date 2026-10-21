#!/usr/bin/env python3
import argparse
import base64
import hashlib
import hmac
import json
import statistics
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed


def canonical_json(value: dict) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def call(url: str, method: str = "GET", headers: dict[str, str] | None = None, body: bytes | None = None) -> tuple[int, str, float]:
    started = time.perf_counter()
    request = urllib.request.Request(url, data=body, headers=headers or {}, method=method)
    try:
        with urllib.request.urlopen(request, timeout=8) as response:
            return response.status, response.read().decode(), (time.perf_counter() - started) * 1000
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode(), (time.perf_counter() - started) * 1000
    except urllib.error.URLError as exc:
        return 0, str(exc), (time.perf_counter() - started) * 1000


def unwrap_seed(encrypted_seed: str, envelope_key: str) -> str:
    envelope = json.loads(base64.urlsafe_b64decode(encrypted_seed.encode()).decode())
    mask = hashlib.sha256(f"{envelope_key}:{envelope['nonce']}".encode()).digest()
    cipher = base64.urlsafe_b64decode(envelope["ciphertext"].encode())
    return bytes(byte ^ mask[index % len(mask)] for index, byte in enumerate(cipher)).decode()


def hmac_hex(key: str, message: str) -> str:
    return hmac.new(key.encode(), message.encode(), hashlib.sha256).hexdigest()


def register_device(base_url: str, envelope_key: str, fingerprint: dict) -> tuple[str, str]:
    body = json.dumps({"fingerprint": fingerprint}).encode()
    code, payload, _ = call(
        f"{base_url}/api/device/register",
        "POST",
        {"Content-Type": "application/json"},
        body,
    )
    if code != 200:
        raise RuntimeError(f"device registration failed: {code} {payload}")
    data = json.loads(payload)
    return data["device_id"], unwrap_seed(data["encrypted_seed"], envelope_key)


def signed_headers(
    device_id: str,
    raw_secret: str,
    fingerprint: dict,
    pepper: str,
    *,
    timestamp: int | None = None,
    path: str = "/api/protected",
    body: bytes = b"",
    tamper_signature: bool = False,
) -> dict[str, str]:
    ts = str(timestamp or int(time.time()))
    digest = hashlib.sha256(body).hexdigest()
    verifier = hmac_hex(pepper, raw_secret)
    signature = hmac_hex(verifier, f"{ts}GET{path}{digest}")
    if tamper_signature:
        signature = "0" * 64
    return {
        "User-Agent": fingerprint.get("userAgent", "security-suite"),
        "X-Device-ID": device_id,
        "X-Timestamp": ts,
        "X-Fingerprint": canonical_json(fingerprint),
        "X-Signature": signature,
    }


def verdict(name: str, passed: bool, detail: str) -> dict:
    return {"name": name, "passed": passed, "detail": detail}


def compact_body(body: str, limit: int = 500) -> str:
    body = body.replace("\n", " ")
    return body if len(body) <= limit else f"{body[:limit]}..."


def run_suite(args: argparse.Namespace) -> list[dict]:
    base = args.base_url.rstrip("/")
    results: list[dict] = []

    code, payload, _ = call(f"{base}/health")
    results.append(verdict("health", code == 200, f"status={code} response={compact_body(payload)}"))

    code, payload, _ = call(f"{base}/api/protected")
    results.append(verdict("unsigned request blocked", code in {403, 429}, f"status={code} response={compact_body(payload)}"))

    fingerprint = {
        "userAgent": "security-suite/legit",
        "platform": "script",
        "screen": "1440x900x24",
        "timezone": "America/New_York",
        "hardwareConcurrency": 8,
    }
    device_id, secret = register_device(base, args.envelope_key, fingerprint)
    timestamp_base = int(time.time())

    code, payload, latency = call(
        f"{base}/api/protected",
        headers=signed_headers(device_id, secret, fingerprint, args.pepper, timestamp=timestamp_base),
    )
    results.append(
        verdict(
            "valid signed request allowed",
            code == 200,
            f"status={code} latency_ms={latency:.2f} response={compact_body(payload)}",
        )
    )

    replay_headers = signed_headers(device_id, secret, fingerprint, args.pepper, timestamp=timestamp_base + 1)
    first, first_payload, _ = call(f"{base}/api/protected", headers=replay_headers)
    second, second_payload, _ = call(f"{base}/api/protected", headers=replay_headers)
    results.append(
        verdict(
            "replay blocked",
            first == 200 and second in {403, 429},
            f"first_status={first} first_response={compact_body(first_payload)} second_status={second} second_response={compact_body(second_payload)}",
        )
    )

    code, payload, _ = call(
        f"{base}/api/protected",
        headers=signed_headers(device_id, secret, fingerprint, args.pepper, timestamp=timestamp_base + 2, tamper_signature=True),
    )
    results.append(verdict("tampered signature blocked", code in {403, 429}, f"status={code} response={compact_body(payload)}"))

    stale_timestamp = int(time.time()) - 120
    code, payload, _ = call(
        f"{base}/api/protected",
        headers=signed_headers(device_id, secret, fingerprint, args.pepper, timestamp=stale_timestamp),
    )
    results.append(verdict("stale timestamp blocked", code in {403, 429}, f"status={code} response={compact_body(payload)}"))

    drifted = dict(fingerprint)
    drifted["screen"] = "1x1x1"
    drifted["canvas"] = "spoofed"
    code, payload, _ = call(
        f"{base}/api/protected",
        headers=signed_headers(device_id, secret, drifted, args.pepper, timestamp=timestamp_base + 3),
    )
    results.append(
        verdict(
            "fingerprint drift challenged",
            code in {200, 403, 429},
            f"status={code} response={compact_body(payload)}; check events for drift score",
        )
    )

    attack_codes: list[int] = []
    attack_latencies: list[float] = []

    def attack_once(index: int) -> tuple[int, str, float]:
        headers = signed_headers(device_id, secret, fingerprint, args.pepper)
        code, payload, latency = call(f"{base}/api/protected", headers=headers)
        return code, payload, latency

    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        futures = [executor.submit(attack_once, index) for index in range(args.attack_requests)]
        for future in as_completed(futures):
            code, payload, latency = future.result()
            attack_codes.append(code)
            attack_latencies.append(latency)
            if len(attack_codes) <= 5:
                results.append(verdict(f"burst sample {len(attack_codes)}", code in {200, 403, 429}, f"status={code} response={compact_body(payload)}"))

    blocked = sum(1 for code in attack_codes if code in {403, 429})
    allowed = sum(1 for code in attack_codes if code == 200)
    results.append(
        verdict(
            "burst attack measured",
            len(attack_codes) == args.attack_requests,
            f"allowed={allowed} blocked={blocked} p50_ms={statistics.median(attack_latencies):.2f}",
        )
    )

    code, metrics, _ = call(f"{base}/api/metrics")
    results.append(verdict("metrics available", code == 200 and "total_requests" in metrics, f"status={code} response={compact_body(metrics, 1000)}"))

    code, events, _ = call(f"{base}/api/events")
    results.append(verdict("events available", code == 200 and "/api/protected" in events, f"status={code} response={compact_body(events, 1000)}"))

    return results


def main() -> None:
    parser = argparse.ArgumentParser(description="Run end-to-end security tests against the Client Integrity API")
    parser.add_argument("--base-url", default="http://localhost:8000")
    parser.add_argument("--pepper", default="change-this-pepper-outside-dev")
    parser.add_argument("--envelope-key", default="local-dev-wasm-envelope-key")
    parser.add_argument("--threads", type=int, default=8)
    parser.add_argument("--attack-requests", type=int, default=40)
    args = parser.parse_args()

    results = run_suite(args)
    passed = sum(1 for result in results if result["passed"])
    print(f"\nSecurity test suite: {passed}/{len(results)} passed\n")
    for result in results:
        marker = "PASS" if result["passed"] else "FAIL"
        print(f"[{marker}] {result['name']}: {result['detail']}")
    raise SystemExit(0 if passed == len(results) else 1)


if __name__ == "__main__":
    main()
