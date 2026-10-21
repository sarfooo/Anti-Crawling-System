#!/usr/bin/env python3
import argparse
import base64
import hashlib
import hmac
import json
import random
import time
import urllib.error
import urllib.request

USER_AGENTS = [
    "Mozilla/5.0 IntegrityCrawler/1.0",
    "curl/8.4.0",
    "python-requests/2.32",
    "Scrapy/2.11 (+https://example.invalid)",
]


def call(url: str, method: str = "GET", headers: dict[str, str] | None = None, body: bytes | None = None) -> tuple[int, str]:
    request = urllib.request.Request(url, data=body, headers=headers or {}, method=method)
    try:
        with urllib.request.urlopen(request, timeout=6) as response:
            return response.status, response.read().decode()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode()
    except urllib.error.URLError as exc:
        return 0, str(exc)


def canonical_json(value: dict) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def unwrap_seed(encrypted_seed: str, envelope_key: str) -> str:
    envelope = json.loads(base64.urlsafe_b64decode(encrypted_seed.encode()).decode())
    mask = hashlib.sha256(f"{envelope_key}:{envelope['nonce']}".encode()).digest()
    cipher = base64.urlsafe_b64decode(envelope["ciphertext"].encode())
    return bytes(byte ^ mask[index % len(mask)] for index, byte in enumerate(cipher)).decode()


def hmac_hex(key: str, message: str) -> str:
    return hmac.new(key.encode(), message.encode(), hashlib.sha256).hexdigest()


def main() -> None:
    parser = argparse.ArgumentParser(description="Bot crawler that intentionally does not sign protected requests")
    parser.add_argument("--base-url", default="http://localhost:8000")
    parser.add_argument("--requests", type=int, default=25)
    parser.add_argument("--delay", type=float, default=0.15)
    parser.add_argument("--respect-protection", action="store_true", help="registers and tries raw-secret signing, which fails")
    parser.add_argument("--envelope-key", default="local-dev-wasm-envelope-key")
    args = parser.parse_args()

    fingerprint = {"userAgent": "crawler", "platform": "script", "screen": "0x0x0"}
    device_id = ""
    raw_secret = ""
    if args.respect_protection:
        body = json.dumps({"fingerprint": fingerprint}).encode()
        code, payload = call(f"{args.base_url}/api/device/register", "POST", {"Content-Type": "application/json"}, body)
        if code == 200:
            registered = json.loads(payload)
            device_id = registered["device_id"]
            raw_secret = unwrap_seed(registered["encrypted_seed"], args.envelope_key)

    success = 0
    blocked = 0
    for index in range(args.requests):
        headers = {"User-Agent": random.choice(USER_AGENTS)}
        if args.respect_protection and device_id and raw_secret:
            timestamp = str(int(time.time()))
            digest = hashlib.sha256(b"").hexdigest()
            # Wrong on purpose: legitimate clients sign with the runtime-derived verifier.
            signature = hmac_hex(raw_secret, f"{timestamp}GET/api/protected{digest}")
            headers.update(
                {
                    "X-Device-ID": device_id,
                    "X-Timestamp": timestamp,
                    "X-Fingerprint": canonical_json(fingerprint),
                    "X-Signature": signature,
                }
            )
        code, payload = call(f"{args.base_url}/api/protected", headers=headers)
        success += int(code == 200)
        blocked += int(code in {403, 429})
        print(f"{index + 1:04d} status={code} body={payload[:120]}")
        time.sleep(args.delay)

    print(json.dumps({"success": success, "blocked_or_challenged": blocked, "total": args.requests}, indent=2))


if __name__ == "__main__":
    main()
