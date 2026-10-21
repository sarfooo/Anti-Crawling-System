#!/usr/bin/env python3
import argparse
import base64
import hashlib
import hmac
import json
import os
import queue
import random
import statistics
import threading
import time
import urllib.error
import urllib.request


def call(url: str, method: str = "GET", headers: dict[str, str] | None = None, body: bytes | None = None) -> tuple[int, float]:
    started = time.perf_counter()
    request = urllib.request.Request(url, data=body, headers=headers or {}, method=method)
    try:
        with urllib.request.urlopen(request, timeout=8) as response:
            response.read()
            return response.status, (time.perf_counter() - started) * 1000
    except urllib.error.HTTPError as exc:
        exc.read()
        return exc.code, (time.perf_counter() - started) * 1000
    except urllib.error.URLError:
        return 0, (time.perf_counter() - started) * 1000


def canonical_json(value: dict) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def unwrap_seed(encrypted_seed: str, envelope_key: str) -> str:
    envelope = json.loads(base64.urlsafe_b64decode(encrypted_seed.encode()).decode())
    mask = hashlib.sha256(f"{envelope_key}:{envelope['nonce']}".encode()).digest()
    cipher = base64.urlsafe_b64decode(envelope["ciphertext"].encode())
    return bytes(byte ^ mask[index % len(mask)] for index, byte in enumerate(cipher)).decode()


def hmac_hex(key: str, message: str) -> str:
    return hmac.new(key.encode(), message.encode(), hashlib.sha256).hexdigest()


def register(base_url: str, fingerprint: dict, envelope_key: str) -> tuple[str, str]:
    body = json.dumps({"fingerprint": fingerprint}).encode()
    request = urllib.request.Request(
        f"{base_url}/api/device/register",
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=8) as response:
        payload = json.loads(response.read().decode())
    return payload["device_id"], unwrap_seed(payload["encrypted_seed"], envelope_key)


def signed_headers(device: tuple[str, str], fingerprint: dict, pepper: str) -> dict[str, str]:
    device_id, raw_secret = device
    timestamp = str(int(time.time()))
    digest = hashlib.sha256(b"").hexdigest()
    verifier = hmac_hex(pepper, raw_secret)
    signature = hmac_hex(verifier, f"{timestamp}GET/api/protected{digest}")
    return {
        "User-Agent": fingerprint["userAgent"],
        "X-Device-ID": device_id,
        "X-Timestamp": timestamp,
        "X-Fingerprint": canonical_json(fingerprint),
        "X-Signature": signature,
    }


def worker(args: argparse.Namespace, jobs: queue.Queue, results: queue.Queue, shared_device: tuple[str, str] | None) -> None:
    fingerprint = {
        "userAgent": f"attack-sim/{threading.get_ident()}",
        "platform": random.choice(["mac", "linux", "win"]),
        "screen": random.choice(["1440x900x24", "1920x1080x24", "390x844x24"]),
        "canvas": hashlib.sha1(str(random.random()).encode()).hexdigest(),
    }
    device = shared_device
    if args.signed and args.mode == "distributed":
        device = register(args.base_url, fingerprint, args.envelope_key)

    while True:
        try:
            jobs.get_nowait()
        except queue.Empty:
            return
        headers = {"User-Agent": fingerprint["userAgent"]}
        if args.signed and device:
            headers = signed_headers(device, fingerprint, args.pepper)
        code, latency = call(f"{args.base_url}/api/protected", headers=headers)
        results.put((code, latency))
        if args.jitter:
            time.sleep(random.uniform(0, args.jitter))


def main() -> None:
    parser = argparse.ArgumentParser(description="Multi-threaded attack simulator")
    parser.add_argument("--base-url", default="http://localhost:8000")
    parser.add_argument("--threads", type=int, default=8)
    parser.add_argument("--requests", type=int, default=200)
    parser.add_argument("--mode", choices=["naive", "semi-smart", "distributed"], default="naive")
    parser.add_argument("--signed", action="store_true")
    parser.add_argument("--jitter", type=float, default=0.0)
    parser.add_argument("--pepper", default=os.getenv("SECRET_PEPPER", "change-this-pepper-outside-dev"))
    parser.add_argument("--envelope-key", default=os.getenv("WASM_ENVELOPE_KEY", "local-dev-wasm-envelope-key"))
    args = parser.parse_args()

    shared_device = None
    if args.signed and args.mode in {"naive", "semi-smart"}:
        shared_device = register(args.base_url, {"userAgent": "shared-attacker", "platform": "script", "screen": "0x0x0"}, args.envelope_key)

    jobs: queue.Queue = queue.Queue()
    results: queue.Queue = queue.Queue()
    for _ in range(args.requests):
        jobs.put(1)

    started = time.perf_counter()
    threads = [threading.Thread(target=worker, args=(args, jobs, results, shared_device), daemon=True) for _ in range(args.threads)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    elapsed = time.perf_counter() - started

    rows = list(results.queue)
    codes = [code for code, _ in rows]
    latencies = [latency for _, latency in rows]
    success = sum(1 for code in codes if code == 200)
    blocked = sum(1 for code in codes if code in {403, 429})
    print(
        json.dumps(
            {
                "mode": args.mode,
                "signed": args.signed,
                "threads": args.threads,
                "requests": len(rows),
                "success_rate": round(success / max(len(rows), 1), 3),
                "block_rate": round(blocked / max(len(rows), 1), 3),
                "requests_per_second": round(len(rows) / max(elapsed, 0.001), 2),
                "latency_ms_p50": round(statistics.median(latencies), 2) if latencies else 0,
                "latency_ms_p95": round(statistics.quantiles(latencies, n=20)[18], 2) if len(latencies) >= 20 else 0,
                "status_counts": {str(code): codes.count(code) for code in sorted(set(codes))},
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
