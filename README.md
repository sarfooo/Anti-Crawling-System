# Client Integrity & Anti-Bot System

A runnable local prototype for device-bound authentication, HMAC request signing, replay prevention, Redis-backed rate limiting, behavior scoring, device reputation, fingerprint drift detection, and an operational React dashboard.

## Run Everything

```bash
docker compose up --build
```

Open:

- Dashboard: `http://localhost:5173`
- API docs: `http://localhost:8000/docs`
- Health: `http://localhost:8000/health`

## Project Structure

```text
/backend              FastAPI, SQLAlchemy, Alembic, Redis enforcement
/frontend             React + Vite + TypeScript dashboard
/tools/crawler.py     Unsigned crawler and failed mimic mode
/tools/attacker.py    Multi-threaded attack simulator
/docker-compose.yml   PostgreSQL, Redis, backend, frontend
```

## Implemented Architecture

- `POST /api/device/register`
  - accepts a fingerprint payload
  - generates a UUID `device_id`
  - generates a secure random 256-bit-ish device secret
  - stores only a peppered secret hash/verifier in `devices.secret_hash`
  - returns `device_id` and an encrypted seed envelope that simulates WASM protection

- Signed protected requests require:
  - `X-Device-ID`
  - `X-Signature`
  - `X-Fingerprint`
  - `X-Timestamp`

- Signature payload:

```text
HMAC_SHA256(device_secret_verifier, timestamp + method + path + body_hash)
```

The browser-side runtime unwraps the simulated WASM seed envelope, derives the same verifier, and signs `/api/protected`.

## Verification Pipeline

The middleware on `/api/protected` performs:

1. Header extraction
2. Device lookup and status validation
3. Constant-time HMAC verification
4. Timestamp freshness check, rejecting requests older than 30 seconds
5. Redis replay prevention using device/timestamp/signature keys
6. Fingerprint comparison and drift logging
7. Redis sliding-window rate limits per device/IP
8. Behavioral scoring for burst traffic, identical timing, repeated failed signatures, many device IDs from one IP, and entropy mismatch
9. Decision engine:
   - `200` allow
   - `429` throttle or soft challenge
   - `403` ban

## Database Tables

Alembic migration `0001_initial` creates:

- `devices`
- `requests_log`
- `decisions`
- `fingerprints`
- `rate_limits`

Migrations run automatically when the backend container starts.

## Dashboard

The dashboard includes:

- Device Monitor with active/flagged/banned status
- Live Requests Feed with headers, signature validity, decision, risk score, and latency
- Attack Visualization showing requests/sec and blocked spikes
- Metrics with allowed/blocked/challenged counts and risk distribution
- Signed Demo button that registers a browser device and sends a signed protected request through the seed runtime

## Tools

Unsigned crawler:

```bash
python3 tools/crawler.py --requests 50
```

Crawler that tries to respect protection but signs incorrectly:

```bash
python3 tools/crawler.py --respect-protection --requests 25
```

Naive unsigned attack:

```bash
python3 tools/attacker.py --mode naive --threads 12 --requests 300
```

Semi-smart signed attack reusing one device:

```bash
python3 tools/attacker.py --mode semi-smart --signed --threads 8 --requests 200
```

Distributed signed simulation:

```bash
python3 tools/attacker.py --mode distributed --signed --threads 10 --requests 200 --jitter 0.05
```

Run the full security smoke suite:

```bash
python3 tools/security_test_suite.py --threads 8 --attack-requests 40
```

Run the presentation-friendly registration/signing walkthrough:

```bash
python3 tools/showcase_registration_flow.py
```

Run the protected-request verification walkthrough:

```bash
python3 tools/showcase_request_verification.py
```

Run the risk engine and fingerprint drift walkthrough:

```bash
python3 tools/showcase_risk_engine.py
```

## Security Notes

This prototype increases attacker cost; it is not bot-proof. The seed envelope is a local simulation of WASM-style client protection, not strong secrecy. Real production hardening should use platform attestation, short-lived session keys, KMS/HSM-backed verification, authenticated admin endpoints, a proper challenge flow, and calibrated anomaly scoring.
