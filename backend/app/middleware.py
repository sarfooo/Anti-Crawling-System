import asyncio
import time
from datetime import datetime, timezone

from fastapi import Request
from fastapi.responses import JSONResponse, Response
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint

from app.config import settings
from app.database import SessionLocal
from app.models import Decision, Device, Fingerprint, RateLimitSnapshot, RequestLog
from app.redis_client import redis_client
from app.risk import RiskScoringEngine
from app.security import body_hash, constant_time_equal, fingerprint_drift, fingerprint_hash, hmac_signature

PROTECTED_PATHS = {"/api/protected"}


class IntegrityMiddleware(BaseHTTPMiddleware):
    def __init__(self, app):
        super().__init__(app)
        self.risk = RiskScoringEngine(redis_client)

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        if request.method == "OPTIONS" or request.url.path not in PROTECTED_PATHS:
            return await call_next(request)

        started = time.perf_counter()
        body = await request.body()
        request._receive = self._replay_body(body)
        digest = body_hash(body)
        db = SessionLocal()
        try:
            decision = self._verify(request, body, digest, db)
            if decision["action"] == "allow":
                response = await call_next(request)
            elif decision["action"] == "challenge":
                await asyncio.sleep(0.3)
                response = JSONResponse(
                    status_code=429,
                    content={"decision": "challenge", "detail": "soft challenge: delay applied, re-sign and retry"},
                )
            elif decision["action"] == "throttle":
                response = JSONResponse(status_code=429, content={"decision": "throttle", "detail": decision["reason"]})
            else:
                response = JSONResponse(status_code=403, content={"decision": "ban", "detail": decision["reason"]})
            self._log(request, digest, db, decision, started)
            return response
        finally:
            db.close()

    @staticmethod
    def _replay_body(body: bytes):
        async def receive():
            return {"type": "http.request", "body": body, "more_body": False}

        return receive

    def _verify(self, request: Request, body: bytes, digest: str, db) -> dict:
        headers = request.headers
        device_id = headers.get("x-device-id")
        signature = headers.get("x-signature", "")
        timestamp = headers.get("x-timestamp", "")
        fingerprint = headers.get("x-fingerprint", "")
        ip_address = request.client.host if request.client else "unknown"

        device = db.query(Device).filter(Device.device_id == device_id).first() if device_id else None
        timestamp_age = self._timestamp_age(timestamp)
        stale_timestamp = timestamp_age is None or timestamp_age > settings.replay_window_seconds
        replay = self._replay(device_id, timestamp, signature)
        signature_valid = False
        drift = 100.0

        if device and timestamp:
            expected = hmac_signature(device.secret_hash, timestamp, request.method, request.url.path, digest)
            signature_valid = constant_time_equal(expected, signature)

        if device and fingerprint:
            incoming_hash = fingerprint_hash(fingerprint)
            drift = fingerprint_drift(device.fingerprint_hash, incoming_hash)
            if drift:
                db.add(Fingerprint(device_id=device.device_id, fingerprint_hash=incoming_hash, raw_fingerprint={"header": fingerprint}, drift_score=drift))

        entropy_mismatch = bool(body and len(set(body)) <= 2)
        risk = self.risk.evaluate(
            db=db,
            device=device,
            device_id=device_id,
            ip_address=ip_address,
            signature_valid=signature_valid,
            stale_timestamp=stale_timestamp,
            replay=replay,
            drift_score=drift,
            entropy_mismatch=entropy_mismatch,
        )
        if device:
            device.last_seen_at = datetime.now(timezone.utc)
            db.add(device)
        db.add(
            RateLimitSnapshot(
                device_id=device_id,
                ip_address=ip_address,
                window_start=datetime.now(timezone.utc),
                request_count=risk.minute_count,
                burst_count=risk.burst_count,
            )
        )
        db.commit()

        return {
            "device_id": device_id,
            "ip_address": ip_address,
            "signature_valid": signature_valid,
            "action": risk.action,
            "risk_score": risk.score,
            "reason": ",".join(risk.reasons),
        }

    @staticmethod
    def _timestamp_age(timestamp: str) -> float | None:
        try:
            sent_at = datetime.fromtimestamp(int(timestamp), timezone.utc)
        except (TypeError, ValueError, OSError):
            return None
        return abs((datetime.now(timezone.utc) - sent_at).total_seconds())

    @staticmethod
    def _replay(device_id: str | None, timestamp: str, signature: str) -> bool:
        if not device_id or not timestamp or not signature:
            return False
        key = f"replay:{device_id}:{timestamp}:{signature}"
        return not bool(redis_client.set(key, "1", nx=True, ex=settings.replay_window_seconds + 15))

    def _log(self, request: Request, digest: str, db, decision: dict, started: float) -> None:
        safe_headers = {
            key: value
            for key, value in request.headers.items()
            if key.lower().startswith("x-") or key.lower() in {"user-agent", "content-type"}
        }
        log = RequestLog(
            device_id=decision["device_id"],
            ip_address=decision["ip_address"],
            method=request.method,
            path=request.url.path,
            headers=safe_headers,
            body_hash=digest,
            signature_valid=decision["signature_valid"],
            decision=decision["action"],
            risk_score=decision["risk_score"],
            reason=decision["reason"],
            latency_ms=round((time.perf_counter() - started) * 1000, 2),
        )
        db.add(log)
        db.flush()
        db.add(
            Decision(
                request_id=log.id,
                device_id=decision["device_id"],
                action=decision["action"],
                risk_score=decision["risk_score"],
                reason=decision["reason"],
            )
        )
        db.commit()
