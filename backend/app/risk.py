from dataclasses import dataclass
from time import time

from redis import Redis
from sqlalchemy.orm import Session

from app.config import settings
from app.models import Device


@dataclass
class RiskDecision:
    action: str
    score: int
    reasons: list[str]
    minute_count: int
    burst_count: int


class RiskScoringEngine:
    def __init__(self, redis_client: Redis):
        self.redis = redis_client

    def evaluate(
        self,
        *,
        db: Session,
        device: Device | None,
        device_id: str | None,
        ip_address: str,
        signature_valid: bool,
        stale_timestamp: bool,
        replay: bool,
        drift_score: float,
        entropy_mismatch: bool,
    ) -> RiskDecision:
        score = 0
        reasons: list[str] = []
        identity = device_id or f"ip:{ip_address}"
        now = time()

        if device is None:
            score += 35
            reasons.append("unknown_device")
        elif device.status == "banned":
            score += 100
            reasons.append("banned_device")
        elif device.status == "flagged":
            score += 15
            reasons.append("flagged_device")

        if not signature_valid:
            score += 50
            reasons.append("signature_mismatch")
            failed = self.redis.incr(f"failed-signatures:{identity}")
            self.redis.expire(f"failed-signatures:{identity}", 300)
            if failed >= 3:
                score += 20
                reasons.append("repeated_failed_signatures")

        if stale_timestamp:
            score += 35
            reasons.append("stale_timestamp")

        if replay:
            score += 60
            reasons.append("replay_detected")

        trust = device.trust_score if device else 25
        minute_limit = max(10, int(settings.base_rate_limit_per_minute * max(trust, 20) / 100))
        burst_limit = max(4, int(settings.burst_rate_limit_per_10_seconds * max(trust, 20) / 100))
        minute_count = self._sliding_count(f"rl:minute:{identity}", now, 60)
        burst_count = self._sliding_count(f"rl:burst:{identity}", now, 10)
        if minute_count > minute_limit:
            score += 22
            reasons.append("adaptive_rate_limit")
        if burst_count > burst_limit:
            score += 25
            reasons.append("burst_traffic")

        last_key = f"timing:last:{identity}"
        previous = self.redis.get(last_key)
        self.redis.setex(last_key, 180, str(now))
        if previous:
            bucket = round(now - float(previous), 2)
            bucket_key = f"timing:repeat:{identity}:{bucket}"
            repeats = self.redis.incr(bucket_key)
            self.redis.expire(bucket_key, 180)
            if repeats >= 4 and bucket < 2:
                score += 20
                reasons.append("identical_timing_intervals")

        ip_key = f"ip-devices:{ip_address}"
        if device_id:
            self.redis.sadd(ip_key, device_id)
            self.redis.expire(ip_key, 900)
        if self.redis.scard(ip_key) >= 5:
            score += 25
            reasons.append("same_ip_many_device_ids")

        if drift_score >= 55:
            score += 30
            reasons.append("major_fingerprint_drift")
        elif drift_score >= 15:
            score += 12
            reasons.append("minor_fingerprint_drift")

        if entropy_mismatch:
            score += 10
            reasons.append("high_request_entropy_mismatch")

        score = min(score, 100)
        if score >= 85:
            action = "ban"
        elif score >= 55:
            action = "throttle"
        elif score >= 35:
            action = "challenge"
        else:
            action = "allow"

        if device:
            device.trust_score = max(0, min(100, device.trust_score + 0.1 - (score / 80)))
            if action == "ban":
                device.status = "banned"
            elif action in {"challenge", "throttle"} and device.status == "active":
                device.status = "flagged"
            db.add(device)

        return RiskDecision(action=action, score=score, reasons=reasons or ["clean"], minute_count=minute_count, burst_count=burst_count)

    def _sliding_count(self, key: str, now: float, window_seconds: int) -> int:
        pipe = self.redis.pipeline()
        pipe.zremrangebyscore(key, 0, now - window_seconds)
        pipe.zadd(key, {str(now): now})
        pipe.expire(key, window_seconds + 5)
        pipe.zcard(key)
        return int(pipe.execute()[-1])
