from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field


class DeviceRegisterRequest(BaseModel):
    fingerprint: dict[str, Any] = Field(default_factory=dict)


class DeviceRegisterResponse(BaseModel):
    device_id: str
    encrypted_seed: str
    seed_format: str = "wasm-demo-envelope-v1"


class DeviceOut(BaseModel):
    device_id: str
    fingerprint_hash: str
    status: str
    trust_score: float
    last_seen_at: datetime | None
    created_at: datetime

    model_config = {"from_attributes": True}


class EventOut(BaseModel):
    id: int
    device_id: str | None
    ip_address: str
    method: str
    path: str
    headers: dict[str, Any]
    body_hash: str
    signature_valid: bool
    decision: str
    risk_score: int
    reason: str
    latency_ms: float
    created_at: datetime

    model_config = {"from_attributes": True}


class BanDeviceRequest(BaseModel):
    device_id: str
    reason: str = "manual admin ban"
