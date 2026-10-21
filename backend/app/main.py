from datetime import datetime, timedelta, timezone
from uuid import uuid4

from fastapi import Depends, FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import case, desc, func
from sqlalchemy.orm import Session

from app.config import settings
from app.database import get_db
from app.middleware import IntegrityMiddleware
from app.models import Decision, Device, Fingerprint, RequestLog
from app.schemas import BanDeviceRequest, DeviceOut, DeviceRegisterRequest, DeviceRegisterResponse, EventOut
from app.security import device_secret, fingerprint_hash, secret_hash, wasm_encrypt_seed

app = FastAPI(title="Client Integrity & Anti-Bot System", version="1.0.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origin_list,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
app.add_middleware(IntegrityMiddleware)


@app.get("/health")
def health() -> dict:
    return {"status": "ok"}


@app.post("/api/device/register", response_model=DeviceRegisterResponse)
def register_device(payload: DeviceRegisterRequest, db: Session = Depends(get_db)) -> DeviceRegisterResponse:
    secret = device_secret()
    fp_hash = fingerprint_hash(payload.fingerprint)
    device = Device(device_id=str(uuid4()), secret_hash=secret_hash(secret), fingerprint_hash=fp_hash, status="active", trust_score=70)
    db.add(device)
    db.flush()
    db.add(Fingerprint(device_id=device.device_id, fingerprint_hash=fp_hash, raw_fingerprint=payload.fingerprint, drift_score=0))
    db.commit()
    return DeviceRegisterResponse(device_id=device.device_id, encrypted_seed=wasm_encrypt_seed(secret))


@app.get("/api/protected")
def protected() -> dict:
    return {"ok": True, "message": "signed device-bound request accepted", "served_at": datetime.now(timezone.utc).isoformat()}


@app.get("/api/devices", response_model=list[DeviceOut])
def devices(db: Session = Depends(get_db)) -> list[Device]:
    return db.query(Device).order_by(desc(Device.created_at)).limit(250).all()


@app.get("/api/events", response_model=list[EventOut])
def events(limit: int = 100, db: Session = Depends(get_db)) -> list[RequestLog]:
    return db.query(RequestLog).order_by(desc(RequestLog.created_at)).limit(min(limit, 500)).all()


@app.get("/api/metrics")
def metrics(db: Session = Depends(get_db)) -> dict:
    since = datetime.now(timezone.utc) - timedelta(minutes=10)
    total = db.query(func.count(RequestLog.id)).scalar() or 0
    allowed = db.query(func.count(RequestLog.id)).filter(RequestLog.decision == "allow").scalar() or 0
    throttled = db.query(func.count(RequestLog.id)).filter(RequestLog.decision == "throttle").scalar() or 0
    banned = db.query(func.count(RequestLog.id)).filter(RequestLog.decision == "ban").scalar() or 0
    challenged = db.query(func.count(RequestLog.id)).filter(RequestLog.decision == "challenge").scalar() or 0
    device_counts = {
        "active": db.query(func.count(Device.id)).filter(Device.status == "active").scalar() or 0,
        "flagged": db.query(func.count(Device.id)).filter(Device.status == "flagged").scalar() or 0,
        "banned": db.query(func.count(Device.id)).filter(Device.status == "banned").scalar() or 0,
    }
    rpm = (
        db.query(
            func.date_trunc("minute", RequestLog.created_at).label("bucket"),
            func.count(RequestLog.id).label("count"),
            func.sum(case((RequestLog.decision == "allow", 1), else_=0)).label("allowed"),
            func.sum(case((RequestLog.decision != "allow", 1), else_=0)).label("blocked"),
        )
        .filter(RequestLog.created_at >= since)
        .group_by("bucket")
        .order_by("bucket")
        .all()
    )
    risk = (
        db.query(func.floor(RequestLog.risk_score / 10).label("bucket"), func.count(RequestLog.id))
        .group_by("bucket")
        .order_by("bucket")
        .all()
    )
    return {
        "total_requests": total,
        "allowed": allowed,
        "blocked": throttled + banned,
        "challenged": challenged,
        "devices": device_counts,
        "requests_per_minute": [
            {"time": row.bucket.isoformat(), "count": row.count, "allowed": row.allowed or 0, "blocked": row.blocked or 0}
            for row in rpm
        ],
        "risk_distribution": [{"score": int(bucket or 0) * 10, "count": count} for bucket, count in risk],
    }


@app.post("/api/admin/ban-device")
def ban_device(payload: BanDeviceRequest, db: Session = Depends(get_db)) -> dict:
    device = db.query(Device).filter(Device.device_id == payload.device_id).first()
    if not device:
        raise HTTPException(status_code=404, detail="device not found")
    device.status = "banned"
    db.add(device)
    db.add(Decision(device_id=device.device_id, action="ban", risk_score=100, reason=payload.reason))
    db.commit()
    return {"device_id": device.device_id, "status": "banned"}
