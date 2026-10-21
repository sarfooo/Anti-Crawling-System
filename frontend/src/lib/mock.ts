import type { Device, Event, Metrics } from "./api";

export const mockDevices: Device[] = [
  {
    device_id: "mock-active-device",
    fingerprint_hash: "12b2f8a0d4e39aa0",
    status: "active",
    trust_score: 88,
    last_seen_at: new Date().toISOString(),
    created_at: new Date().toISOString()
  },
  {
    device_id: "mock-flagged-device",
    fingerprint_hash: "ff43ac91c20e94bb",
    status: "flagged",
    trust_score: 34,
    last_seen_at: new Date().toISOString(),
    created_at: new Date().toISOString()
  }
];

export const mockEvents: Event[] = [
  {
    id: 1,
    device_id: "mock-active-device",
    ip_address: "127.0.0.1",
    method: "GET",
    path: "/api/protected",
    headers: { "x-device-id": "mock-active-device" },
    body_hash: "empty",
    signature_valid: true,
    decision: "allow",
    risk_score: 3,
    reason: "clean",
    latency_ms: 8,
    created_at: new Date().toISOString()
  },
  {
    id: 2,
    device_id: null,
    ip_address: "127.0.0.1",
    method: "GET",
    path: "/api/protected",
    headers: { "user-agent": "rotator" },
    body_hash: "empty",
    signature_valid: false,
    decision: "throttle",
    risk_score: 78,
    reason: "unknown_device,signature_mismatch",
    latency_ms: 13,
    created_at: new Date().toISOString()
  }
];

export const mockMetrics: Metrics = {
  total_requests: 2,
  allowed: 1,
  blocked: 1,
  challenged: 0,
  devices: { active: 1, flagged: 1, banned: 0 },
  requests_per_minute: [
    { time: new Date(Date.now() - 120000).toISOString(), count: 2, allowed: 2, blocked: 0 },
    { time: new Date(Date.now() - 60000).toISOString(), count: 9, allowed: 3, blocked: 6 },
    { time: new Date().toISOString(), count: 4, allowed: 2, blocked: 2 }
  ],
  risk_distribution: [
    { score: 0, count: 1 },
    { score: 70, count: 1 }
  ]
};
