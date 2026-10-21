export const API_BASE = import.meta.env.VITE_API_BASE_URL ?? "http://localhost:8000";

export type Device = {
  device_id: string;
  fingerprint_hash: string;
  status: "active" | "flagged" | "banned";
  trust_score: number;
  last_seen_at: string | null;
  created_at: string;
};

export type Event = {
  id: number;
  device_id: string | null;
  ip_address: string;
  method: string;
  path: string;
  headers: Record<string, string>;
  body_hash: string;
  signature_valid: boolean;
  decision: string;
  risk_score: number;
  reason: string;
  latency_ms: number;
  created_at: string;
};

export type Metrics = {
  total_requests: number;
  allowed: number;
  blocked: number;
  challenged: number;
  devices: { active: number; flagged: number; banned: number };
  requests_per_minute: Array<{ time: string; count: number; allowed: number; blocked: number }>;
  risk_distribution: Array<{ score: number; count: number }>;
};

export async function getJson<T>(path: string): Promise<T> {
  const response = await fetch(`${API_BASE}${path}`);
  if (!response.ok) {
    throw new Error(`${path} failed: ${response.status}`);
  }
  return response.json();
}
