import React from "react";
import { createRoot } from "react-dom/client";
import { Activity, Ban, Gauge, ListFilter, RefreshCcw, ShieldAlert, ShieldCheck, Zap } from "lucide-react";
import {
  Area,
  AreaChart,
  Bar,
  BarChart,
  CartesianGrid,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis
} from "recharts";
import { API_BASE, getJson, type Device, type Event, type Metrics } from "./lib/api";
import { mockDevices, mockEvents, mockMetrics } from "./lib/mock";
import { collectFingerprint, WasmIntegrityRuntime } from "./wasm/integrityRuntime";
import "./styles.css";

function useConsoleData() {
  const [devices, setDevices] = React.useState<Device[]>(mockDevices);
  const [events, setEvents] = React.useState<Event[]>(mockEvents);
  const [metrics, setMetrics] = React.useState<Metrics>(mockMetrics);
  const [apiLive, setApiLive] = React.useState(false);

  const refresh = React.useCallback(async () => {
    try {
      const [nextDevices, nextEvents, nextMetrics] = await Promise.all([
        getJson<Device[]>("/api/devices"),
        getJson<Event[]>("/api/events"),
        getJson<Metrics>("/api/metrics")
      ]);
      setDevices(nextDevices);
      setEvents(nextEvents);
      setMetrics(nextMetrics);
      setApiLive(true);
    } catch {
      setApiLive(false);
    }
  }, []);

  React.useEffect(() => {
    refresh();
    const timer = window.setInterval(refresh, 3000);
    return () => window.clearInterval(timer);
  }, [refresh]);

  return { devices, events, metrics, apiLive, refresh };
}

function Pill({ value }: { value: string }) {
  return <span className={`pill ${value}`}>{value}</span>;
}

function MetricCard({ label, value, icon }: { label: string; value: string | number; icon: React.ReactNode }) {
  return (
    <div className="metric-card">
      <span className="metric-icon">{icon}</span>
      <span>
        <small>{label}</small>
        <strong>{value}</strong>
      </span>
    </div>
  );
}

function App() {
  const { devices, events, metrics, apiLive, refresh } = useConsoleData();
  const [runtime] = React.useState(() => new WasmIntegrityRuntime());
  const [clientState, setClientState] = React.useState("unregistered");

  const registerAndCall = async () => {
    const fingerprint = collectFingerprint();
    const response = await fetch(`${API_BASE}/api/device/register`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ fingerprint })
    });
    const registered = await response.json();
    await runtime.install(registered.device_id, registered.encrypted_seed, fingerprint);
    const headers = await runtime.signedHeaders("GET", "/api/protected");
    const protectedResponse = await fetch(`${API_BASE}/api/protected`, { headers });
    setClientState(`${protectedResponse.status} ${protectedResponse.ok ? "signed request allowed" : "signed request challenged"}`);
    refresh();
  };

  const attackSeries = metrics.requests_per_minute.map((point) => ({
    ...point,
    time: new Date(point.time).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })
  }));
  const blockedPct = metrics.total_requests
    ? Math.round(((metrics.blocked + metrics.challenged) / metrics.total_requests) * 100)
    : 0;

  return (
    <main>
      <header className="topbar">
        <div>
          <p className="eyebrow">Client Integrity & Anti-Bot System</p>
          <h1>Security Operations Console</h1>
        </div>
        <div className="top-actions">
          <span className={`api-state ${apiLive ? "online" : "offline"}`}>{apiLive ? "real API" : "mock fallback"}</span>
          <button onClick={registerAndCall}>Signed Demo</button>
          <button className="icon-button" onClick={refresh} title="Refresh">
            <RefreshCcw size={17} />
          </button>
        </div>
      </header>

      <section className="client-strip">
        <ShieldCheck size={18} />
        <span>WASM-style protected seed runtime:</span>
        <strong>{clientState}</strong>
      </section>

      <section className="metrics-grid">
        <MetricCard label="Total Requests" value={metrics.total_requests} icon={<Activity size={19} />} />
        <MetricCard label="Allowed" value={metrics.allowed} icon={<ShieldCheck size={19} />} />
        <MetricCard label="Blocked" value={`${blockedPct}%`} icon={<Ban size={19} />} />
        <MetricCard label="Flagged Devices" value={metrics.devices.flagged} icon={<ShieldAlert size={19} />} />
      </section>

      <section className="layout">
        <article className="panel">
          <div className="panel-title">
            <h2>Device Monitor</h2>
            <ListFilter size={18} />
          </div>
          <div className="table">
            <div className="row head">
              <span>Device</span>
              <span>Status</span>
              <span>Trust</span>
            </div>
            {devices.map((device) => (
              <div className="row" key={device.device_id}>
                <span className="mono">{device.device_id}</span>
                <Pill value={device.status} />
                <span>{Math.round(device.trust_score)}</span>
              </div>
            ))}
          </div>
        </article>

        <article className="panel">
          <div className="panel-title">
            <h2>Attack Visualization</h2>
            <Zap size={18} />
          </div>
          <ResponsiveContainer width="100%" height={260}>
            <AreaChart data={attackSeries}>
              <CartesianGrid strokeDasharray="3 3" stroke="#263244" />
              <XAxis dataKey="time" stroke="#8ea0b8" />
              <YAxis stroke="#8ea0b8" />
              <Tooltip contentStyle={{ background: "#101826", border: "1px solid #263244" }} />
              <Area type="monotone" dataKey="count" stroke="#40c4aa" fill="#40c4aa22" />
              <Area type="monotone" dataKey="blocked" stroke="#d94645" fill="#d9464528" />
            </AreaChart>
          </ResponsiveContainer>
        </article>
      </section>

      <section className="layout lower">
        <article className="panel">
          <div className="panel-title">
            <h2>Live Requests Feed</h2>
            <Activity size={18} />
          </div>
          {events.map((event) => (
            <div className="event" key={event.id}>
              <div className="event-main">
                <Pill value={event.decision} />
                <span className="mono">{event.method} {event.path}</span>
                <span>{event.ip_address}</span>
                <strong>risk {event.risk_score}</strong>
              </div>
              <div className="event-sub">
                <span>{event.reason}</span>
                <span>{event.signature_valid ? "signed" : "invalid"}</span>
                <span>{Math.round(event.latency_ms)} ms</span>
              </div>
            </div>
          ))}
        </article>

        <article className="panel">
          <div className="panel-title">
            <h2>Metrics</h2>
            <Gauge size={18} />
          </div>
          <ResponsiveContainer width="100%" height={250}>
            <BarChart data={metrics.risk_distribution}>
              <CartesianGrid strokeDasharray="3 3" stroke="#263244" />
              <XAxis dataKey="score" stroke="#8ea0b8" />
              <YAxis stroke="#8ea0b8" />
              <Tooltip contentStyle={{ background: "#101826", border: "1px solid #263244" }} />
              <Bar dataKey="count" fill="#f0b35a" radius={[4, 4, 0, 0]} />
            </BarChart>
          </ResponsiveContainer>
        </article>
      </section>
    </main>
  );
}

createRoot(document.getElementById("root")!).render(<App />);
