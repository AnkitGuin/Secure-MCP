import { useEffect, useMemo, useState } from "react";
import type { ReactNode } from "react";
import { createRoot } from "react-dom/client";
import { BrowserRouter, Link, NavLink, Route, Routes, useLocation, useParams } from "react-router-dom";
import { UserManager, WebStorageStateStore, InMemoryWebStorage } from "oidc-client-ts";
import type { User } from "oidc-client-ts";
import {
  Activity,
  ArrowDownToLine,
  ArrowRight,
  ArrowUpRight,
  BookOpen,
  ChartNoAxesCombined,
  ChevronRight,
  CircleCheck,
  CircleX,
  Clock3,
  Database,
  FlaskConical,
  Fingerprint,
  Gauge,
  Layers3,
  LockKeyhole,
  Menu,
  Network,
  RefreshCw,
  ScanLine,
  Settings2,
  Shield,
  ShieldCheck,
  SlidersHorizontal,
  X,
} from "lucide-react";
import { api, download, useLoad } from "./api";
import type {
  Api,
  Approval,
  Benchmark,
  Case,
  Connector,
  Event,
  Me,
  Overview,
  Policy,
  PolicyConfig,
  Simulation,
  Tool,
} from "./api";
import "./style.css";

const nav = [
  { title: "Overview", href: "/", icon: Gauge, group: "Workspace" },
  { title: "Tool Registry", href: "/tools", icon: Network, group: "Workspace" },
  { title: "Policy Center", href: "/policies", icon: Layers3, group: "Workspace" },
  { title: "Approval Queue", href: "/approvals", icon: ShieldCheck, group: "Workspace" },
  { title: "Security Events", href: "/events", icon: ScanLine, group: "Workspace" },
  { title: "Attack Lab", href: "/lab", icon: FlaskConical, group: "Evaluation" },
  { title: "Policy Simulator", href: "/simulator", icon: SlidersHorizontal, group: "Evaluation" },
  { title: "Benchmarks", href: "/benchmarks", icon: ChartNoAxesCombined, group: "Evaluation" },
  { title: "Settings", href: "/settings", icon: Settings2, group: "Administration" },
] as const;
const descriptions: Record<string, string> = {
  Overview: "Monitor tool access, policy decisions, and connector health for your workspace.",
  "Tool Registry": "Inspect trusted connectors, tool schemas, and manifest drift.",
  "Policy Center": "Review active rules and stage a bounded policy change.",
  "Approval Queue": "Review sensitive requests bound to a specific tool call.",
  "Security Events": "Inspect policy decisions and verify the tenant audit chain.",
  "Attack Lab": "Compare how the same synthetic attack behaves under three controls.",
  "Policy Simulator": "Replay sanitized decisions against a candidate without invoking tools.",
  Benchmarks: "Inspect observed outcomes and latency across reproducible test scenarios.",
  Settings: "Review your identity, tenant membership, and operational limits.",
};
const names: Record<string, string> = {
  direct: "Direct upstream",
  prompt_only: "Prompt guard",
  protected: "SecureMCP",
  require_approval: "Approval required",
  allow: "Allowed",
  deny: "Denied",
  crm: "CRM",
  docs: "Documents",
  messages: "Messaging",
};
const fmt = (value: string) =>
  names[value] ||
  value
    .toLowerCase()
    .replaceAll("_", " ")
    .replace(/^./, (c) => c.toUpperCase());
const date = (seconds?: number) =>
  seconds
    ? new Date(seconds * 1000).toLocaleString([], {
        month: "short",
        day: "numeric",
        hour: "2-digit",
        minute: "2-digit",
      })
    : "—";
const utcDate = (seconds?: number) =>
  seconds
    ? new Date(seconds * 1000).toLocaleString([], {
        month: "short",
        day: "numeric",
        hour: "2-digit",
        minute: "2-digit",
        timeZone: "UTC",
      })
    : "—";
const short = (s: string) => s?.slice(0, 8) || "—";
const admin = (me: Me) => me.roles.includes("security_admin");
const canAudit = (me: Me) => admin(me) || me.roles.includes("auditor");
const count = (n: unknown) => (typeof n === "number" ? n.toLocaleString() : "—");
const pct = (n: unknown) => (typeof n === "number" ? (n * 100).toFixed(1) + "%" : "—");

function Brand() {
  return (
    <div className="brand">
      <div className="brand-icon">
        <Shield size={21} />
        <span />
      </div>
      <div>
        <strong>SecureMCP</strong>
        <small>OPERATIONS CONSOLE</small>
      </div>
    </div>
  );
}
function Badge({ value }: { value: string }) {
  const variant = ["allow", "APPROVED", "ACTIVE", "ready", "SUCCEEDED", "CONSUMED"].includes(value)
    ? "good"
    : ["deny", "DRIFTED", "REJECTED", "REVOKED", "unavailable"].includes(value)
      ? "bad"
      : ["require_approval", "PENDING", "UNKNOWN_REQUIRES_RECONCILIATION", "EXPIRED"].includes(value)
        ? "warn"
        : "neutral";
  return (
    <span className={"badge " + variant}>
      <i />
      {fmt(value)}
    </span>
  );
}
function Empty({ children = "No records match this view." }: { children?: ReactNode }) {
  return (
    <div className="empty">
      <Database size={19} />
      {children}
    </div>
  );
}
function Panel({
  title,
  detail,
  action,
  children,
  className = "",
}: {
  title: string;
  detail?: string;
  action?: ReactNode;
  children: ReactNode;
  className?: string;
}) {
  return (
    <section className={"panel " + className}>
      <div className="panel-head">
        <div>
          <h2>{title}</h2>
          {detail && <p>{detail}</p>}
        </div>
        {action}
      </div>
      {children}
    </section>
  );
}
function Load({ loading, error, children }: { loading: boolean; error: string; children: ReactNode }) {
  if (error)
    return (
      <div className="notice error" role="alert">
        <CircleX size={17} />
        {error}
      </div>
    );
  if (loading)
    return (
      <div className="loading" role="status">
        <RefreshCw size={18} /> Loading workspace data…
      </div>
    );
  return <>{children}</>;
}
function DataTable({ columns, rows }: { columns: string[]; rows: ReactNode[][] }) {
  if (!rows.length) return <Empty />;
  return (
    <div className="table-wrap">
      <table>
        <thead>
          <tr>
            {columns.map((label) => (
              <th key={label} scope="col">
                {label}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {rows.map((row, index) => (
            <tr key={index}>
              {row.map((cell, column) => (
                <td key={column}>{cell}</td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
function JsonView({ value }: { value: unknown }) {
  return <pre className="json">{JSON.stringify(value, null, 2)}</pre>;
}
function Button({
  children,
  onClick,
  disabled,
  kind = "",
}: {
  children: ReactNode;
  onClick: () => void;
  disabled?: boolean;
  kind?: string;
}) {
  return (
    <button type="button" className={"button " + kind} onClick={onClick} disabled={disabled}>
      {children}
    </button>
  );
}
function useAction() {
  const [message, setMessage] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  async function run<T>(work: () => Promise<T>, success: string): Promise<T | undefined> {
    setBusy(true);
    setError("");
    setMessage("");
    try {
      const value = await work();
      setMessage(success);
      return value;
    } catch (e) {
      setError(e instanceof Error ? e.message : "Request failed.");
      return undefined;
    } finally {
      setBusy(false);
    }
  }
  return {
    busy,
    run,
    notice: error ? (
      <div className="notice error" role="alert">
        <CircleX size={16} />
        {error}
      </div>
    ) : message ? (
      <div className="notice success" role="status">
        <CircleCheck size={16} />
        {message}
      </div>
    ) : null,
  };
}

function ActivityGraph({ data }: { data: Overview["series"] }) {
  const [selected, setSelected] = useState<number | null>(null);
  if (!data.length) return <Empty>Activity will appear after an MCP tool call.</Empty>;
  const max = Math.max(...data.map((item) => item.count), 4);
  const graph = data.length === 1 ? [{ time: data[0].time - 3600, count: 0 }, ...data] : data;
  const coords = graph.map((item, i) => ({
    x: 40 + (i * 584) / (graph.length - 1),
    y: 159 - (item.count / max) * 133,
    ...item,
  }));
  const line = coords.map(({ x, y }) => `${x},${y}`).join(" ");
  const item = selected === null ? null : coords[selected];
  return (
    <div className="graph">
      <svg viewBox="0 0 650 190" role="img" aria-label="Tool decisions per hour">
        <defs>
          <linearGradient id="chart-fill" x2="0" y2="1">
            <stop stopColor="#a78bfa" stopOpacity=".3" />
            <stop offset="1" stopColor="#a78bfa" stopOpacity="0" />
          </linearGradient>
        </defs>
        {[0, 1, 2, 3, 4].map((index) => (
          <g key={index}>
            <path d={`M40 ${26 + index * 33.25}H624`} className="chart-grid" />
            <text x="3" y={30 + index * 33.25}>
              {Math.round(max * (1 - index / 4))}
            </text>
          </g>
        ))}
        <polygon points={`40,159 ${line} 624,159`} fill="url(#chart-fill)" />
        <polyline points={line} fill="none" stroke="#a78bfa" strokeWidth="2.5" />
        {coords.map((point, index) => (
          <circle
            key={point.time}
            cx={point.x}
            cy={point.y}
            r={selected === index ? 6 : 3.5}
            fill="#c4b5fd"
            tabIndex={0}
            aria-label={`${utcDate(point.time)}: ${point.count} calls`}
            onFocus={() => setSelected(index)}
            onMouseEnter={() => setSelected(index)}
          />
        ))}
        <text x="40" y="182">
          {utcDate(graph[0].time)}
        </text>
        <text x="624" y="182" textAnchor="end">
          {utcDate(graph.at(-1)?.time)}
        </text>
      </svg>
      <div className="chart-key">
        <i />
        {item ? `${utcDate(item.time)} · ${item.count} calls` : "Tool calls per hour"}
      </div>
    </div>
  );
}
function OverviewPage({ call, me }: { call: Api; me: Me }) {
  const [hours, setHours] = useState(24);
  const query = useLoad<Overview>(call, "/overview?hours=" + hours);
  const d = query.data;
  return (
    <Load {...query}>
      {d && (
        <>
          <div className="toolbar">
            <div className="context-tag">
              <span className="tenant-dot" />
              {fmt(me.tenant)} Systems
            </div>
            <div className="spacer" />
            <label className="inline">
              <Clock3 size={15} />
              <select
                aria-label="Time range"
                value={hours}
                onChange={(e) => setHours(Number(e.target.value))}
              >
                <option value={24}>Last 24 hours</option>
                <option value={48}>Last 48 hours</option>
                <option value={168}>Last 7 days</option>
              </select>
            </label>
            <Button onClick={query.refresh}>
              <RefreshCw size={15} /> Refresh
            </Button>
          </div>
          <div className="kpis">
            {[
              {
                label: "Tool calls",
                value: d.total,
                icon: Activity,
                accent: "violet",
                caption: "Requests in the selected period",
              },
              {
                label: "Allowed",
                value: d.counts.allow ?? 0,
                icon: CircleCheck,
                accent: "green",
                caption: "Approved for dispatch",
              },
              {
                label: "Denied",
                value: d.counts.deny ?? 0,
                icon: Shield,
                accent: "red",
                caption: "Blocked before dispatch",
              },
              {
                label: "Approval required",
                value: d.counts.require_approval ?? 0,
                icon: LockKeyhole,
                accent: "gold",
                caption: "Requests routed to a reviewer",
              },
            ].map(({ label, value, icon: Icon, accent, caption }) => (
              <div className="kpi" key={label}>
                <div>
                  <span>{label}</span>
                  <i className={accent}>
                    <Icon size={17} />
                  </i>
                </div>
                <strong>{count(value)}</strong>
                <small>{caption}</small>
              </div>
            ))}
          </div>
          <div className="main-grid">
            <Panel
              title="Tool call activity"
              detail="Hourly decisions for the selected period"
              action={<span className="muted mono">UTC</span>}
            >
              <ActivityGraph data={d.series} />
            </Panel>
            <Panel
              title="Gateway health"
              detail={`${d.active_connectors} enabled connectors`}
              className="health"
            >
              <ul>
                {Object.entries(d.health).map(([key, value]) => (
                  <li key={key}>
                    <span>{fmt(key)}</span>
                    <Badge value={value ? "ready" : "unavailable"} />
                  </li>
                ))}
              </ul>
            </Panel>
          </div>
          <div className="split-grid">
            <Panel title="Decision latency" detail="Gateway decision path">
              <div className="compact-kpis">
                <div>
                  <small>Median</small>
                  <strong>{d.latency.p50} ms</strong>
                </div>
                <div>
                  <small>95th percentile</small>
                  <strong>{d.latency.p95} ms</strong>
                </div>
              </div>
            </Panel>
            <Panel title="Blocked or gated by risk" detail="Known risk classifications">
              <div className="compact-kpis">
                {Object.entries(d.risk_counts).map(([key, value]) => (
                  <div key={key}>
                    <small>{key}</small>
                    <strong>{value}</strong>
                  </div>
                ))}
                {!Object.keys(d.risk_counts).length && (
                  <span className="muted">No blocked or gated calls.</span>
                )}
              </div>
            </Panel>
          </div>
          <Panel
            title="Recent decisions"
            detail="Latest tool activity in this workspace"
            action={
              canAudit(me) && (
                <Link to="/events" className="button">
                  View events <ArrowRight size={15} />
                </Link>
              )
            }
          >
            <EventsTable items={d.latest} links={canAudit(me)} />
          </Panel>
        </>
      )}
    </Load>
  );
}
function EventsTable({ items, links = true }: { items: Event[]; links?: boolean }) {
  return (
    <DataTable
      columns={["Tool", "Decision", "Reason", "Time", ""]}
      rows={items.map((event) => [
        <span className="mono">{event.tool}</span>,
        <Badge value={event.effect} />,
        fmt(event.reason),
        date(event.occurred),
        links ? (
          <Link aria-label={`Inspect ${event.tool}`} to={"/events/" + event.id}>
            <ArrowUpRight size={16} />
          </Link>
        ) : null,
      ])}
    />
  );
}
function EventsPage({ call }: { call: Api }) {
  const [filters, setFilters] = useState({
    effect: "",
    tool: "",
    reason: "",
    trace: "",
    subject: "",
    since: "",
  });
  const [cursor, setCursor] = useState<number | null>(null);
  const [verified, setVerified] = useState<{ valid: boolean; events: number }>();
  const search = new URLSearchParams(
    Object.entries(filters)
      .filter(([, value]) => value)
      .map(([key, value]) => [key, key === "since" ? String(new Date(value).getTime() / 1000) : value]),
  );
  if (cursor) search.set("cursor", String(cursor));
  const query = useLoad<{ items: Event[]; next_cursor: number | null }>(call, "/audit/events?" + search);
  const action = useAction();
  return (
    <>
      {action.notice}
      <Panel
        title="Audit explorer"
        detail="Filter the tenant-scoped, redacted event stream"
        action={
          <div className="actions">
            <Button
              onClick={async () => {
                const value = await action.run(
                  () => call<{ valid: boolean; events: number }>("/audit/integrity"),
                  "Audit chain checked.",
                );
                if (value) setVerified(value);
              }}
              disabled={action.busy}
            >
              <Fingerprint size={16} /> Verify integrity
            </Button>
            <Button onClick={() => download("security-events.json", query.data)} disabled={!query.data}>
              <ArrowDownToLine size={16} /> Export page
            </Button>
          </div>
        }
      >
        <div className="filters">
          {Object.keys(filters).map((key) => (
            <label key={key}>
              {fmt(key)}
              <input
                aria-label={fmt(key)}
                type={key === "since" ? "date" : "text"}
                value={filters[key as keyof typeof filters]}
                onChange={(e) => {
                  setFilters({ ...filters, [key]: e.target.value });
                  setCursor(null);
                }}
              />
            </label>
          ))}
        </div>
        {verified && (
          <div className={"notice " + (verified.valid ? "success" : "error")}>
            {verified.valid ? "Chain verified" : "Integrity mismatch"} · {verified.events} events
          </div>
        )}
        <Load {...query}>
          {query.data && (
            <>
              <EventsTable items={query.data.items} />
              <div className="panel-foot actions">
                <Button onClick={() => setCursor(null)} disabled={!cursor}>
                  First page
                </Button>
                <Button
                  onClick={() => setCursor(query.data?.next_cursor ?? null)}
                  disabled={!query.data.next_cursor}
                >
                  Next page <ChevronRight size={15} />
                </Button>
              </div>
            </>
          )}
        </Load>
      </Panel>
    </>
  );
}
function Detail({ call, kind }: { call: Api; kind: "events" | "approvals" | "tools" | "benchmarks" }) {
  const { id } = useParams();
  const endpoint = {
    events: "/audit/events",
    approvals: "/approvals",
    tools: "/tools",
    benchmarks: "/benchmarks/runs",
  }[kind];
  const query = useLoad<Record<string, unknown>>(call, endpoint + "/" + encodeURIComponent(id ?? ""));
  return (
    <Panel
      title={id ?? "Details"}
      action={
        <Link to={"/" + kind} className="button">
          <X size={16} /> Close
        </Link>
      }
    >
      <Load {...query}>{query.data && <JsonView value={query.data} />}</Load>
    </Panel>
  );
}
function RegistryPage({ call, me }: { call: Api; me: Me }) {
  const connectors = useLoad<Connector[]>(call, "/connectors");
  const tools = useLoad<Tool[]>(call, "/tools");
  const { id } = useParams();
  const detail = useLoad<Tool>(call, id ? "/tools/" + encodeURIComponent(id) : null);
  const action = useAction();
  const [connector, setConnector] = useState("crm");
  const [rationale, setRationale] = useState("");
  const mutate = async (path: string, body: unknown, notice: string) => {
    if (await action.run(() => call(path, body), notice)) {
      connectors.refresh();
      tools.refresh();
      detail.refresh();
    }
  };
  return (
    <>
      {action.notice}
      <Panel
        title="Connectors"
        detail="Pinned private MCP endpoints"
        action={
          admin(me) && (
            <div className="actions">
              <select
                aria-label="Connector to register"
                value={connector}
                onChange={(e) => setConnector(e.target.value)}
              >
                {["crm", "docs", "messages"].map((item) => (
                  <option key={item}>{item}</option>
                ))}
              </select>
              <Button
                disabled={action.busy}
                onClick={() => void mutate("/connectors", { connector }, "Connector registered.")}
              >
                Register
              </Button>
            </div>
          )
        }
      >
        <Load {...connectors}>
          <div className="connectors">
            {connectors.data?.map((c) => (
              <article key={c.id} className="connector">
                <div>
                  <Network size={19} />
                  <h3>{fmt(c.id)}</h3>
                  <Badge value={c.enabled ? "ACTIVE" : "disabled"} />
                </div>
                <p>Streamable HTTP · Pinned endpoint</p>
                <small>Last discovery {date(c.last_discovery ?? undefined)}</small>
                {admin(me) && (
                  <div className="actions">
                    <Button
                      disabled={action.busy}
                      onClick={() =>
                        void mutate(`/connectors/${c.id}/discover`, {}, "Discovery finished.")
                      }
                    >
                      Discover
                    </Button>
                    <Button
                      disabled={action.busy}
                      onClick={() =>
                        void mutate(
                          `/connectors/${c.id}/${c.enabled ? "disable" : "enable"}`,
                          {},
                          "Connector status updated.",
                        )
                      }
                    >
                      {c.enabled ? "Disable" : "Enable"}
                    </Button>
                  </div>
                )}
              </article>
            ))}
          </div>
        </Load>
      </Panel>
      <Panel title="Tool manifests" detail="Risk, scopes, and approval status">
        <Load {...tools}>
          <DataTable
            columns={["Tool", "Risk", "Required scope", "Manifest", "Status"]}
            rows={(tools.data ?? []).map((t) => [
              canAudit(me) ? (
                <Link className="mono" to={"/tools/" + t.tool}>
                  {t.tool}
                </Link>
              ) : (
                <span className="mono">{t.tool}</span>
              ),
              t.risk ?? "—",
              t.scope ?? "—",
              t.version ?? "—",
              <Badge value={t.state} />,
            ])}
          />
        </Load>
      </Panel>
      {id && (
        <Panel
          title={id}
          detail="Manifest comparison"
          action={
            <Link className="button" to="/tools">
              <X size={16} /> Close
            </Link>
          }
        >
          <Load {...detail}>
            {detail.data && (
              <>
                <div className="split-grid">
                  <div>
                    <h3>Approved definition</h3>
                    <JsonView value={detail.data.definition} />
                  </div>
                  {detail.data.candidate && (
                    <div>
                      <h3>Discovered candidate</h3>
                      <JsonView value={detail.data.candidate} />
                    </div>
                  )}
                </div>
                {admin(me) && detail.data.candidate_fingerprint && (
                  <div className="panel-foot actions">
                    <input
                      aria-label="Manifest rationale"
                      placeholder="Review rationale"
                      value={rationale}
                      onChange={(e) => setRationale(e.target.value)}
                    />
                    <Button
                      kind="primary"
                      disabled={action.busy || rationale.trim().length < 8}
                      onClick={() =>
                        void mutate(
                          `/tools/${id}/approve-manifest`,
                          { fingerprint: detail.data?.candidate_fingerprint, rationale },
                          "Manifest approved.",
                        )
                      }
                    >
                      Approve exact fingerprint
                    </Button>
                  </div>
                )}
              </>
            )}
          </Load>
        </Panel>
      )}
    </>
  );
}
const defaultPolicy: PolicyConfig = {
  export_cap: 5,
  external_domains: [],
  export_roles: ["team_lead"],
  export_requires_approval: true,
  disabled_tools: [],
  redact_pii: true,
};
function PoliciesPage({ call, me }: { call: Api; me: Me }) {
  const query = useLoad<Policy[]>(call, "/policies");
  const [config, setConfig] = useState<PolicyConfig>(defaultPolicy);
  const [domains, setDomains] = useState("");
  const [disabled, setDisabled] = useState("");
  const [rationale, setRationale] = useState("");
  const [reviewReason, setReviewReason] = useState("");
  const [chosen, setChosen] = useState<Policy>();
  const action = useAction();
  const mutate = async (path: string, body: unknown, notice: string) => {
    if (await action.run(() => call(path, body), notice)) query.refresh();
  };
  const current = query.data?.find((p) => p.state === "ACTIVE");
  return (
    <>
      {action.notice}
      <div className="split-grid">
        <Panel title="Active policy" detail="Effective configuration and approval rules">
          <Load {...query}>
            {current ? (
              <>
                <div className="panel-foot actions">
                  <Badge value={current.state} />
                  <code>{current.id}</code>
                  <Button
                    onClick={() => {
                      setConfig(current.config);
                      setDomains(current.config.external_domains.join(", "));
                      setDisabled(current.config.disabled_tools.join(", "));
                    }}
                  >
                    Copy to draft
                  </Button>
                </div>
                <JsonView value={current.config} />
              </>
            ) : (
              <Empty />
            )}
          </Load>
        </Panel>
        {admin(me) && (
          <Panel
            title="Stage a policy draft"
            detail="Changes require validation and a second administrator"
          >
            <div className="form">
              <label>
                Maximum export records
                <input
                  type="number"
                  min="1"
                  max="20"
                  value={config.export_cap}
                  onChange={(e) => setConfig({ ...config, export_cap: Number(e.target.value) })}
                />
              </label>
              <label>
                Approved external domains
                <input
                  value={domains}
                  onChange={(e) => setDomains(e.target.value)}
                  placeholder="Comma-separated domains"
                />
              </label>
              <label>
                Disabled tools
                <input
                  value={disabled}
                  onChange={(e) => setDisabled(e.target.value)}
                  placeholder="Comma-separated tool IDs"
                />
              </label>
              <fieldset>
                <legend>Export roles</legend>
                <div className="actions">
                  {["team_lead", "support_agent", "demo_agent"].map((role) => (
                    <label className="check" key={role}>
                      <input
                        type="checkbox"
                        checked={config.export_roles.includes(role)}
                        onChange={(e) =>
                          setConfig({
                            ...config,
                            export_roles: e.target.checked
                              ? [...config.export_roles, role]
                              : config.export_roles.filter((item) => item !== role),
                          })
                        }
                      />
                      {fmt(role)}
                    </label>
                  ))}
                </div>
              </fieldset>
              <label className="check">
                <input
                  type="checkbox"
                  checked={config.export_requires_approval}
                  onChange={(e) => setConfig({ ...config, export_requires_approval: e.target.checked })}
                />{" "}
                Require export review
              </label>
              <label>
                Change rationale
                <textarea value={rationale} onChange={(e) => setRationale(e.target.value)} />
              </label>
              <Button
                kind="primary"
                disabled={action.busy || rationale.trim().length < 8}
                onClick={() =>
                  void mutate(
                    "/policies/drafts",
                    {
                      config: {
                        ...config,
                        external_domains: domains
                          .split(",")
                          .map((x) => x.trim())
                          .filter(Boolean),
                        disabled_tools: disabled
                          .split(",")
                          .map((x) => x.trim())
                          .filter(Boolean),
                      },
                      rationale,
                    },
                    "Policy draft staged.",
                  )
                }
              >
                Stage draft <ArrowRight size={16} />
              </Button>
            </div>
          </Panel>
        )}
      </div>
      <Panel title="Policy history" detail="Version, validation, and activation">
        <Load {...query}>
          <DataTable
            columns={["Version", "State", "Reason", "Validation", "Actions"]}
            rows={(query.data ?? []).map((p) => [
              <Button onClick={() => setChosen(p)}>{short(p.id)}</Button>,
              <Badge value={p.state} />,
              p.reason,
              p.validated ? "Passed" : "Pending",
              <div className="actions">
                {admin(me) && p.state === "DRAFT" && (
                  <>
                    <Button
                      disabled={action.busy}
                      onClick={() =>
                        void mutate(`/policies/drafts/${p.id}/validate`, {}, "Draft validation passed.")
                      }
                    >
                      Validate
                    </Button>
                    {p.validated && p.author !== me.sub && (
                      <Button
                        onClick={() => {
                          setChosen(p);
                          setReviewReason("");
                        }}
                      >
                        Review activation
                      </Button>
                    )}
                  </>
                )}
              </div>,
            ])}
          />
        </Load>
      </Panel>
      {chosen && (
        <Panel
          title={`Policy ${short(chosen.id)}`}
          action={
            <Button onClick={() => setChosen(undefined)}>
              <X size={15} /> Close
            </Button>
          }
        >
          <JsonView value={chosen.config} />
          {admin(me) && chosen.author !== me.sub && chosen.validated && chosen.state === "DRAFT" && (
            <div className="panel-foot actions">
              <input
                aria-label="Activation rationale"
                value={reviewReason}
                onChange={(e) => setReviewReason(e.target.value)}
              />
              <Button
                kind="primary"
                disabled={reviewReason.length < 8 || action.busy}
                onClick={() => {
                  void mutate(
                    `/policies/drafts/${chosen.id}/activate`,
                    { rationale: reviewReason },
                    "Policy activated.",
                  );
                  setChosen(undefined);
                }}
              >
                Confirm activation
              </Button>
            </div>
          )}
        </Panel>
      )}
    </>
  );
}
function ApprovalsPage({ call, me }: { call: Api; me: Me }) {
  const { id } = useParams();
  const [status, setStatus] = useState("");
  const [review, setReview] = useState<{ id: string; action: "approve" | "reject" | "revoke" }>();
  const [revealed, setRevealed] = useState<{ id: string; data: unknown }>();
  const [rationale, setRationale] = useState("");
  const query = useLoad<Approval[]>(call, "/approvals" + (status ? "?status=" + status : ""));
  const detail = useLoad<Approval>(call, id ? "/approvals/" + id : null);
  const action = useAction();
  const statuses = [
    "",
    "PENDING",
    "APPROVED",
    "REJECTED",
    "REVOKED",
    "EXPIRED",
    "CONSUMED",
    "UNKNOWN_REQUIRES_RECONCILIATION",
  ];
  return (
    <>
      {action.notice}
      <Panel
        title="Approval requests"
        detail="Refresh the queue to retrieve the latest decisions."
        action={
          <Button
            onClick={() => {
              query.refresh();
              detail.refresh();
            }}
          >
            <RefreshCw size={15} /> Refresh
          </Button>
        }
      >
        <div className="tabs">
          {statuses.map((item) => (
            <button
              key={item}
              className={status === item ? "active" : ""}
              onClick={() => setStatus(item)}
            >
              {item ? fmt(item) : "All"}
            </button>
          ))}
        </div>
        <Load {...query}>
          <DataTable
            columns={["Action", "Requester", "Status", "Expires", ""]}
            rows={(query.data ?? []).map((row) => [
              <Link to={"/approvals/" + row.id} className="mono">
                {row.tool}
              </Link>,
              short(row.requester),
              <Badge value={row.status} />,
              date(row.expires),
              <Link to={"/approvals/" + row.id} aria-label="Review request">
                <ArrowUpRight size={16} />
              </Link>,
            ])}
          />
        </Load>
      </Panel>
      {id && (
        <Panel
          title="Review exact action"
          detail={id}
          action={
            <Link className="button" to="/approvals">
              <X size={16} /> Close
            </Link>
          }
        >
          <Load {...detail}>
            {detail.data && (
              <>
                <div className="panel-foot actions">
                  <Badge value={detail.data.status} />
                  <span className="mono">{detail.data.tool}</span>
                  <span className="muted">Expires {date(detail.data.expires)}</span>
                </div>
                <JsonView value={detail.data.preview} />
                {detail.data.reviews && <JsonView value={detail.data.reviews} />}
                {revealed?.id === id && <JsonView value={revealed?.data} />}
                {admin(me) &&
                  detail.data.requester !== me.sub &&
                  detail.data.expires * 1000 > Date.now() && (
                    <div className="panel-foot actions">
                      <Button
                        onClick={async () => {
                          if (revealed?.id === id) {
                            setRevealed(undefined);
                            return;
                          }
                          const data = await action.run(
                            () => call("/approvals/" + id + "/arguments"),
                            "Access to exact arguments recorded.",
                          );
                          if (data && id) setRevealed({ id, data });
                        }}
                      >
                        {revealed?.id === id ? "Hide exact arguments" : "Reveal exact arguments"}
                      </Button>
                    </div>
                  )}
                {admin(me) &&
                  detail.data.requester !== me.sub &&
                  ["PENDING", "APPROVED"].includes(detail.data.status) && (
                    <div className="panel-foot actions">
                      {detail.data.status === "PENDING" && (
                        <>
                          <Button kind="primary" onClick={() => setReview({ id, action: "approve" })}>
                            Approve
                          </Button>
                          <Button onClick={() => setReview({ id, action: "reject" })}>Reject</Button>
                        </>
                      )}
                      <Button onClick={() => setReview({ id, action: "revoke" })}>Revoke</Button>
                    </div>
                  )}
              </>
            )}
          </Load>
        </Panel>
      )}
      {review && review.id === id && (
        <dialog
          open
          className="dialog"
          aria-labelledby="review-title"
          onKeyDown={(e) => {
            if (e.key === "Escape") setReview(undefined);
          }}
        >
          <h2 id="review-title">Confirm {review.action}</h2>
          <p>Changes to arguments require a new approval. This decision applies to the action shown.</p>
          <label>
            Review rationale
            <textarea autoFocus value={rationale} onChange={(e) => setRationale(e.target.value)} />
          </label>
          <div className="actions">
            <Button onClick={() => setReview(undefined)}>Cancel</Button>
            <Button
              kind="primary"
              disabled={rationale.trim().length < 8 || action.busy}
              onClick={async () => {
                if (
                  await action.run(
                    () => call(`/approvals/${review.id}/${review.action}`, { rationale }),
                    "Review recorded.",
                  )
                ) {
                  setReview(undefined);
                  setRationale("");
                  query.refresh();
                  detail.refresh();
                }
              }}
            >
              Confirm {review.action}
            </Button>
          </div>
        </dialog>
      )}
    </>
  );
}
function SimulatorPage({ call, me }: { call: Api; me: Me }) {
  const policies = useLoad<Policy[]>(call, "/policies");
  const [candidate, setCandidate] = useState("");
  const [tool, setTool] = useState("");
  const [risk, setRisk] = useState("");
  const [role, setRole] = useState("");
  const [report, setReport] = useState<Simulation>();
  const action = useAction();
  const simulate = async (save: boolean) => {
    const response = await action.run(
      () =>
        call<Simulation>("/policies/simulate", {
          candidate,
          ...(tool ? { tool } : {}),
          ...(risk ? { risk } : {}),
          ...(role ? { role } : {}),
          save,
        }),
      save ? "Simulation report saved." : "Simulation finished.",
    );
    if (response) setReport(response);
  };
  return (
    <>
      {action.notice}
      <Panel
        title="Replay configuration"
        detail="Use recent redacted facts from your tenant to compare current and candidate rules."
      >
        <div className="filters">
          <label>
            Candidate version
            <select value={candidate} onChange={(e) => setCandidate(e.target.value)}>
              <option value="">Select a policy</option>
              {policies.data?.map((p) => (
                <option key={p.id} value={p.id}>
                  {short(p.id)} · {p.state} · {p.reason}
                </option>
              ))}
            </select>
          </label>
          <label>
            Tool
            <input value={tool} onChange={(e) => setTool(e.target.value)} placeholder="All tools" />
          </label>
          <label>
            Role
            <input value={role} onChange={(e) => setRole(e.target.value)} placeholder="All roles" />
          </label>
          <label>
            Risk
            <select value={risk} onChange={(e) => setRisk(e.target.value)}>
              <option value="">All tiers</option>
              {["R0", "R1", "R2", "R3"].map((r) => (
                <option key={r}>{r}</option>
              ))}
            </select>
          </label>
        </div>
        <div className="panel-foot actions">
          <Button
            kind="primary"
            onClick={() => void simulate(false)}
            disabled={!candidate || action.busy}
          >
            <FlaskConical size={16} /> Compare decisions
          </Button>
          {admin(me) && (
            <Button onClick={() => void simulate(true)} disabled={!candidate || action.busy}>
              Save report
            </Button>
          )}
        </div>
      </Panel>
      {report && (
        <Panel
          title="Decision comparison"
          detail={`${report.cases.length} replayed requests`}
          action={
            <Button onClick={() => download("policy-simulation.json", report)}>
              <ArrowDownToLine size={16} /> Download
            </Button>
          }
        >
          <div className="compact-kpis">
            {["allow", "deny", "require_approval"].map((effect) => (
              <div key={effect}>
                <small>Newly {fmt(effect).toLowerCase()}</small>
                <strong>{report.changes[effect] ?? 0}</strong>
              </div>
            ))}
          </div>
          <DataTable
            columns={["Tool", "Risk", "Current", "Candidate", "Review"]}
            rows={report.cases.map((item) => [
              <Link className="mono" to={"/events/" + item.event_id}>
                {item.tool}
              </Link>,
              item.risk,
              <>
                <Badge value={item.current_effect} />
                <small>{item.current_reasons.map(fmt).join(", ")}</small>
              </>,
              <>
                <Badge value={item.candidate_effect} />
                <small>{item.candidate_reasons.map(fmt).join(", ")}</small>
              </>,
              item.regression ? "Potential regression" : "—",
            ])}
          />
        </Panel>
      )}
    </>
  );
}
function BenchmarkBars({ modes }: { modes: Benchmark["summary"]["modes"] }) {
  const metrics = [
    { label: "Unauthorized execution", key: "unauthorized_execution_rate", color: "var(--red)" },
    { label: "Legitimate completion", key: "legitimate_completion", color: "var(--good)" },
  ];
  return (
    <div className="benchmark-bars">
      {metrics.map((metric) => (
        <div key={metric.key}>
          <h3>{metric.label}</h3>
          {Object.entries(modes).map(([mode, summary]) => {
            const value = summary[metric.key];
            return (
              <div className="bar-row" key={mode}>
                <span>{fmt(mode)}</span>
                <div className="bar-track" aria-hidden="true">
                  <div
                    style={{
                      width: typeof value === "number" ? pct(value) : "0%",
                      background: metric.color,
                    }}
                  />
                </div>
                <strong>{pct(value)}</strong>
              </div>
            );
          })}
        </div>
      ))}
    </div>
  );
}
function Experiment({ call, me, lab }: { call: Api; me: Me; lab: boolean }) {
  const { id } = useParams();
  const query = useLoad<Benchmark[]>(call, "/benchmarks/runs");
  const [selected, setSelected] = useState("");
  const [scenario, setScenario] = useState(lab ? "INJECT-001" : "all");
  const [offset, setOffset] = useState(0);
  const runId = id || selected;
  const detail = useLoad<Benchmark>(call, runId ? "/benchmarks/runs/" + runId : null);
  const outcomes = useLoad<Case[]>(
    call,
    runId ? `/benchmarks/runs/${runId}/results?offset=${offset}` : null,
  );
  const action = useAction();
  const d = detail.data;
  const cases = outcomes.data ?? [];
  return (
    <>
      {action.notice}
      <Panel
        title={lab ? "Run a synthetic attack" : "Benchmark runs"}
        detail={
          lab
            ? "Each condition starts from an isolated synthetic dataset."
            : "Review previous suites or run the deterministic benchmark."
        }
      >
        <div className="panel-foot actions">
          {admin(me) && (
            <>
              <label>
                Scenario
                <select value={scenario} onChange={(e) => setScenario(e.target.value)}>
                  {Object.entries(
                    lab
                      ? {
                          "INJECT-001": "Injected export",
                          "INJECT-002": "Injected external message",
                          "CROSS-001": "Cross-tenant read",
                          "REVIEW-001": "Approval argument swap",
                          "TRUST-002": "Tool manifest drift",
                        }
                      : {
                          all: "Full 150-case suite",
                          held_out: "Held-out cases",
                          development: "Development cases",
                        },
                  ).map(([value, label]) => (
                    <option value={value} key={value}>
                      {label}
                    </option>
                  ))}
                </select>
              </label>
              <Button
                kind="primary"
                disabled={action.busy}
                onClick={async () => {
                  const run = await action.run(
                    () => call<{ id: string }>("/benchmarks/runs", { scenario }),
                    "Run completed.",
                  );
                  if (run) {
                    setSelected(run.id);
                    setOffset(0);
                    query.refresh();
                  }
                }}
              >
                <FlaskConical size={16} />
                {action.busy ? "Running…" : "Run " + (lab ? "scenario" : "benchmark")}
              </Button>
            </>
          )}
          {!lab && (
            <label>
              Saved run
              <select
                value={runId}
                onChange={(e) => {
                  setSelected(e.target.value);
                  setOffset(0);
                }}
              >
                <option value="">Select a run</option>
                {query.data?.map((run) => (
                  <option key={run.id} value={run.id}>
                    {short(run.id)} · {run.summary.selection} · {date(run.created)}
                  </option>
                ))}
              </select>
            </label>
          )}
        </div>
      </Panel>
      {runId && (
        <Load {...detail}>
          {d && (
            <>
              <Panel
                title="Observed results"
                detail={d.summary.execution_environment}
                action={
                  <Link className="button" to={"/benchmarks/" + d.id}>
                    Run permalink <ArrowUpRight size={15} />
                  </Link>
                }
              >
                {!lab && <BenchmarkBars modes={d.summary.modes} />}
                <DataTable
                  columns={[
                    "Condition",
                    "Attack success",
                    "Unauthorized execution",
                    "Legitimate completion",
                    "p95 latency",
                  ]}
                  rows={Object.entries(d.summary.modes).map(([mode, m]) => [
                    fmt(mode),
                    pct(m.attack_success_rate),
                    pct(m.unauthorized_execution_rate),
                    pct(m.legitimate_completion),
                    typeof m.latency_p95_ms === "number" ? m.latency_p95_ms + " ms" : "—",
                  ])}
                />
              </Panel>
              {lab && cases[0] && (
                <div className="split-grid">
                  <Panel title="Original task" detail={cases[0].objective}>
                    <JsonView value={cases[0].args} />
                  </Panel>
                  <Panel title="Untrusted content">
                    <div className="panel-foot">
                      {cases[0].untrusted_input ?? "This scenario uses a crafted tool request."}
                    </div>
                  </Panel>
                </div>
              )}
              <Panel
                title="Case outcomes"
                detail="Decisions and database effects"
                action={
                  <Button
                    onClick={() =>
                      download("benchmark-page.json", { summary: d.summary, results: cases })
                    }
                  >
                    <ArrowDownToLine size={16} /> Download page
                  </Button>
                }
              >
                <Load {...outcomes}>
                  <DataTable
                    columns={[
                      "Case",
                      "Mode",
                      "Decision codes",
                      "Committed",
                      "Database delta",
                      "Latency",
                    ]}
                    rows={cases.map((row) => [
                      <span className="mono">{row.scenario}</span>,
                      fmt(row.mode),
                      row.codes.map(fmt).join(" · "),
                      row.committed ? "Yes" : "No",
                      <code>{JSON.stringify(row.db_delta)}</code>,
                      row.latency_ms + " ms",
                    ])}
                  />
                  <div className="panel-foot actions">
                    <Button onClick={() => setOffset(Math.max(0, offset - 100))} disabled={offset === 0}>
                      Previous
                    </Button>
                    <Button onClick={() => setOffset(offset + 100)} disabled={cases.length < 100}>
                      Next <ChevronRight size={15} />
                    </Button>
                  </div>
                </Load>
              </Panel>
            </>
          )}
        </Load>
      )}
    </>
  );
}
function SettingsPage({ call, me }: { call: Api; me: Me }) {
  const query = useLoad<{
    policy: PolicyConfig;
    approval_ttl: number;
    quota_per_minute: number;
    memberships: { sub: string; name: string; roles: string[]; enabled: boolean }[];
  }>(call, "/settings");
  const [edit, setEdit] = useState<{ sub: string; name: string; roles: string[]; enabled: boolean }>();
  const [reason, setReason] = useState("");
  const action = useAction();
  return (
    <Load {...query}>
      {query.data && (
        <>
          <div className="split-grid">
            <Panel title="Authenticated identity">
              <dl className="properties">
                <dt>Principal</dt>
                <dd>{me.name}</dd>
                <dt>Tenant</dt>
                <dd>{me.tenant}</dd>
                <dt>Role</dt>
                <dd>{me.roles.map(fmt).join(", ")}</dd>
                <dt>Scopes</dt>
                <dd>{me.scopes.join(", ")}</dd>
              </dl>
            </Panel>
            <Panel title="Runtime limits">
              <dl className="properties">
                <dt>Approval lifetime</dt>
                <dd>{query.data.approval_ttl} seconds</dd>
                <dt>Call quota</dt>
                <dd>{query.data.quota_per_minute} per minute</dd>
                <dt>Output masking</dt>
                <dd>Enabled by policy</dd>
              </dl>
            </Panel>
          </div>
          {action.notice}
          {admin(me) && (
            <Panel title="Tenant membership">
              <DataTable
                columns={["Identity", "Role", "State", ""]}
                rows={query.data.memberships.map((m) => [
                  m.name,
                  m.roles.map(fmt).join(", "),
                  <Badge value={m.enabled ? "ACTIVE" : "disabled"} />,
                  !m.roles.includes("security_admin") && (
                    <Button
                      onClick={() => {
                        setEdit(m);
                        setReason("");
                      }}
                    >
                      Edit membership
                    </Button>
                  ),
                ])}
              />
            </Panel>
          )}
          {edit && (
            <Panel
              title={`Edit ${edit.name}`}
              action={<Button onClick={() => setEdit(undefined)}>Cancel</Button>}
            >
              <div className="form">
                <label className="check">
                  <input
                    type="checkbox"
                    checked={edit.enabled}
                    onChange={(event) => setEdit({ ...edit, enabled: event.target.checked })}
                  />
                  Membership enabled
                </label>
                <fieldset>
                  <legend>Roles</legend>
                  <div className="actions">
                    {["support_agent", "team_lead", "auditor", "demo_agent"].map((role) => (
                      <label className="check" key={role}>
                        <input
                          type="checkbox"
                          checked={edit.roles.includes(role)}
                          onChange={(event) =>
                            setEdit({
                              ...edit,
                              roles: event.target.checked
                                ? [...edit.roles, role]
                                : edit.roles.filter((value) => value !== role),
                            })
                          }
                        />
                        {fmt(role)}
                      </label>
                    ))}
                  </div>
                </fieldset>
                <label>
                  Change rationale
                  <input value={reason} onChange={(event) => setReason(event.target.value)} />
                </label>
                <Button
                  kind="primary"
                  disabled={action.busy || !edit.roles.length || reason.trim().length < 8}
                  onClick={async () => {
                    if (
                      await action.run(
                        () =>
                          call("/settings/memberships/" + edit.sub, {
                            roles: edit.roles,
                            enabled: edit.enabled,
                            rationale: reason,
                          }),
                        "Membership updated.",
                      )
                    ) {
                      setEdit(undefined);
                      query.refresh();
                    }
                  }}
                >
                  Confirm membership change
                </Button>
              </div>
            </Panel>
          )}
        </>
      )}
    </Load>
  );
}

function Console({ call, me, onLogout }: { call: Api; me: Me; onLogout: () => void }) {
  const location = useLocation();
  const [menu, setMenu] = useState(false);
  const page =
    nav.find((item) =>
      item.href === "/" ? location.pathname === "/" : location.pathname.startsWith(item.href),
    )?.title ?? "Overview";
  return (
    <div className="layout">
      <a className="skip" href="#content">
        Skip to content
      </a>
      <aside className={menu ? "sidebar open" : "sidebar"}>
        <Link to="/" aria-label="SecureMCP overview">
          <Brand />
        </Link>
        <div className="tenant-card">
          <div className="tenant-icon">{me.tenant.slice(0, 1).toUpperCase()}</div>
          <div>
            <strong>{fmt(me.tenant)} Systems</strong>
            <small>Tenant workspace</small>
          </div>
        </div>
        <nav aria-label="Main navigation">
          {["Workspace", "Evaluation", "Administration"].map((group) => (
            <div className="nav-group" key={group}>
              <span>{group}</span>
              {nav
                .filter((item) => item.group === group)
                .map(({ title, href, icon: Icon }) => (
                  <NavLink key={href} to={href} end={href === "/"} onClick={() => setMenu(false)}>
                    <Icon size={17} />
                    {title}
                  </NavLink>
                ))}
            </div>
          ))}
        </nav>
        <div className="side-foot">
          <div className="avatar">
            {me.name
              .split("-")
              .map((word) => word[0].toUpperCase())
              .join("")}
          </div>
          <div>
            <strong>{me.name}</strong>
            <small>{me.roles.map(fmt).join(", ")}</small>
          </div>
        </div>
      </aside>
      <div className="workspace">
        <header className="top">
          <Button onClick={() => setMenu(!menu)} kind="mobile-menu">
            <Menu size={18} />
          </Button>
          <span className="breadcrumbs">
            Workspace <ChevronRight size={13} /> <strong>{page}</strong>
          </span>
          <div className="spacer" />
          <span className="environment">
            <i /> Synthetic environment
          </span>
          <Button onClick={onLogout}>Sign out</Button>
        </header>
        <main id="content">
          <div className="page-head">
            <div className="section-mark">
              <ShieldCheck size={15} /> Security operations
            </div>
            <h1>{page}</h1>
            <p>{descriptions[page]}</p>
          </div>
          <Routes>
            <Route index element={<OverviewPage call={call} me={me} />} />
            <Route path="/tools/:id?" element={<RegistryPage call={call} me={me} />} />
            <Route path="/policies" element={<PoliciesPage call={call} me={me} />} />
            <Route path="/approvals/:id?" element={<ApprovalsPage call={call} me={me} />} />
            <Route path="/events" element={<EventsPage call={call} />} />
            <Route path="/events/:id" element={<Detail call={call} kind="events" />} />
            <Route path="/simulator" element={<SimulatorPage call={call} me={me} />} />
            <Route path="/lab" element={<Experiment call={call} me={me} lab key="lab" />} />
            <Route
              path="/benchmarks/:id?"
              element={<Experiment call={call} me={me} lab={false} key="benchmarks" />}
            />
            <Route path="/settings" element={<SettingsPage call={call} me={me} />} />
            <Route path="*" element={<Empty>View not found.</Empty>} />
          </Routes>
        </main>
      </div>
    </div>
  );
}
function Connected({ token, onLogout }: { token: string; onLogout: () => void }) {
  const call = useMemo(() => api(token), [token]);
  const query = useLoad<Me>(call, "/me");
  if (!query.data)
    return (
      <div className="signin">
        <Brand />
        <Load {...query}>
          <Button onClick={onLogout}>Sign out</Button>
        </Load>
        {query.error && <Button onClick={onLogout}>Sign out</Button>}
      </div>
    );
  return <Console call={call} me={query.data} onLogout={onLogout} />;
}
let initialization: Promise<{ manager: UserManager; user: User | null }> | undefined;
function initialize() {
  initialization ??= fetch("/api/config", { credentials: "omit", cache: "no-store" }).then(
    async (response) => {
      if (!response.ok) throw new Error("Identity configuration could not be loaded.");
      const config = (await response.json()) as { issuer: string; client_id: string };
      const manager = new UserManager({
        authority: config.issuer,
        client_id: config.client_id,
        redirect_uri: location.origin + "/callback",
        post_logout_redirect_uri: location.origin,
        response_type: "code",
        scope: "openid",
        automaticSilentRenew: false,
        monitorSession: false,
        userStore: new WebStorageStateStore({ store: new InMemoryWebStorage() }),
        stateStore: new WebStorageStateStore({ store: window.sessionStorage }),
      });
      const callback = location.pathname === "/callback";
      const user = callback ? await manager.signinRedirectCallback() : await manager.getUser();
      if (callback) history.replaceState(null, "", "/");
      return { manager, user };
    },
  );
  return initialization;
}
function App() {
  const [state, setState] = useState<{ manager: UserManager; user: User | null }>();
  const [error, setError] = useState("");
  useEffect(() => {
    void initialize()
      .then(setState)
      .catch(() =>
        setError("Sign-in could not be completed. Reload the console to start a new session."),
      );
  }, []);
  useEffect(() => {
    if (!state?.user) return;
    const logout = () => setState((previous) => (previous ? { ...previous, user: null } : previous));
    state.manager.events.addAccessTokenExpired(logout);
    return () => state.manager.events.removeAccessTokenExpired(logout);
  }, [state]);
  async function logout() {
    if (!state) return;
    await state.manager.removeUser();
    try {
      await state.manager.signoutRedirect({ id_token_hint: state.user?.id_token });
    } catch {
      setState({ ...state, user: null });
    }
  }
  if (state?.user && !state.user.expired)
    return (
      <BrowserRouter>
        <Connected token={state.user.access_token} onLogout={() => void logout()} />
      </BrowserRouter>
    );
  return (
    <main className="signin">
      <div className="signin-card">
        <Brand />
        <div className="signin-icon">
          <ShieldCheck size={37} />
        </div>
        <h1>Sign in to SecureMCP</h1>
        <p>Manage enterprise tool access, review sensitive requests, and investigate security events.</p>
        {error && (
          <div className="notice error" role="alert">
            {error}
          </div>
        )}
        <Button
          kind="primary"
          disabled={!state}
          onClick={() =>
            void state?.manager
              .signinRedirect()
              .catch(() => setError("Could not connect to the identity provider."))
          }
        >
          <LockKeyhole size={17} /> Continue with Keycloak <ArrowRight size={16} />
        </Button>
        <small>
          <BookOpen size={14} /> Local demonstration · Synthetic data only
        </small>
      </div>
    </main>
  );
}
createRoot(document.getElementById("root")!).render(<App />);
