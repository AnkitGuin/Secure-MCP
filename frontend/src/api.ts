import { useCallback, useEffect, useState } from "react";

export type Json = null | boolean | number | string | Json[] | { [key: string]: Json };
export type Me = { sub: string; name: string; tenant: string; roles: string[]; scopes: string[] };
export type Event = {
  id: string;
  seq: number;
  trace: string;
  principal: string;
  tool: string;
  effect: string;
  reason: string;
  outcome: string;
  duration_ms: number;
  occurred: number;
  details: Json;
};
export type Overview = {
  total: number;
  counts: Record<string, number>;
  active_connectors: number;
  latency: { p50: number; p95: number };
  series: { time: number; count: number }[];
  risk_counts: Record<string, number>;
  health: Record<string, boolean>;
  latest: Event[];
};
export type Connector = { id: string; enabled: boolean; last_discovery: number | null };
export type Tool = {
  tool: string;
  connector: string;
  version: number;
  state: string;
  scope: string;
  risk: string;
  fingerprint: string;
  definition: Json;
  candidate?: Json;
  candidate_fingerprint?: string;
};
export type PolicyConfig = {
  export_cap: number;
  external_domains: string[];
  export_roles: string[];
  export_requires_approval: boolean;
  disabled_tools: string[];
  redact_pii: true;
};
export type Policy = {
  id: string;
  state: string;
  reason: string;
  author: string;
  checksum: string;
  created: number;
  validated: boolean;
  config: PolicyConfig;
};
export type Approval = {
  id: string;
  requester: string;
  tool: string;
  status: string;
  preview: Json;
  expires: number;
  created: number;
  policy_id: string;
  reviews?: Json;
};
export type Simulation = {
  id?: string;
  current: string;
  candidate: string;
  changes: Record<string, number>;
  cases: {
    event_id: string;
    tool: string;
    risk: string;
    current_effect: string;
    candidate_effect: string;
    current_reasons: string[];
    candidate_reasons: string[];
    regression: boolean;
  }[];
};
export type Case = {
  scenario: string;
  mode: string;
  category: string;
  tool: string;
  objective: string;
  codes: string[];
  args: Json;
  untrusted_input: string | null;
  latency_ms: number;
  committed: boolean;
  unauthorized_effect: boolean;
  db_delta: Json;
};
export type Benchmark = {
  id: string;
  created: number;
  summary: {
    selection: string;
    scenario_count: number;
    suite: string;
    execution_environment: string;
    modes: Record<string, Record<string, Json>>;
  };
};

export function api(token: string) {
  return async <T>(path: string, body?: unknown): Promise<T> => {
    const response = await fetch("/api/v1" + path, {
      credentials: "omit",
      cache: "no-store",
      headers: {
        Authorization: "Bearer " + token,
        ...(body === undefined ? {} : { "Content-Type": "application/json" }),
      },
      ...(body === undefined ? {} : { method: "POST", body: JSON.stringify(body) }),
    });
    if (!response.ok) {
      const payload = await response.json().catch(() => ({}));
      throw new Error(
        payload.error
          ? `${payload.error.message} · ${payload.error.request_id}`
          : `Request failed (${response.status})`,
      );
    }
    return response.json() as Promise<T>;
  };
}

export type Api = ReturnType<typeof api>;
export function useLoad<T>(call: Api, path: string | null) {
  const [response, setResponse] = useState<{
    path: string;
    revision: number;
    data?: T;
    error?: string;
  }>();
  const [revision, setRevision] = useState(0);
  const refresh = useCallback(() => setRevision((n) => n + 1), []);
  useEffect(() => {
    if (path === null) return;
    let active = true;
    call<T>(path)
      .then((data) => {
        if (active) setResponse({ path, revision, data });
      })
      .catch((error: Error) => {
        if (active) setResponse({ path, revision, error: error.message });
      });
    return () => {
      active = false;
    };
  }, [call, path, revision]);
  const current = response?.path === path && response.revision === revision ? response : undefined;
  return {
    data: current?.data,
    error: current?.error ?? "",
    loading: path !== null && !current,
    refresh,
  };
}

export function download(name: string, value: unknown) {
  const url = URL.createObjectURL(
    new Blob([JSON.stringify(value, null, 2)], { type: "application/json" }),
  );
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = name;
  anchor.click();
  URL.revokeObjectURL(url);
}
