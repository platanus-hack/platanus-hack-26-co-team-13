import { randomUUID } from "node:crypto";
import { definePluginEntry } from "openclaw/plugin-sdk/plugin-entry";

const ADAPTER_VERSION = "0.1.0";
const DEFAULT_URL = "http://127.0.0.1:8000/api/v1/firewall/tool-calls/authorize";

type JsonObject = Record<string, unknown>;
type Decision = { decision: "allow" | "block" | "review"; reason?: string };
type HookResult = {
  params: JsonObject;
  block?: true;
  blockReason?: string;
  requireApproval?: {
    title: string;
    description: string;
    severity: "warning";
    timeoutMs: number;
    allowedDecisions: Array<"allow-once" | "deny">;
  };
};

function isObject(value: unknown): value is JsonObject {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function unprotectedTools(): Set<string> {
  return new Set(
    (process.env.MEMORY_FIREWALL_UNPROTECTED_TOOLS ?? "")
      .split(",")
      .map((name) => name.trim().toLowerCase())
      .filter(Boolean),
  );
}

function configuredTimeoutMs(): number {
  const value = Number(process.env.MEMORY_FIREWALL_TIMEOUT_MS ?? "2000");
  return Number.isFinite(value) && value > 0 ? value : 2000;
}

function parseMetadata(value: unknown):
  | { argumentLineage: Record<string, string[]>; scope: string; tenantId: string }
  | undefined {
  if (!isObject(value) || !isObject(value.argument_lineage)) return undefined;
  const lineage: Record<string, string[]> = {};
  for (const [key, sources] of Object.entries(value.argument_lineage)) {
    if (!Array.isArray(sources) || !sources.every((source) => typeof source === "string")) {
      return undefined;
    }
    lineage[key] = sources;
  }
  const scope = value.scope ?? process.env.MEMORY_FIREWALL_SCOPE ?? "default";
  const tenantId = value.tenant_id ?? process.env.MEMORY_FIREWALL_TENANT_ID ?? "default";
  if (typeof scope !== "string" || !scope || typeof tenantId !== "string" || !tenantId) return undefined;
  return { argumentLineage: lineage, scope, tenantId };
}

export async function authorizeToolCall(
  request: JsonObject,
  fetchImpl: typeof fetch = fetch,
): Promise<Decision> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), configuredTimeoutMs());
  try {
    const response = await fetchImpl(process.env.MEMORY_FIREWALL_URL ?? DEFAULT_URL, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(request),
      signal: controller.signal,
    });
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    const body: unknown = await response.json();
    if (
      !isObject(body) ||
      body.request_id !== request.request_id ||
      !["allow", "block", "review"].includes(String(body.decision)) ||
      (body.reason !== undefined && typeof body.reason !== "string")
    ) {
      throw new Error("malformed or unbound response");
    }
    return { decision: body.decision as Decision["decision"], reason: body.reason as string | undefined };
  } catch (error) {
    return {
      decision: "block",
      reason: `Memory Firewall unavailable: ${error instanceof Error ? error.message : "request failed"}`,
    };
  } finally {
    clearTimeout(timer);
  }
}

export async function handleBeforeToolCall(
  event: { toolName: string; params: JsonObject; toolCallId?: string; runId?: string },
  ctx: { agentId?: string; sessionId?: string; sessionKey?: string; runId?: string },
  client: typeof authorizeToolCall = authorizeToolCall,
): Promise<HookResult> {
  const metadataValue = event.params._memory_firewall;
  const params = { ...event.params };
  delete params._memory_firewall;
  if (unprotectedTools().has(event.toolName.trim().toLowerCase())) return { params };

  const metadata = parseMetadata(metadataValue);
  if (!metadata) {
    return { params, block: true, blockReason: "Memory Firewall metadata is required" };
  }
  const requestId = randomUUID();
  const session: JsonObject = { id: ctx.sessionId ?? ctx.sessionKey ?? "openclaw-session" };
  if (event.runId ?? ctx.runId) session.turn_id = event.runId ?? ctx.runId;
  if (event.toolCallId) session.tool_call_id = event.toolCallId;
  const result = await client({
    schema_version: "memory-firewall.tool-call.v1",
    request_id: requestId,
    runtime: { name: "openclaw", adapter_version: ADAPTER_VERSION },
    session,
    tool: { name: event.toolName, arguments: params },
    argument_lineage: metadata.argumentLineage,
    scope: metadata.scope,
    actor: {
      id: ctx.agentId ?? process.env.MEMORY_FIREWALL_ACTOR_ID ?? "openclaw-agent",
      type: "agent",
    },
    tenant_id: metadata.tenantId,
  });
  const reason = result.reason || `Memory Firewall decision: ${result.decision}`;
  if (result.decision === "allow") return { params };
  if (result.decision === "review") {
    return {
      params,
      requireApproval: {
        title: `Memory Firewall review: ${event.toolName}`,
        description: reason,
        severity: "warning",
        timeoutMs: 60_000,
        allowedDecisions: ["allow-once", "deny"],
      },
    };
  }
  return { params, block: true, blockReason: reason };
}

export default definePluginEntry({
  id: "memory-firewall",
  name: "Memory Firewall",
  description: "Fail-closed authorization for protected tool calls",
  register(api) {
    api.on("before_tool_call", handleBeforeToolCall, {
      priority: 100,
      timeoutMs: Math.min(configuredTimeoutMs() + 1000, 600_000),
    });
  },
});
