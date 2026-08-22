import { randomUUID } from "node:crypto";
import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";

const ADAPTER_VERSION = "0.1.0";
const DEFAULT_URL = "http://127.0.0.1:8000/api/v1/firewall/tool-calls/authorize";
const DEFAULT_HEARTBEAT_URL = "http://127.0.0.1:8000/api/v1/runtime/connections/heartbeat";
const DEFAULT_BLOCK_EVENT_URL = "http://127.0.0.1:8000/api/v1/runtime/tool-blocks";

type JsonObject = Record<string, unknown>;
type Lineage = Record<string, string[]>;
type Decision = { decision: "allow" | "block" | "review"; reason?: string };

function unprotectedTools(): Set<string> {
  return new Set(
    (process.env.MEMORY_FIREWALL_UNPROTECTED_TOOLS ?? "")
      .split(",")
      .map((name) => name.trim().toLowerCase())
      .filter(Boolean),
  );
}

function timeoutMs(): number {
  const parsed = Number(process.env.MEMORY_FIREWALL_TIMEOUT_MS ?? "2000");
  return Number.isFinite(parsed) && parsed > 0 ? parsed : 2000;
}

function isObject(value: unknown): value is JsonObject {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function parseMetadata(value: unknown):
  | { argumentLineage: Lineage; scope: string; tenantId: string }
  | undefined {
  if (!isObject(value) || !isObject(value.argument_lineage)) return undefined;
  const lineage: Lineage = {};
  for (const [key, sources] of Object.entries(value.argument_lineage)) {
    if (!Array.isArray(sources) || !sources.every((source) => typeof source === "string")) {
      return undefined;
    }
    lineage[key] = sources;
  }
  if (value.scope !== undefined && (typeof value.scope !== "string" || !value.scope)) return undefined;
  if (value.tenant_id !== undefined && (typeof value.tenant_id !== "string" || !value.tenant_id)) {
    return undefined;
  }
  return {
    argumentLineage: lineage,
    scope: (value.scope as string | undefined) ?? process.env.MEMORY_FIREWALL_SCOPE ?? "default",
    tenantId:
      (value.tenant_id as string | undefined) ?? process.env.MEMORY_FIREWALL_TENANT_ID ?? "default",
  };
}

export async function authorizeToolCall(
  request: JsonObject,
  fetchImpl: typeof fetch = fetch,
): Promise<Decision> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs());
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

export async function reportHeartbeat(
  sessionId: string,
  fetchImpl: typeof fetch = fetch,
): Promise<boolean> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs());
  try {
    const response = await fetchImpl(
      process.env.MEMORY_FIREWALL_HEARTBEAT_URL ?? DEFAULT_HEARTBEAT_URL,
      {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          runtime: { name: "pi", adapter_version: ADAPTER_VERSION },
          session: { id: sessionId },
        }),
        signal: controller.signal,
      },
    );
    return response.ok;
  } catch {
    return false;
  } finally {
    clearTimeout(timer);
  }
}

async function reportLocalBlock(
  event: { toolName: string; toolCallId?: string },
  sessionId: string,
  reason: string,
  fetchImpl: typeof fetch = fetch,
): Promise<void> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs());
  try {
    await fetchImpl(process.env.MEMORY_FIREWALL_BLOCK_EVENT_URL ?? DEFAULT_BLOCK_EVENT_URL, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        runtime: { name: "pi", adapter_version: ADAPTER_VERSION },
        session: { id: sessionId, tool_call_id: event.toolCallId },
        tool_name: event.toolName,
        reason,
        actor: { id: process.env.MEMORY_FIREWALL_ACTOR_ID ?? "pi-agent", type: "agent" },
        tenant_id: process.env.MEMORY_FIREWALL_TENANT_ID ?? "default",
      }),
      signal: controller.signal,
    });
  } catch {
    // Audit reporting never weakens the local fail-closed decision.
  } finally {
    clearTimeout(timer);
  }
}

export async function handleToolCall(
  event: { toolName: string; toolCallId?: string; input: JsonObject },
  sessionId: string,
  client: typeof authorizeToolCall = authorizeToolCall,
): Promise<{ block: true; reason: string } | undefined> {
  const metadataValue = event.input._memory_firewall;
  delete event.input._memory_firewall;
  if (unprotectedTools().has(event.toolName.trim().toLowerCase())) return undefined;

  const metadata = parseMetadata(metadataValue);
  if (!metadata) {
    const reason = "Memory Firewall metadata is required";
    await reportLocalBlock(event, sessionId, reason);
    return { block: true, reason };
  }

  const requestId = randomUUID();
  const result = await client({
    schema_version: "memory-firewall.tool-call.v1",
    request_id: requestId,
    runtime: { name: "pi", adapter_version: ADAPTER_VERSION },
    session: { id: sessionId, tool_call_id: event.toolCallId },
    tool: { name: event.toolName, arguments: event.input },
    argument_lineage: metadata.argumentLineage,
    scope: metadata.scope,
    actor: { id: process.env.MEMORY_FIREWALL_ACTOR_ID ?? "pi-agent", type: "agent" },
    tenant_id: metadata.tenantId,
  });
  if (result.decision === "allow") return undefined;
  return { block: true, reason: result.reason || `Memory Firewall decision: ${result.decision}` };
}

export default function memoryFirewallExtension(pi: ExtensionAPI): void {
  pi.on("session_start", async (_event, ctx) => {
    await reportHeartbeat(ctx.sessionManager.getSessionId());
  });
  pi.on("tool_call", async (event, ctx) => {
    const sessionId = ctx.sessionManager.getSessionId();
    await reportHeartbeat(sessionId);
    return handleToolCall(
      event as { toolName: string; toolCallId?: string; input: JsonObject },
      sessionId,
    );
  });
}
