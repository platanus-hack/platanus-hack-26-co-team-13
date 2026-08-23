import { createHash, randomUUID } from "node:crypto";
import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";

const ADAPTER_VERSION = "0.1.0";
const DEFAULT_URL = "http://127.0.0.1:8000/api/v1/firewall/tool-calls/authorize";
const DEFAULT_HEARTBEAT_URL = "http://127.0.0.1:8000/api/v1/runtime/connections/heartbeat";
const DEFAULT_BLOCK_EVENT_URL = "http://127.0.0.1:8000/api/v1/runtime/tool-blocks";
const DEFAULT_TIMEOUT_MS = 15_000;

type JsonObject = Record<string, unknown>;
type Lineage = Record<string, string[]>;
type Decision = { decision: "allow" | "block" | "review"; reason?: string };

function timeoutMs(): number {
  const parsed = Number(process.env.MEMORY_FIREWALL_TIMEOUT_MS ?? String(DEFAULT_TIMEOUT_MS));
  return Number.isFinite(parsed) && parsed > 0 ? parsed : DEFAULT_TIMEOUT_MS;
}

function isObject(value: unknown): value is JsonObject {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function canonicalJson(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  if (isObject(value)) {
    return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(",")}}`;
  }
  if (typeof value === "number") {
    if (!Number.isFinite(value)) throw new Error("non-finite action argument");
    return `{"$number":${JSON.stringify(expandNumber(value))}}`;
  }
  return JSON.stringify(value) ?? "null";
}

function expandNumber(value: number): string {
  const text = value.toString().toLowerCase();
  if (!text.includes("e")) return Object.is(value, -0) ? "0" : text;
  const [coefficient, exponentText] = text.split("e");
  const exponent = Number(exponentText);
  const negative = coefficient.startsWith("-");
  const digits = coefficient.replace("-", "").replace(".", "");
  const decimalIndex = coefficient.replace("-", "").indexOf(".");
  const originalIndex = decimalIndex === -1 ? digits.length : decimalIndex;
  const targetIndex = originalIndex + exponent;
  const expanded = targetIndex <= 0
    ? `0.${"0".repeat(-targetIndex)}${digits}`
    : targetIndex >= digits.length
      ? `${digits}${"0".repeat(targetIndex - digits.length)}`
      : `${digits.slice(0, targetIndex)}.${digits.slice(targetIndex)}`;
  return `${negative ? "-" : ""}${expanded}`;
}

function expectedResponseBinding(request: JsonObject): { tool: string; session: string; argsHash: string } {
  const tool = request.tool as JsonObject;
  const session = request.session as JsonObject;
  return {
    tool: String(tool.name).trim().toUpperCase(),
    session: String(session.id).trim().toLowerCase(),
    argsHash: createHash("sha256").update(canonicalJson(tool.arguments)).digest("hex"),
  };
}

/**
 * Read the workspace credential, or throw.
 *
 * The workspace is proven by this key alone. There is deliberately no default
 * and no fallback to a "tenant id" env var: an unauthenticated agent must fail
 * loudly rather than silently write into somebody else's workspace.
 */
function workspaceKey(): string {
  const key = process.env.MEMORY_FIREWALL_WORKSPACE_KEY?.trim();
  if (!key) {
    throw new Error(
      "MEMORY_FIREWALL_WORKSPACE_KEY is not set. Obtain the key from " +
        "POST /api/v1/auth/register or /api/v1/workspace/key/rotate.",
    );
  }
  return key;
}

function firewallHeaders(): Record<string, string> {
  return { "content-type": "application/json", "x-workspace-key": workspaceKey() };
}

function parseMetadata(value: unknown): { argumentLineage: Lineage; scope: string } | undefined {
  if (!isObject(value) || !isObject(value.argument_lineage)) return undefined;
  const lineage: Lineage = {};
  for (const [key, sources] of Object.entries(value.argument_lineage)) {
    if (!Array.isArray(sources) || !sources.every((source) => typeof source === "string")) {
      return undefined;
    }
    lineage[key] = sources;
  }
  if (value.scope !== undefined && (typeof value.scope !== "string" || !value.scope)) return undefined;
  // No tenant_id: the server derives the workspace from the workspace key and
  // ignores anything the caller puts in the body.
  return {
    argumentLineage: lineage,
    scope: (value.scope as string | undefined) ?? process.env.MEMORY_FIREWALL_SCOPE ?? "default",
  };
}

export async function authorizeToolCall(
  request: JsonObject,
  fetchImpl: typeof fetch = fetch,
): Promise<Decision> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs());
  try {
    const encodedRequest = JSON.stringify(request);
    const response = await fetchImpl(process.env.MEMORY_FIREWALL_URL ?? DEFAULT_URL, {
      method: "POST",
      headers: firewallHeaders(),
      body: encodedRequest,
      signal: controller.signal,
    });
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    const body: unknown = await response.json();
    const binding = expectedResponseBinding(JSON.parse(encodedRequest) as JsonObject);
    if (
      !isObject(body) ||
      body.request_id !== request.request_id ||
      body.tool_name !== binding.tool ||
      body.session_id !== binding.session ||
      body.args_hash !== binding.argsHash ||
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
      headers: firewallHeaders(),
      body: JSON.stringify({
        runtime: { name: "pi", adapter_version: ADAPTER_VERSION },
        session: { id: sessionId, tool_call_id: event.toolCallId },
        tool_name: event.toolName,
        reason,
        actor: { id: process.env.MEMORY_FIREWALL_ACTOR_ID ?? "pi-agent", type: "agent" },
      }),
      signal: controller.signal,
    });
  } catch (error) {
    // Audit reporting never weakens the local fail-closed decision, but a
    // missing credential is a configuration fault and must be visible.
    console.error(
      `[memory-firewall] could not record local block: ${
        error instanceof Error ? error.message : "request failed"
      }`,
    );
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
