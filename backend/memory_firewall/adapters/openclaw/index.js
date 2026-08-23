import { createHash, randomUUID } from "node:crypto";
import { definePluginEntry } from "openclaw/plugin-sdk/plugin-entry";

const ADAPTER_VERSION = "0.1.0";
const DEFAULT_URL = "http://127.0.0.1:8000/api/v1/firewall/tool-calls/authorize";
const DEFAULT_TIMEOUT_MS = 15_000;

function isObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function canonicalJson(value) {
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

function expandNumber(value) {
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

function expectedResponseBinding(request) {
  const tool = request.tool;
  const session = request.session;
  return {
    tool: String(tool.name).trim().toUpperCase(),
    session: String(session.id).trim().toLowerCase(),
    argsHash: createHash("sha256").update(canonicalJson(tool.arguments)).digest("hex"),
  };
}

function configuredTimeoutMs() {
  const value = Number(process.env.MEMORY_FIREWALL_TIMEOUT_MS ?? String(DEFAULT_TIMEOUT_MS));
  return Number.isFinite(value) && value > 0 ? value : DEFAULT_TIMEOUT_MS;
}

function workspaceKey() {
  const key = process.env.MEMORY_FIREWALL_WORKSPACE_KEY?.trim();
  if (!key) {
    throw new Error(
      "MEMORY_FIREWALL_WORKSPACE_KEY is not set. Obtain the key from " +
        "POST /api/v1/auth/register or /api/v1/workspace/key/rotate.",
    );
  }
  return key;
}

function parseMetadata(value) {
  if (!isObject(value) || !isObject(value.argument_lineage)) return undefined;
  const lineage = {};
  for (const [key, sources] of Object.entries(value.argument_lineage)) {
    if (!Array.isArray(sources) || !sources.every((source) => typeof source === "string")) {
      return undefined;
    }
    lineage[key] = sources;
  }
  const scope = value.scope ?? process.env.MEMORY_FIREWALL_SCOPE ?? "default";
  if (typeof scope !== "string" || !scope) return undefined;
  return { argumentLineage: lineage, scope };
}

export async function authorizeToolCall(request, fetchImpl = fetch) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), configuredTimeoutMs());
  try {
    const encodedRequest = JSON.stringify(request);
    const response = await fetchImpl(process.env.MEMORY_FIREWALL_URL ?? DEFAULT_URL, {
      method: "POST",
      headers: { "content-type": "application/json", "x-workspace-key": workspaceKey() },
      body: encodedRequest,
      signal: controller.signal,
    });
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    const body = await response.json();
    const binding = expectedResponseBinding(JSON.parse(encodedRequest));
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
    return { decision: body.decision, reason: body.reason };
  } catch (error) {
    return {
      decision: "block",
      reason: `Memory Firewall unavailable: ${error instanceof Error ? error.message : "request failed"}`,
    };
  } finally {
    clearTimeout(timer);
  }
}

export async function handleBeforeToolCall(event, ctx, client = authorizeToolCall) {
  const metadataValue = event.params._memory_firewall;
  const params = { ...event.params };
  delete params._memory_firewall;
  const metadata = parseMetadata(metadataValue);
  if (!metadata) {
    return { params, block: true, blockReason: "Memory Firewall metadata is required" };
  }
  const requestId = randomUUID();
  const session = { id: ctx.sessionId ?? ctx.sessionKey ?? "openclaw-session" };
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
  });
  const reason = result.reason || `Memory Firewall decision: ${result.decision}`;
  if (result.decision === "allow") return { params };
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
