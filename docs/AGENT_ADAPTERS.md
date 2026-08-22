# Native Agent Adapters

Memory Firewall is installed in the agent execution path. The dashboard is a
control plane; it does not enforce policy.

```text
Pi tool_call -----------+
Hermes pre_tool_call ---+--> local Memory Firewall core --> ALLOW / BLOCK
OpenClaw before_tool_call+
```

## Install

Install the Python package from the backend directory:

```bash
python -m pip install ./backend
memory-firewall serve
```

Install an adapter for the current user:

```bash
memory-firewall install pi
memory-firewall install hermes
memory-firewall install openclaw
```

Use `--scope project` to install into the current project, or `--target PATH`
to select an explicit destination. Hermes must then enable the plugin with
`hermes plugins enable provenance-firewall`. OpenClaw must add the printed
directory to `plugins.load.paths`.

## Execution Contract

Protected calls carry a reserved argument that the adapter removes before the
real tool sees it:

```json
{
  "vendor": "Andina Logistics",
  "account": "8842",
  "amount": 48000000,
  "_memory_firewall": {
    "scope": "accounts_payable",
    "tenant_id": "demo",
    "argument_lineage": {
      "vendor": ["analysis_signed_envelope"],
      "account": ["analysis_signed_envelope"],
      "amount": ["analysis_signed_envelope"]
    }
  }
}
```

The adapter never accepts authority from tool arguments. The core loads every
referenced envelope from SQLite, verifies its Ed25519 signature, verifies all
ancestors, checks tenant, state, TTL, authority, capability, and scope, then
records a signed `TOOL_DECISION` event.

Each envelope also signs structured `claims`. Every pending argument value must
exactly match the corresponding claim in at least one referenced envelope.
This prevents valid evidence for one account or amount from authorizing a
different value.

Every non-control tool argument needs at least one signed evidence ID. Missing
lineage fails closed.

## Failure Semantics

All tools are protected by default. Only tools explicitly listed in
`MEMORY_FIREWALL_UNPROTECTED_TOOLS` bypass authorization. For protected tools,
all of these conditions produce a native block:

- Missing or malformed `_memory_firewall` metadata.
- Core connection refusal or timeout.
- Non-2xx HTTP response.
- Malformed JSON or unknown decision.
- Response `request_id` mismatch.
- Missing, corrupt, cross-tenant, expired, or insufficient evidence.

The default timeout is 2 seconds. Configure it with
`MEMORY_FIREWALL_TIMEOUT_MS`. Configure the core URL with
`MEMORY_FIREWALL_URL`.

`memory-firewall serve` creates an owner-readable Ed25519 seed at
`~/.memory-firewall/signing.key` and reuses it across restarts. Starting the API
with persistent SQLite and no configured key is rejected instead of silently
making existing envelopes unverifiable. Authority elevation and administrative
memory search additionally require a bearer `MEMORY_FIREWALL_ADMIN_TOKEN` and
server-bound admin actor and tenant settings. Legacy escalation approval and
token retrieval use the same boundary. The dashboard ledger requires an
HttpOnly viewer session; it exposes only pseudonymous object references, never
reusable analysis IDs. Users create their own account from the web interface.
Passwords use salted scrypt hashes and revocable sessions are stored as token
hashes in SQLite.

## Adapter Status

`adapter_verified` means the adapter package, native hook mapping, metadata
removal, and fail-closed contract are tested in this repository. It does not
mean an external agent process is connected. Live connections are reported
separately and remain empty unless a runtime establishes one.

Pi sends a short-lived heartbeat from its native `session_start` and
`tool_call` hooks. A connection expires after 30 seconds without another event,
so a stale installation is never presented as a live agent. Local fail-closed
decisions, such as missing metadata, are stored as `TOOL_BLOCKED_LOCAL` events
without retaining raw tool arguments.

## Verify Pi End to End

Start the core and install the adapter:

```bash
memory-firewall serve
memory-firewall install pi
```

In a second terminal, ask Pi to invoke a harmless synthetic side effect. Do not
include `_memory_firewall`; this intentionally exercises fail-closed behavior:

```bash
pi --provider YOUR_PROVIDER --model YOUR_MODEL --no-session --tools bash -p \
  "Use bash exactly once to run: touch /tmp/memory-firewall-should-not-exist"
test ! -e /tmp/memory-firewall-should-not-exist
```

Pi reports `Memory Firewall metadata is required`, the marker remains absent,
the runtime status briefly lists `pi`, and the protected activity ledger shows
`TOOL_BLOCKED_LOCAL` after login. This verifies the native hook and the missing
side effect; it does not depend on the model's natural-language account of what
happened.

## Current Boundary

The browser replay executes a synthetic callable through the local execution
gateway and reports its measured invocation count. Native runtime cards
distinguish verified installations from TTL-bound live connections.

The adapters enforce tool execution and consume signed memory IDs. They do not
yet automatically ingest arbitrary emails or infer argument lineage from model
text. The next Pi integration will expose memory ingestion/retrieval tools so
the runtime, rather than the model, attaches envelope IDs to later tool calls.
