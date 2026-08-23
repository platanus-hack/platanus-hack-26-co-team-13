# Memory Firewall adapter for OpenClaw

Registers the official typed `before_tool_call` hook through `definePluginEntry`. It strips `_memory_firewall`, maps `allow` to rewritten `params`, and blocks both `block` and unresolved `review` decisions.

## Install

Stage through the Memory Firewall CLI, then install with OpenClaw so it records
the plugin provenance before reloading the Gateway:

```sh
python3 -m memory_firewall.cli install openclaw
openclaw plugins install --force ~/.memory-firewall/adapters/openclaw
openclaw gateway restart
openclaw plugins inspect memory-firewall --runtime --json
```

Project-local discovery, run at the target project root:

```sh
python3 -m memory_firewall.cli install openclaw --scope project
openclaw plugins install --force .memory-firewall/adapters/openclaw
openclaw gateway restart
openclaw plugins inspect memory-firewall --runtime --json
```

Restart the Gateway after installation. `MEMORY_FIREWALL_WORKSPACE_KEY` is **required**: it is the workspace credential (`mfw_...`) returned once by `POST /api/v1/auth/register` and re-issued by `POST /api/v1/workspace/key/rotate`. The adapter sends it as the `X-Workspace-Key` header, and the server derives the workspace from it. The adapter no longer sends `tenant_id`; the server would discard it. If the key is unset the adapter fails closed and loudly instead of falling back to a default workspace.

Configure with `MEMORY_FIREWALL_WORKSPACE_KEY` (required), `MEMORY_FIREWALL_URL`, `MEMORY_FIREWALL_TIMEOUT_MS`, `MEMORY_FIREWALL_SCOPE`, and `MEMORY_FIREWALL_ACTOR_ID`. Defaults target the local API with a 15000 ms timeout.

## Limitations

OpenClaw plugins run in process and are not a sandbox. Higher- and lower-priority policy hooks still apply. Metadata supplies lineage and routing scope only; actor identity is host context or configuration. Unresolved native approval denies, while API and validation failures block before approval.
