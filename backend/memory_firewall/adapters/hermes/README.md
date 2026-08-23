# Memory Firewall adapter for Hermes

Registers a native `pre_tool_call` hook. It strips `_memory_firewall`, authorizes protected tools, maps `allow` to argument modification, `block` to a block directive, and `review` to Hermes approval.

## Install

Install and enable for the current user:

```sh
python3 -m memory_firewall.cli install hermes
hermes plugins enable memory-firewall
hermes plugins doctor memory-firewall --ci
```

Project-local installation, run at the target project root:

```sh
python3 -m memory_firewall.cli install hermes --scope project
HERMES_ENABLE_PROJECT_PLUGINS=true hermes plugins enable memory-firewall
HERMES_ENABLE_PROJECT_PLUGINS=true hermes plugins doctor .hermes/plugins/memory-firewall --ci
```

`MEMORY_FIREWALL_WORKSPACE_KEY` is **required**: it is the workspace credential (`mfw_...`) returned once by `POST /api/v1/auth/register` and re-issued by `POST /api/v1/workspace/key/rotate`. The adapter sends it as the `X-Workspace-Key` header, and the server derives the workspace from it. The adapter no longer sends `tenant_id`; the server would discard it. If the key is unset the adapter fails closed and loudly instead of falling back to a default workspace.

Configure with `MEMORY_FIREWALL_WORKSPACE_KEY` (required), `MEMORY_FIREWALL_URL`, `MEMORY_FIREWALL_TIMEOUT_MS`, `MEMORY_FIREWALL_PROTECTED_TOOLS`, `MEMORY_FIREWALL_SCOPE`, and `MEMORY_FIREWALL_ACTOR_ID`. Defaults target the local API with a 2000 ms timeout.

## Limitations

Hermes plugins run in process and are not a sandbox. Plugin ordering still applies. Metadata carries lineage and routing scope only; actor identity comes from configuration. Missing or invalid evidence and every transport or response error block protected calls.
