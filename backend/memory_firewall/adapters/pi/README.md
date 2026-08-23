# Memory Firewall adapter for Pi

Intercepts Pi `tool_call` events. Protected calls are authorized by Memory Firewall; `_memory_firewall` is always removed from the executed input. `block` and `review` both block because Pi has no native deferred-approval result for this hook.

## Install

Global, from this directory:

```sh
pi install "$(pwd)"
```

Project-local, run at the target project root:

```sh
pi install -l /Users/cris/Downloads/memory-firewall/platanus-hack-26-co-team-13/backend/memory_firewall/adapters/pi
```

For a one-off check: `pi -e ./index.ts`.

`MEMORY_FIREWALL_WORKSPACE_KEY` is **required**: it is the workspace credential (`mfw_...`) returned once by `POST /api/v1/auth/register` and re-issued by `POST /api/v1/workspace/key/rotate`. The adapter sends it as the `X-Workspace-Key` header, and the server derives the workspace from it. The adapter no longer sends `tenant_id`; the server would discard it. If the key is unset the adapter fails closed and loudly instead of falling back to a default workspace.

Configure with `MEMORY_FIREWALL_WORKSPACE_KEY` (required), `MEMORY_FIREWALL_URL`, `MEMORY_FIREWALL_TIMEOUT_MS`, `MEMORY_FIREWALL_PROTECTED_TOOLS`, `MEMORY_FIREWALL_SCOPE`, and `MEMORY_FIREWALL_ACTOR_ID`. Defaults target the local API with a 2000 ms timeout.

## Limitations

This is an in-process policy hook, not a sandbox. Other extensions loaded earlier can alter inputs. Metadata supplies lineage and routing scope only; actor identity is runtime configuration, and every protected failure blocks.
