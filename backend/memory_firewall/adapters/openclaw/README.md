# Memory Firewall adapter for OpenClaw

Registers the official typed `before_tool_call` hook through `definePluginEntry`. It strips `_memory_firewall`, maps `allow` to rewritten `params`, `block` to `block`, and `review` to `requireApproval`.

## Install

Global managed installation from this directory:

```sh
openclaw plugins install -l "$(pwd)" --force
openclaw plugins enable memory-firewall
openclaw plugins inspect memory-firewall --runtime --json
```

Project-local discovery, run at the target project root:

```sh
mkdir -p .openclaw/extensions
cp -R /Users/cris/Downloads/memory-firewall/platanus-hack-26-co-team-13/backend/memory_firewall/adapters/openclaw .openclaw/extensions/memory-firewall
openclaw plugins enable memory-firewall
openclaw plugins inspect memory-firewall --runtime --json
```

Restart the Gateway after installation. Configure with `MEMORY_FIREWALL_URL`, `MEMORY_FIREWALL_TIMEOUT_MS`, `MEMORY_FIREWALL_PROTECTED_TOOLS`, `MEMORY_FIREWALL_SCOPE`, `MEMORY_FIREWALL_TENANT_ID`, and `MEMORY_FIREWALL_ACTOR_ID`. Defaults target the local API with a 2000 ms timeout.

## Limitations

OpenClaw plugins run in process and are not a sandbox. Higher- and lower-priority policy hooks still apply. Metadata supplies lineage and routing scope only; actor identity is host context or configuration. Unresolved native approval denies, while API and validation failures block before approval.
