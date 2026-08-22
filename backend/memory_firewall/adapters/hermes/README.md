# Memory Firewall adapter for Hermes

Registers a native `pre_tool_call` hook. It strips `_memory_firewall`, authorizes protected tools, maps `allow` to argument modification, `block` to a block directive, and `review` to Hermes approval.

## Install

Global installation from this directory:

```sh
mkdir -p ~/.hermes/plugins/memory-firewall
cp plugin.yaml __init__.py ~/.hermes/plugins/memory-firewall/
hermes plugins enable memory-firewall
hermes plugins doctor memory-firewall --ci
```

Project-local installation, run at the target project root:

```sh
mkdir -p .hermes/plugins/memory-firewall
cp /Users/cris/Downloads/memory-firewall/platanus-hack-26-co-team-13/backend/memory_firewall/adapters/hermes/{plugin.yaml,__init__.py} .hermes/plugins/memory-firewall/
HERMES_ENABLE_PROJECT_PLUGINS=true hermes plugins enable memory-firewall
HERMES_ENABLE_PROJECT_PLUGINS=true hermes plugins doctor .hermes/plugins/memory-firewall --ci
```

Configure with `MEMORY_FIREWALL_URL`, `MEMORY_FIREWALL_TIMEOUT_MS`, `MEMORY_FIREWALL_PROTECTED_TOOLS`, `MEMORY_FIREWALL_SCOPE`, `MEMORY_FIREWALL_TENANT_ID`, and `MEMORY_FIREWALL_ACTOR_ID`. Defaults target the local API with a 2000 ms timeout.

## Limitations

Hermes plugins run in process and are not a sandbox. Plugin ordering still applies. Metadata carries lineage and routing scope only; actor identity comes from configuration. Missing or invalid evidence and every transport or response error block protected calls.
